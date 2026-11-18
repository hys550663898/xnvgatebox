package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
)

const managementJournal = ".management-transaction.json"

var managementConfigFiles = []string{"settings.json", "password", "basepath"}
var managementMu sync.Mutex

type managementSettingsRequest struct {
	Password        *string `json:"password"`
	BasePath        *string `json:"base_path"`
	Port            *int    `json:"port"`
	ListenAddr      *string `json:"listen_addr"`
	ResidentialOnly *bool   `json:"residential_only"`
	HTTPS           *bool   `json:"https"`
	Domain          *string `json:"domain"`
	CertFile        *string `json:"cert_file"`
	KeyFile         *string `json:"key_file"`
}

type preparedManagementListener struct {
	activate func()
	cancel   func()
}

func (s *webServer) prepareManagementListener(next WebSettings) (*preparedManagementListener, error) {
	if s.prepareListener != nil {
		return s.prepareListener(next)
	}
	addr := next.listenAddrString()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("无法监听 %s: %w", addr, err)
	}
	if next.HTTPS {
		cert, err := loadManagementCert(next.CertFile, next.KeyFile)
		if err != nil {
			ln.Close()
			return nil, err
		}
		ln = tls.NewListener(ln, &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		})
	}
	return &preparedManagementListener{activate: func() { s.activateListener(ln, addr) }, cancel: func() { ln.Close() }}, nil
}

func applyManagementSettings(auth *Auth, srv *webServer, in managementSettingsRequest) error {
	managementMu.Lock()
	defer managementMu.Unlock()
	next := getWebSettings()
	if in.Port != nil {
		next.Port = *in.Port
	}
	if in.ListenAddr != nil {
		next.ListenAddr = *in.ListenAddr
	}
	if in.ResidentialOnly != nil {
		v := *in.ResidentialOnly
		next.ResidentialOnly = &v
	}
	tlsTouched := false
	if in.HTTPS != nil {
		next.HTTPS = *in.HTTPS
		tlsTouched = true
	}
	if in.Domain != nil {
		next.Domain = strings.TrimSpace(*in.Domain)
	}
	if in.CertFile != nil {
		next.CertFile = strings.TrimSpace(*in.CertFile)
		tlsTouched = true
	}
	if in.KeyFile != nil {
		next.KeyFile = strings.TrimSpace(*in.KeyFile)
		tlsTouched = true
	}
	password := in.Password
	if password != nil && *password == "" {
		password = nil
	}
	return commitManagementSettingsMode(auth, srv, next, password, in.BasePath, tlsTouched)
}

// Bind the replacement port before touching any credential/file; start serving
// only after the entire durable transaction commits. Old listener stays live
// when validation, bind or any write fails.
func commitManagementSettings(auth *Auth, srv *webServer, next WebSettings, password, base *string) error {
	return commitManagementSettingsMode(auth, srv, next, password, base, false)
}

// forceListener 为真时即使端口/监听地址没变也重备监听：设置表单每次
// 保存都会带上 HTTPS 字段，借此让续期后替换的证书文件被重新加载。
func commitManagementSettingsMode(auth *Auth, srv *webServer, next WebSettings, password, base *string, forceListener bool) error {
	if err := validatePort(next.Port); err != nil {
		return err
	}
	norm, err := normalizeListenAddr(next.ListenAddr)
	if err != nil {
		return err
	}
	next.ListenAddr = norm
	if err := validateTLSSettings(next); err != nil {
		return err
	}
	if password != nil {
		v := strings.TrimSpace(*password)
		if len(v) < 4 {
			return fmt.Errorf("口令至少4位")
		}
		password = &v
	}
	if base != nil {
		v, err := validateBasePath(*base)
		if err != nil {
			return err
		}
		base = &v
	}
	dir := filepath.Dir(webSettingsPath)
	if auth != nil && auth.dir != dir {
		return fmt.Errorf("管理配置目录不一致")
	}
	current := getWebSettings()
	var prepared *preparedManagementListener
	listenerChanged := next.Port != current.Port || next.ListenAddr != current.ListenAddr ||
		next.HTTPS != current.HTTPS || next.CertFile != current.CertFile || next.KeyFile != current.KeyFile
	if listenerChanged || (forceListener && next.HTTPS) {
		prepared, err = srv.prepareManagementListener(next)
		if err != nil {
			return err
		}
		defer func() {
			if prepared != nil {
				prepared.cancel()
			}
		}()
	}
	tx, err := beginConfigTransaction(dir, managementJournal, managementConfigFiles)
	if err != nil {
		return err
	}
	fail := func(cause error) error {
		if err := tx.rollback(); err != nil {
			return fmt.Errorf("管理配置回滚未完成；旧入口保留，重启需恢复记录: %w", err)
		}
		return cause
	}
	blob, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fail(err)
	}
	if err := atomicConfigWrite(webSettingsPath, blob); err != nil {
		return fail(err)
	}
	if srv.managementHook != nil {
		if err := srv.managementHook("after_settings_write"); err != nil {
			return fail(err)
		}
	}
	if password != nil {
		if auth == nil {
			return fail(fmt.Errorf("缺少管理认证对象"))
		}
		if err := atomicConfigWrite(filepath.Join(dir, "password"), []byte(*password+"\n")); err != nil {
			return fail(err)
		}
	}
	if srv.managementHook != nil {
		if err := srv.managementHook("after_password_write"); err != nil {
			return fail(err)
		}
	}
	if base != nil {
		if err := atomicConfigWrite(filepath.Join(dir, "basepath"), []byte(strings.TrimPrefix(*base, "/")+"\n")); err != nil {
			return fail(err)
		}
	}
	if srv.managementHook != nil {
		if err := srv.managementHook("before_commit"); err != nil {
			return fail(err)
		}
	}
	if err := tx.commit(); err != nil {
		return fail(err)
	}
	webSettingsMu.Lock()
	webSettingsCur = next
	webSettingsMu.Unlock()
	if password != nil {
		auth.mu.Lock()
		auth.password = *password
		auth.mu.Unlock()
	}
	if base != nil {
		basePathMu.Lock()
		basePathCur = *base
		basePathDir = dir
		basePathMu.Unlock()
	}
	if prepared != nil {
		prepared.activate()
		prepared = nil
	}
	return nil
}
