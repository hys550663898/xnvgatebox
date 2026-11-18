package main

import (
	"encoding/json"
	"fmt"
	"log"
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
	// 同地址只切协议（HTTP↔HTTPS）时没法预绑：端口还被自己的旧监听
	// 占着，bind 必然 address already in use。证书先校验存好，真正的
	// 关旧/绑新留到 activate 阶段原地完成（swapInPlace）。
	s.mu.Lock()
	sameAddr := s.hasCfg && s.addr == addr
	protocolFlip := s.hasCfg && s.cfg.HTTPS != next.HTTPS
	s.mu.Unlock()
	if sameAddr && !protocolFlip {
		// 线上监听已经在这个地址上：端口/地址/协议都没变（多半只是
		// 换证书或改无关字段），不需要也不应该再绑一次。activate
		// 只负责在提交后把新证书设为当前证书；但证书先在这里校验，
		// 坏证书要在保存时报错，而不是静默沿用旧证书。
		if next.HTTPS {
			if _, err := loadManagementCert(next.CertFile, next.KeyFile); err != nil {
				return nil, err
			}
		}
		return &preparedManagementListener{activate: func() {
			if next.HTTPS {
				_ = storeManagementCert(next.CertFile, next.KeyFile)
			}
		}, cancel: func() {}}, nil
	}
	if sameAddr && protocolFlip {
		if next.HTTPS {
			if _, err := loadManagementCert(next.CertFile, next.KeyFile); err != nil {
				return nil, err
			}
		}
		return &preparedManagementListener{activate: func() { s.swapInPlace(next) }, cancel: func() {}}, nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("无法监听 %s: %w", addr, err)
	}
	if next.HTTPS {
		if _, err := loadManagementCert(next.CertFile, next.KeyFile); err != nil {
			ln.Close()
			return nil, err
		}
	}
	return &preparedManagementListener{activate: func() {
		// activate 发生在事务提交之后：此刻才把证书设为当前证书，
		// 回滚的保存不会污染线上监听用的证书。
		if next.HTTPS {
			_ = storeManagementCert(next.CertFile, next.KeyFile)
		}
		s.activateListener(ln, next)
	}, cancel: func() { ln.Close() }}, nil
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
	if in.HTTPS != nil {
		next.HTTPS = *in.HTTPS
	}
	if in.Domain != nil {
		next.Domain = strings.TrimSpace(*in.Domain)
	}
	if in.CertFile != nil {
		next.CertFile = strings.TrimSpace(*in.CertFile)
	}
	if in.KeyFile != nil {
		next.KeyFile = strings.TrimSpace(*in.KeyFile)
	}
	password := in.Password
	if password != nil && *password == "" {
		password = nil
	}
	return commitManagementSettings(auth, srv, next, password, in.BasePath)
}

// Bind the replacement port before touching any credential/file; start serving
// only after the entire durable transaction commits. Old listener stays live
// when validation, bind or any write fails.
func commitManagementSettings(auth *Auth, srv *webServer, next WebSettings, password, base *string) error {
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
	// 证书路径/内容的变化不需要重备监听：TLS 握手走 GetCertificate
	// 读当前证书，提交后把新证书存进 managementCert 即刻生效。
	listenerChanged := next.Port != current.Port || next.ListenAddr != current.ListenAddr ||
		next.HTTPS != current.HTTPS
	if listenerChanged {
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
	} else if next.HTTPS {
		// 监听没动（只改了证书路径/内容或无关字段）：把新证书设为
		// 当前证书，TLS 握手即刻用上，不需要重绑端口。
		if err := storeManagementCert(next.CertFile, next.KeyFile); err != nil {
			log.Printf("更新管理界面证书失败: %v", err)
		}
	}
	return nil
}
