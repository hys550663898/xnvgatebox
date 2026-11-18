package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// socksSettings 是“代理资源 → VPS SOCKS5”的全局设置。
//
// 与逐条出口的凭据不同，这里定的是全局规则：外部端口从哪个区间分配、
// 凭据是每条随机还是全部共用同一套固定值。外部接入按产品决定全部强制
// 开启（见 ensureAllPublicSocks），所以这里没有单独的开关字段。
type socksSettings struct {
	PortMin   int    `json:"port_min"`
	PortMax   int    `json:"port_max"`
	CredMode  string `json:"cred_mode"` // random | fixed
	FixedUser string `json:"fixed_user,omitempty"`
	FixedPass string `json:"fixed_pass,omitempty"`
}

const (
	credModeRandom = "random"
	credModeFixed  = "fixed"
)

func defaultSocksSettings() socksSettings {
	return socksSettings{PortMin: randPortMin, PortMax: randPortMax, CredMode: credModeRandom}
}

func validateSocksSettings(s socksSettings) error {
	if s.PortMin < 1024 || s.PortMax > 65535 || s.PortMin > s.PortMax {
		return fmt.Errorf("外部端口区间须在 1024–65535 内且起始不大于结束")
	}
	switch s.CredMode {
	case credModeRandom:
	case credModeFixed:
		if err := validateCred(s.fixedCred()); err != nil {
			return fmt.Errorf("固定凭据无效: %w", err)
		}
	default:
		return fmt.Errorf("凭据模式须为 random 或 fixed")
	}
	return nil
}

func (s socksSettings) fixedCred() SocksCred {
	return SocksCred{User: s.FixedUser, Pass: s.FixedPass}
}

// newCred 按当前模式生成一条新出口应使用的凭据。
func (s socksSettings) newCred() (SocksCred, error) {
	if s.CredMode == credModeFixed {
		return s.fixedCred(), nil
	}
	return newSocksCred()
}

func (c *Console) socksSettingsPath() string {
	return filepath.Join(c.m.workDir, "socks-settings.json")
}

func (c *Console) loadSocksSettings() error {
	c.socks = defaultSocksSettings()
	blob, err := os.ReadFile(c.socksSettingsPath())
	if os.IsNotExist(err) {
		c.m.credForNew = c.newSlotCred
		return nil
	}
	if err != nil {
		return err
	}
	var s socksSettings
	if json.Unmarshal(blob, &s) != nil || validateSocksSettings(s) != nil {
		return fmt.Errorf("SOCKS 全局设置损坏，保留原文件")
	}
	c.socks = s
	c.m.credForNew = c.newSlotCred
	return nil
}

func (c *Console) socksSnapshot() socksSettings {
	c.socksMu.Lock()
	defer c.socksMu.Unlock()
	return c.socks
}

// newSlotCred 是 Manager 新建/恢复无凭据出口时的凭据来源，读当前全局模式。
func (c *Console) newSlotCred() (SocksCred, error) {
	return c.socksSnapshot().newCred()
}

// saveSocksSettings 先落盘再发布到内存，与 check-settings 的顺序一致。
func (c *Console) saveSocksSettings(s socksSettings) error {
	if err := validateSocksSettings(s); err != nil {
		return err
	}
	blob, _ := json.Marshal(s)
	if err := atomicConfigWrite(c.socksSettingsPath(), blob); err != nil {
		return fmt.Errorf("SOCKS 全局设置保存失败")
	}
	c.socksMu.Lock()
	c.socks = s
	c.socksMu.Unlock()
	return nil
}

// applySocksCreds 把全局凭据规则强制应用到全部已有出口。
//
// fixed：所有出口统一成固定凭据，已经一致的跳过，重复保存可安全重试。
// random 且 reapply 为真：每条出口重新生成互不相同的随机凭据。
//
// 批量语义而不是逐条 SetCred：逐条改意味着每条都要全量重启一次
// Xray，生产环境里出口在重启间隙抖动、重建，后面的 SetCred 会因
// 隧道已被替换或配置应用失败而回滚，表现为“只改成功了第一个”。
// 这里先把全部目标凭据一次写进内存，只 apply 一次、存盘一次；
// apply 或存盘失败则整体恢复旧凭据再 apply 一次。
func (c *Console) applySocksCreds(s socksSettings, reapplyRandom bool) error {
	type change struct {
		t        *Tunnel
		previous SocksCred
	}
	var changes []change
	assigned := map[SocksCred]bool{}
	for _, t := range c.m.Tunnels() {
		var want SocksCred
		switch {
		case s.CredMode == credModeFixed:
			want = s.fixedCred()
			if t.credential() == want {
				continue
			}
		case reapplyRandom:
			for attempt := 0; attempt < 8; attempt++ {
				gen, err := newSocksCred()
				if err != nil {
					return err
				}
				if !assigned[gen] {
					want = gen
					break
				}
			}
			if want.User == "" {
				return fmt.Errorf("无法为 Slot %d 生成不重复的随机凭据", t.Slot)
			}
			assigned[want] = true
		default:
			return nil
		}
		changes = append(changes, change{t: t, previous: t.credential()})
		t.setCredential(want)
	}
	if len(changes) == 0 {
		return nil
	}
	rollback := func(cause error) error {
		for _, ch := range changes {
			ch.t.setCredential(ch.previous)
		}
		if err := c.m.resync(changes[0].t); err != nil {
			return fmt.Errorf("凭据应用失败且旧配置恢复失败: %v (原错误: %w)", err, cause)
		}
		_ = c.m.saveState()
		return fmt.Errorf("凭据应用失败，已恢复全部旧凭据: %w", cause)
	}
	if err := c.m.resync(changes[0].t); err != nil {
		return rollback(err)
	}
	if err := c.m.saveState(); err != nil {
		return rollback(err)
	}
	return nil
}

// enforceFixedCreds 是 watch 对账的一半：全固定模式下，任何凭据与
// 固定值不一致的出口（例如保存时正逢抖动没改上的、恢复时带回旧
// 凭据的）都会被批量纠正。全部一致时零成本返回，不触发重启。
func (c *Console) enforceFixedCreds() error {
	s := c.socksSnapshot()
	if s.CredMode != credModeFixed {
		return nil
	}
	want := s.fixedCred()
	for _, t := range c.m.Tunnels() {
		if t.credential() != want {
			return c.applySocksCreds(s, false)
		}
	}
	return nil
}

// reconcileAllPublicSocks 只对账已打开的外部 SOCKS 端口区间：已启用
// 入站的端口落在设置区间外的重新分配到区间内，区间内的保持不动。
// 外部接入默认关闭、由用户逐条打开，对账不新建入站、不重新打开
// 手动关闭的。非内置模式没有外部 SOCKS 概念，静默跳过。
func (c *Console) reconcileAllPublicSocks() error {
	p, err := openPanel()
	if err != nil {
		return nil
	}
	n, ok := p.(*Native)
	if !ok {
		return nil
	}
	s := c.socksSnapshot()
	return n.reconcilePublicSocksPorts(c.m.Tunnels(), s.PortMin, s.PortMax)
}

type socksSettingsRequest struct {
	socksSettings
	// ApplyCreds 表示本次保存要把凭据规则重新应用到全部已有出口。
	// 前端在模式或固定凭据发生修改时置真；后端在模式切换时也会强制应用。
	ApplyCreds bool `json:"apply_creds"`
}

func (c *Console) apiSocksSettings(w http.ResponseWriter, r *http.Request) {
	var req socksSettingsRequest
	if err := readConsoleJSON(w, r, &req); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	next := req.socksSettings
	if err := validateSocksSettings(next); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	c.targetMu.Lock()
	defer c.targetMu.Unlock()
	if c.ctx.Err() != nil {
		writeJSON(w, 503, map[string]string{"error": "管理服务正在停止"})
		return
	}
	prev := c.socksSnapshot()
	if err := c.saveSocksSettings(next); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	// 模式切换（或固定凭据改动）本身即构成重新应用的意图，
	// 不依赖前端是否正确置位 apply_creds。
	transition := prev.CredMode != next.CredMode ||
		(next.CredMode == credModeFixed && prev.fixedCred() != next.fixedCred())
	var errs []string
	if err := c.applySocksCreds(next, req.ApplyCreds || transition); err != nil {
		errs = append(errs, err.Error())
	}
	if err := c.reconcileAllPublicSocks(); err != nil {
		errs = append(errs, err.Error())
	}
	invalidateInbounds()
	if len(errs) > 0 {
		writeJSON(w, 409, map[string]string{"error": strings.Join(errs, "; ")})
		return
	}
	writeJSON(w, 200, next)
}
