package main

import (
	"fmt"
	"net/http"
)

type SocksExposure struct {
	Port   int  `json:"port"`
	Enable bool `json:"enable"`
}

func (n *Native) socksExposures() map[int]*SocksExposure {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := map[int]*SocksExposure{}
	for _, ib := range n.store.Inbounds {
		if ib.SocksSlot > 0 {
			out[ib.SocksSlot] = &SocksExposure{Port: ib.Port, Enable: ib.Enable && !n.unavailable}
		}
	}
	return out
}

// ensurePublicSocks 给每个出口补齐已启用的外部 SOCKS 入站。
//
// 与 setPublicSocks 的手动开关不同，这是全局规则的对账：缺失的按
// portMin–portMax 区间新建；已有的强制打开 Enable，且端口落在区间外
// 时重新分配到区间内（区间内的保持不动）。用户改区间即期望全部开放
// 端口随之进入新区间，不能只对新入站生效。
// 一批出口只在确有变化时 apply 一次，避免逐条重启 Xray。
func (n *Native) ensurePublicSocks(tunnels []*Tunnel, portMin, portMax int) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()
	used := n.store.usedPorts()
	for _, tunnel := range tunnels {
		used[tunnel.Port] = true
	}
	changed := false
	for _, t := range tunnels {
		found := false
		for _, ib := range n.store.Inbounds {
			if ib.SocksSlot == t.Slot {
				found = true
				if !ib.Enable {
					ib.Enable = true
					changed = true
				}
				if ib.Port < portMin || ib.Port > portMax {
					port, err := freePortInRange(used, portMin, portMax)
					if err != nil {
						return err
					}
					used[port] = true
					ib.Port = port
					changed = true
				}
				break
			}
		}
		if found {
			continue
		}
		cred := t.credential()
		if err := validateCred(cred); err != nil {
			return err
		}
		port, err := freePortInRange(used, portMin, portMax)
		if err != nil {
			return err
		}
		used[port] = true
		n.store.Inbounds = append(n.store.Inbounds, &nativeInbound{
			ID: n.store.NextID, Port: port, Protocol: "socks", Network: "tcp", Security: "none",
			Remark: fmt.Sprintf("SOCKS · %02d", t.Slot), NameMode: "custom", Enable: true,
			BoundSlot: t.Slot, SocksSlot: t.Slot,
			Clients: []nativeClient{{Email: cred.User, Password: cred.Pass, Enable: true}},
		})
		n.store.NextID++
		changed = true
	}
	if !changed {
		return nil
	}
	return n.apply(tunnels)
}

// Keep the internal hand-off private. External access is a separate authenticated
// Xray listener bound to the same stable Slot; its route never uses host-direct.
func (n *Native) setPublicSocks(t *Tunnel, enabled bool, tunnels []*Tunnel) error {
	return n.setPublicSocksInRange(t, enabled, tunnels, randPortMin, randPortMax)
}

func (n *Native) setPublicSocksInRange(t *Tunnel, enabled bool, tunnels []*Tunnel, portMin, portMax int) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()
	for _, ib := range n.store.Inbounds {
		if ib.SocksSlot == t.Slot {
			if ib.Enable == enabled {
				return nil
			}
			ib.Enable = enabled
			return n.apply(tunnels)
		}
	}
	if !enabled {
		return nil
	}
	cred := t.credential()
	if err := validateCred(cred); err != nil {
		return err
	}
	used := n.store.usedPorts()
	for _, tunnel := range tunnels {
		used[tunnel.Port] = true
	}
	port, err := freePortInRange(used, portMin, portMax)
	if err != nil {
		return err
	}
	n.store.Inbounds = append(n.store.Inbounds, &nativeInbound{
		ID: n.store.NextID, Port: port, Protocol: "socks", Network: "tcp", Security: "none",
		Remark: fmt.Sprintf("SOCKS · %02d", t.Slot), NameMode: "custom", Enable: true,
		BoundSlot: t.Slot, SocksSlot: t.Slot,
		Clients: []nativeClient{{Email: cred.User, Password: cred.Pass, Enable: true}},
	})
	n.store.NextID++
	return n.apply(tunnels)
}

// A direct entry is created only through this explicit operation. Old unbound
// entries are never migrated into direct entries, and enabling it is idempotent.
func (n *Native) setHostDirect(enabled bool, serverName string, tunnels []*Tunnel) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	finish := n.beginChange()
	defer finish()
	for _, ib := range n.store.Inbounds {
		if ib.HostDirect {
			if ib.Enable == enabled {
				return nil
			}
			ib.Enable = enabled
			return n.apply(tunnels)
		}
	}
	if !enabled {
		return nil
	}
	used := n.store.usedPorts()
	for _, tunnel := range tunnels {
		used[tunnel.Port] = true
	}
	ib, err := n.prepareInbound(NewInboundSpec{
		Protocol: "vless", Network: "tcp", Security: "reality", Remark: "VPS 本机直出",
		Dest: serverName + ":443", ServerNames: serverName, Fingerprint: "chrome",
	}, used)
	if err != nil {
		return err
	}
	ib.HostDirect, ib.NameMode = true, "custom"
	n.store.Inbounds = append(n.store.Inbounds, ib)
	n.store.NextID++
	return n.apply(tunnels)
}

func (c *Console) apiHostDirect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := readConsoleJSON(w, r, &req); err != nil || req.Enabled == nil {
		writeJSON(w, 400, map[string]string{"error": "需要明确设置是否启用本机直出"})
		return
	}
	p, err := openPanel()
	n, ok := p.(*Native)
	if err != nil || !ok {
		writeJSON(w, 409, map[string]string{"error": "本机直出仅用于内置模式"})
		return
	}
	c.targetMu.Lock()
	defer c.targetMu.Unlock()
	if c.ctx.Err() != nil {
		w.WriteHeader(503)
		return
	}
	host := "www.tesla.com"
	if c.plan != nil {
		host = c.plan.ServerName
	}
	if err := n.setHostDirect(*req.Enabled, host, c.m.Tunnels()); err != nil {
		writeJSON(w, 409, map[string]string{"error": firstLine(err.Error())})
		return
	}
	invalidateInbounds()
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (c *Console) apiPublicSocks(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		// Only authenticated administration exposes credentials. Never publish
		// them in candidate observations, GitHub files or public subscriptions.
		view := c.m.ExitsOf()
		links := []map[string]any{}
		for _, e := range view.Exits {
			if e.Status == "up" && e.PublicSocks != nil && e.PublicSocks.Enable {
				links = append(links, map[string]any{"slot": e.Slot, "name": subscriptionExitName(e),
					"url": socksURL(publicHost(r), e.PublicSocks.Port, SocksCred{User: e.SocksUser, Pass: e.SocksPass})})
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]any{"links": links})
		return
	}
	var req struct {
		Slot    int   `json:"slot"`
		Enabled *bool `json:"enabled"`
	}
	if err := readConsoleJSON(w, r, &req); err != nil || req.Slot < 1 || req.Enabled == nil {
		writeJSON(w, 400, map[string]string{"error": "需要出口编号及外部访问开关"})
		return
	}
	p, err := openPanel()
	n, ok := p.(*Native)
	if err != nil || !ok {
		writeJSON(w, 409, map[string]string{"error": "外部 SOCKS 仅用于内置模式"})
		return
	}
	c.m.mu.RLock()
	t := c.m.tunnels[req.Slot]
	c.m.mu.RUnlock()
	if t == nil {
		writeJSON(w, 404, map[string]string{"error": "出口不存在"})
		return
	}
	t.changeMu.Lock()
	defer t.changeMu.Unlock()
	if !c.m.ownsTunnel(t) || c.ctx.Err() != nil {
		writeJSON(w, 409, map[string]string{"error": "出口已删除或服务正在停止"})
		return
	}
	t.opMu.Lock()
	defer t.opMu.Unlock()
	socksCfg := c.socksSnapshot()
	if err := n.setPublicSocksInRange(t, *req.Enabled, c.m.Tunnels(), socksCfg.PortMin, socksCfg.PortMax); err != nil {
		writeJSON(w, 409, map[string]string{"error": firstLine(err.Error())})
		return
	}
	invalidateInbounds()
	writeJSON(w, 200, map[string]bool{"ok": true})
}
