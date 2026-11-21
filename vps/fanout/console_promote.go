package main

import (
	"log"
	"net/http"
	"strings"
)

// slotPinned 判断一个 Slot 是否被用户固定到了指定候选节点。
// 固定出口是计划（目标数量）之外的用户指定，对账逻辑据此跳过它。
func slotPinned(t *Tunnel) bool {
	return t != nil && t.policySnapshot().PinnedHost != ""
}

// apiPromoteCandidate 把候选页选定的一个节点直接建成固定出口：
// 新建一个 Slot，策略只放行该节点本身，不占目标数量、不会被数量
// 对账移除；节点连不上时退避重试它自己，不自动换到别的节点。
// 就绪后与普通出口一样自动进入订阅。
func (c *Console) apiPromoteCandidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	var in struct {
		Host string `json:"host"`
	}
	if err := readConsoleJSON(w, r, &in); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	host := strings.TrimSpace(in.Host)
	if host == "" {
		writeJSON(w, 400, map[string]string{"error": "缺少候选节点"})
		return
	}
	if currentPanelMode() != "native" {
		writeJSON(w, 409, map[string]string{"error": "设为出口仅用于内置 Xray 模式"})
		return
	}
	c.targetMu.Lock()
	defer c.targetMu.Unlock()
	if c.ctx.Err() != nil {
		writeJSON(w, 503, map[string]string{"error": "管理服务正在停止"})
		return
	}
	nodes, _ := c.m.Nodes()
	var node Node
	for _, n := range nodes {
		if n.HostName == host {
			node = n
			break
		}
	}
	if node.HostName == "" {
		writeJSON(w, 404, map[string]string{"error": "候选不存在，请先刷新候选池"})
		return
	}
	for _, t := range c.m.Tunnels() {
		if t.snapshot().Node.HostName == host {
			writeJSON(w, 409, map[string]string{"error": "该节点已经是出口"})
			return
		}
	}
	policy := defaultSlotPolicyForMode("", false)
	policy.PinnedHost = host
	tun, err := c.start(node, policy)
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": firstLine(err.Error())})
		return
	}
	// 立刻对账一次给新出口绑入站（订阅靠它收录）；还没有计划的实例
	// reconcile 会提前返回，这里直接补一次绑定。
	if err := c.reconcile(); err != nil {
		log.Printf("设为出口后对账失败: %v", err)
	}
	if c.plan == nil {
		if err := c.ensure(c.m.Tunnels(), "www.tesla.com"); err != nil {
			log.Printf("设为出口后绑定入站失败: %v", err)
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "slot": tun.Slot})
}
