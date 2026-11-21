package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPinnedHostNormalization(t *testing.T) {
	p := defaultSlotPolicyForMode("", false)
	p.PinnedHost = "  public-vpn-123.opengw.net "
	got, err := normalizePolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if got.PinnedHost != "public-vpn-123.opengw.net" {
		t.Fatalf("pin not trimmed/kept: %q", got.PinnedHost)
	}
	for _, bad := range []string{"has space.example", "line\nbreak", strings.Repeat("a", 254)} {
		p.PinnedHost = bad
		if _, err := normalizePolicy(p); err == nil {
			t.Fatalf("invalid pin accepted: %q", bad)
		}
	}
	// 计划模板策略不许带固定节点：所有自动出口会去抢同一个节点。
	plan := ExitPlan{Count: 1, Policy: p, ServerName: "fixture.example.invalid"}
	plan.Policy.PinnedHost = "pin.example"
	if err := validateExitPlan(&plan, 4); err != nil {
		t.Fatal(err)
	}
	if plan.Policy.PinnedHost != "" {
		t.Fatal("plan policy kept a pinned host")
	}
}

func TestPinnedCandidatesOnlyPinnedNode(t *testing.T) {
	m := NewManager(3, t.TempDir())
	m.nodes = []Node{
		{HostName: "a", CountryCode: "JP"},
		{HostName: "b", CountryCode: "US"},
		{HostName: "c", CountryCode: "JP"},
	}
	p := defaultSlotPolicyForMode("", false)
	p.PinnedHost = "b"
	tunnel := &Tunnel{Slot: 1, Status: "waiting_for_nodes", Policy: &p, Node: Node{HostName: "b", CountryCode: "US", Config: "b-profile"}}
	m.tunnels[1] = tunnel
	got := m.candidatesFor(tunnel)
	if len(got) != 1 || got[0].HostName != "b" {
		t.Fatalf("pinned slot admitted other candidates: %v", got)
	}
	// 候选池刷新后固定节点不在清单里：用 Slot 保存的节点兜底，不换人。
	m.nodes = []Node{{HostName: "a", CountryCode: "JP"}}
	got = m.candidatesFor(tunnel)
	if len(got) != 1 || got[0].HostName != "b" || got[0].Config != "b-profile" {
		t.Fatalf("pinned slot lost its saved node: %v", got)
	}
	// 固定节点被别的 Slot 占用时不能抢。
	other := &Tunnel{Slot: 2, Status: "up", Node: Node{HostName: "b", CountryCode: "US"}}
	m.tunnels[2] = other
	if got := m.candidatesFor(tunnel); len(got) != 0 {
		t.Fatalf("pinned slot stole an occupied node: %v", got)
	}
	delete(m.tunnels, 2)
	// 冷却期内本轮跳过，靠外层退避重试。
	tunnel.cooldown = map[string]time.Time{"b": time.Now().Add(time.Minute)}
	if got := m.candidatesFor(tunnel); len(got) != 0 {
		t.Fatalf("pinned slot ignored cooldown: %v", got)
	}
}

func TestPinnedSwapRejectedAndPolicyPersists(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(3, dir)
	p := defaultSlotPolicyForMode("", false)
	p.PinnedHost = "pin.example"
	tunnel := &Tunnel{Slot: 1, Port: 17928, Status: "up", Policy: &p, Node: Node{HostName: "pin.example", CountryCode: "JP", Config: "pin-profile"}, Cred: SocksCred{User: "u", Pass: "p"}}
	tunnel.resetWork()
	m.tunnels[1] = tunnel
	if err := m.Swap(1); err == nil || !strings.Contains(err.Error(), "固定") {
		t.Fatalf("auto swap on pinned slot not rejected: %v", err)
	}
	if tunnel.Node.HostName != "pin.example" {
		t.Fatal("rejected swap changed the node")
	}
	if err := m.saveState(); err != nil {
		t.Fatal(err)
	}
	restored := NewManager(3, dir)
	if n, err := restored.restoreState(); err != nil || n != 1 {
		t.Fatalf("restore failed: %v %d", err, n)
	}
	if got := restored.tunnels[1].policySnapshot().PinnedHost; got != "pin.example" {
		t.Fatalf("pin lost across restart: %q", got)
	}
}

func TestConsolePinnedExitOutsideTargetCount(t *testing.T) {
	c := consoleFixture(t)
	plan := ExitPlan{Count: 2, Policy: defaultSlotPolicyForMode("", false), ServerName: "fixture.example.invalid"}
	if err := c.applyTarget(plan); err != nil {
		t.Fatal(err)
	}
	pinned := defaultSlotPolicyForMode("", false)
	pinned.PinnedHost = "pin.example"
	tun, err := c.start(Node{HostName: "pin.example", CountryCode: "JP"}, pinned)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.reconcile(); err != nil {
		t.Fatal(err)
	}
	if len(c.m.Tunnels()) != 3 {
		t.Fatalf("pinned exit missing after reconcile: %d", len(c.m.Tunnels()))
	}
	// 目标调小：只减自动出口，固定出口保留。
	plan.Count = 1
	if err := c.applyTarget(plan); err != nil {
		t.Fatal(err)
	}
	if len(c.m.Tunnels()) != 2 || c.m.tunnels[tun.Slot] == nil {
		t.Fatal("target decrease removed the pinned exit")
	}
	// 目标调大：补的是自动出口，固定出口不占数。
	plan.Count = 3
	if err := c.applyTarget(plan); err != nil {
		t.Fatal(err)
	}
	if len(c.m.Tunnels()) != 4 {
		t.Fatalf("pinned exit counted toward target: %d", len(c.m.Tunnels()))
	}
	// 删固定出口不动目标数量。
	if err := c.deleteSlot(tun.Slot); err != nil {
		t.Fatal(err)
	}
	if c.plan.Count != 3 {
		t.Fatalf("deleting pinned exit changed target: %d", c.plan.Count)
	}
	if len(c.m.Tunnels()) != 3 || c.m.tunnels[tun.Slot] != nil {
		t.Fatal("pinned exit not deleted or auto exits disturbed")
	}
}

func TestPromoteCandidateCreatesPinnedExit(t *testing.T) {
	c := consoleFixture(t)
	panelState.mu.Lock()
	prevForced := panelState.forced
	panelState.forced = "native"
	panelState.mu.Unlock()
	t.Cleanup(func() {
		panelState.mu.Lock()
		panelState.forced = prevForced
		panelState.mu.Unlock()
	})
	c.m.nodes = []Node{{HostName: "pin.example", CountryCode: "JP", Config: "pin-profile"}}
	req := httptest.NewRequest(http.MethodPost, "/api/console/promote", strings.NewReader(`{"host":"pin.example"}`))
	rec := httptest.NewRecorder()
	c.apiPromoteCandidate(rec, req)
	if rec.Code != 200 {
		t.Fatalf("promote failed: %d %s", rec.Code, rec.Body.String())
	}
	if len(c.m.Tunnels()) != 1 {
		t.Fatal("promote did not create an exit")
	}
	for _, tun := range c.m.Tunnels() {
		if tun.policySnapshot().PinnedHost != "pin.example" || tun.Node.HostName != "pin.example" {
			t.Fatal("promoted exit is not pinned to the chosen candidate")
		}
	}
	// 重复设为出口要明确拒绝。
	req = httptest.NewRequest(http.MethodPost, "/api/console/promote", strings.NewReader(`{"host":"pin.example"}`))
	rec = httptest.NewRecorder()
	c.apiPromoteCandidate(rec, req)
	if rec.Code != 409 {
		t.Fatalf("duplicate promote accepted: %d", rec.Code)
	}
	// 不在候选池里的节点不能凭空指定。
	req = httptest.NewRequest(http.MethodPost, "/api/console/promote", strings.NewReader(`{"host":"ghost.example"}`))
	rec = httptest.NewRecorder()
	c.apiPromoteCandidate(rec, req)
	if rec.Code != 404 {
		t.Fatalf("unknown candidate accepted: %d", rec.Code)
	}
}
