package main

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateSocksSettings(t *testing.T) {
	valid := []socksSettings{
		{PortMin: 20000, PortMax: 60000, CredMode: credModeRandom},
		{PortMin: 30000, PortMax: 30000, CredMode: credModeFixed, FixedUser: "fixeduser", FixedPass: "fixedpass123"},
	}
	for _, s := range valid {
		if err := validateSocksSettings(s); err != nil {
			t.Fatal("valid settings rejected", s, err)
		}
	}
	invalid := []socksSettings{
		{PortMin: 80, PortMax: 60000, CredMode: credModeRandom},
		{PortMin: 30001, PortMax: 30000, CredMode: credModeRandom},
		{PortMin: 20000, PortMax: 70000, CredMode: credModeRandom},
		{PortMin: 20000, PortMax: 60000, CredMode: "bogus"},
		{PortMin: 20000, PortMax: 60000, CredMode: credModeFixed},
		{PortMin: 20000, PortMax: 60000, CredMode: credModeFixed, FixedUser: "has space", FixedPass: "fixedpass123"},
	}
	for _, s := range invalid {
		if err := validateSocksSettings(s); err == nil {
			t.Fatal("invalid settings accepted", s)
		}
	}
}

func TestSocksSettingsNewCredModes(t *testing.T) {
	fixed := socksSettings{PortMin: 20000, PortMax: 60000, CredMode: credModeFixed, FixedUser: "fixeduser", FixedPass: "fixedpass123"}
	for i := 0; i < 3; i++ {
		cred, err := fixed.newCred()
		if err != nil || cred != fixed.fixedCred() {
			t.Fatal("fixed mode must always return the fixed credential", cred, err)
		}
	}
	random := defaultSocksSettings()
	a, err := random.newCred()
	if err != nil || a.User == "" || a.Pass == "" {
		t.Fatal("random mode must generate a credential", err)
	}
	b, err := random.newCred()
	if err != nil || a == b {
		t.Fatal("random mode must generate distinct credentials", err)
	}
}

func TestFreePortInRange(t *testing.T) {
	taken := map[int]bool{}
	for p := 24100; p <= 24110; p++ {
		taken[p] = true
	}
	delete(taken, 24107)
	port, err := freePortInRange(taken, 24100, 24110)
	if err != nil || port != 24107 {
		t.Fatal("must find the only untaken port in range", port, err)
	}
	taken[24107] = true
	if _, err := freePortInRange(taken, 24100, 24110); err == nil {
		t.Fatal("full range must error")
	}
	if _, err := freePortInRange(taken, 30000, 20000); err == nil {
		t.Fatal("inverted range must error")
	}
}

func TestReconcilePublicSocksPortsOnlyTouchesEnabled(t *testing.T) {
	n, runtime, ts := rollbackFixture(t)
	// External access is off by default: reconciliation must not create
	// an inbound for a tunnel that has none, nor restart Xray for it.
	starts := runtime.starts
	if err := n.reconcilePublicSocksPorts(ts, 24100, 24110); err != nil {
		t.Fatal(err)
	}
	if n.socksExposures()[1] != nil || runtime.starts != starts {
		t.Fatal("reconcile must not auto-open external SOCKS")
	}
	// The user opens it manually; the port comes from the configured range.
	if err := n.setPublicSocksInRange(ts[0], true, ts, 24100, 24110); err != nil {
		t.Fatal(err)
	}
	exposure := n.socksExposures()[1]
	if exposure == nil || !exposure.Enable {
		t.Fatal("manual open must enable external SOCKS")
	}
	if exposure.Port < 24100 || exposure.Port > 24110 {
		t.Fatal("external port outside configured range", exposure.Port)
	}
	starts = runtime.starts
	if err := n.reconcilePublicSocksPorts(ts, 24100, 24110); err != nil || runtime.starts != starts {
		t.Fatal("idempotent reconcile restarted Xray")
	}
	// A manual close sticks: reconciliation never re-opens it.
	if err := n.setPublicSocks(ts[0], false, ts); err != nil {
		t.Fatal(err)
	}
	if n.socksExposures()[1].Enable {
		t.Fatal("manual close fixture failed")
	}
	starts = runtime.starts
	if err := n.reconcilePublicSocksPorts(ts, 24100, 24110); err != nil || runtime.starts != starts {
		t.Fatal("reconcile restarted Xray for a closed inbound")
	}
	if n.socksExposures()[1].Enable {
		t.Fatal("reconcile must not re-open a manually closed inbound")
	}
	// Re-open manually, then a range change still moves the enabled
	// port into the new range.
	if err := n.setPublicSocksInRange(ts[0], true, ts, 24100, 24110); err != nil {
		t.Fatal(err)
	}
	if err := n.reconcilePublicSocksPorts(ts, 25000, 25010); err != nil {
		t.Fatal(err)
	}
	moved := n.socksExposures()[1]
	if !moved.Enable || moved.Port < 25000 || moved.Port > 25010 {
		t.Fatal("range change must move the enabled port into the new range", moved)
	}
	starts = runtime.starts
	if err := n.reconcilePublicSocksPorts(ts, 25000, 25010); err != nil || runtime.starts != starts {
		t.Fatal("idempotent reconcile after move restarted Xray")
	}
	stored, err := loadNativeStore(n.dir)
	if err != nil || len(stored.Inbounds) != 2 || !stored.Inbounds[1].Enable || stored.Inbounds[1].SocksSlot != 1 {
		t.Fatal("external access not persisted", err)
	}
}

func TestSocksSettingsSaveLoadAndProvider(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(32, dir)
	c := &Console{m: m}
	if err := c.loadSocksSettings(); err != nil {
		t.Fatal(err)
	}
	if got := c.socksSnapshot(); got != defaultSocksSettings() {
		t.Fatal("absent file must yield defaults", got)
	}
	want := socksSettings{PortMin: 26000, PortMax: 26999, CredMode: credModeFixed, FixedUser: "fixeduser", FixedPass: "fixedpass123"}
	if err := c.saveSocksSettings(want); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "socks-settings.json")); err != nil {
		t.Fatal("settings file not written", err)
	}
	m2 := NewManager(32, dir)
	c2 := &Console{m: m2}
	if err := c2.loadSocksSettings(); err != nil {
		t.Fatal(err)
	}
	if got := c2.socksSnapshot(); got != want {
		t.Fatal("settings roundtrip mismatch", got, want)
	}
	cred, err := m2.newSlotCred()
	if err != nil || cred != want.fixedCred() {
		t.Fatal("manager must use the fixed credential for new slots", cred, err)
	}
}

func TestRestoredTunnelWithoutCredUsesProvider(t *testing.T) {
	fixed := SocksCred{User: "fixeduser", Pass: "fixedpass123"}
	st := &persistedState{Tunnels: []persistedTunnel{{Slot: 1, Port: 18001, HostName: "gone-node"}}}
	tunnels, err := prepareRestoredTunnelsWithCred(st, nil, func() (SocksCred, error) { return fixed, nil })
	if err != nil || len(tunnels) != 1 || tunnels[0].Cred != fixed {
		t.Fatal("restored tunnel without saved cred must use provider", tunnels, err)
	}
	// A saved credential is identity: restore must not rotate it.
	st.Tunnels[0].SocksUser, st.Tunnels[0].SocksPass = "saved-user", "saved-pass"
	tunnels, err = prepareRestoredTunnelsWithCred(st, nil, func() (SocksCred, error) { return fixed, nil })
	if err != nil || tunnels[0].Cred != (SocksCred{User: "saved-user", Pass: "saved-pass"}) {
		t.Fatal("saved credential must be preserved on restore", tunnels, err)
	}
}

func TestApplySocksCredsFixedThenRandom(t *testing.T) {
	n, _, ts := rollbackFixture(t)
	usePanel(t, n)
	m := NewManager(32, t.TempDir())
	second := &Tunnel{Slot: 2, Port: 17929, Status: "up", Node: Node{HostName: "b"}, Cred: SocksCred{User: "second-user", Pass: "second-pass"}}
	m.tunnels[1] = ts[0]
	m.tunnels[2] = second
	c := &Console{m: m}

	fixed := socksSettings{PortMin: 20000, PortMax: 60000, CredMode: credModeFixed, FixedUser: "fixeduser", FixedPass: "fixedpass123"}
	if err := c.applySocksCreds(fixed, false); err != nil {
		t.Fatal(err)
	}
	for _, tun := range []*Tunnel{ts[0], second} {
		if tun.credential() != fixed.fixedCred() {
			t.Fatal("fixed mode must unify every slot", tun.Slot, tun.credential())
		}
	}
	// Saving fixed again is a no-op for already unified slots.
	if err := c.applySocksCreds(fixed, false); err != nil {
		t.Fatal(err)
	}
	random := defaultSocksSettings()
	before := []SocksCred{ts[0].credential(), second.credential()}
	if err := c.applySocksCreds(random, false); err != nil {
		t.Fatal(err)
	}
	if ts[0].credential() != before[0] || second.credential() != before[1] {
		t.Fatal("random save without reapply must not rotate credentials")
	}
	if err := c.applySocksCreds(random, true); err != nil {
		t.Fatal(err)
	}
	a, b := ts[0].credential(), second.credential()
	if a == fixed.fixedCred() || b == fixed.fixedCred() || a == b || a.User == "" || b.User == "" {
		t.Fatal("switching to random must regenerate distinct credentials", a, b)
	}
}

// Regression for the production report "only the first list entry
// changed": batch application must unify every tunnel with a single
// Xray restart, and the watch-side enforcement must converge drifted
// credentials without any save action.
func TestApplySocksCredsBatchSingleRestartAndEnforce(t *testing.T) {
	n, runtime, ts := rollbackFixture(t)
	usePanel(t, n)
	m := NewManager(32, t.TempDir())
	second := &Tunnel{Slot: 2, Port: 17930, Status: "up", Node: Node{HostName: "b"}, Cred: SocksCred{User: "user-two", Pass: "pass-two-123"}}
	third := &Tunnel{Slot: 3, Port: 17931, Status: "up", Node: Node{HostName: "c"}, Cred: SocksCred{User: "user-three", Pass: "pass-three-123"}}
	m.tunnels[1] = ts[0]
	m.tunnels[2] = second
	m.tunnels[3] = third
	c := &Console{m: m}
	fixed := socksSettings{PortMin: 20000, PortMax: 60000, CredMode: credModeFixed, FixedUser: "fixeduser", FixedPass: "fixedpass123"}
	if err := c.saveSocksSettings(fixed); err != nil {
		t.Fatal(err)
	}
	starts := runtime.starts
	if err := c.applySocksCreds(fixed, false); err != nil {
		t.Fatal(err)
	}
	if runtime.starts != starts+1 {
		t.Fatal("batch apply must restart Xray exactly once", runtime.starts, starts)
	}
	for _, tun := range []*Tunnel{ts[0], second, third} {
		if tun.credential() != fixed.fixedCred() {
			t.Fatal("batch apply missed a slot", tun.Slot, tun.credential())
		}
	}
	// Drift one slot back (simulating a save-time miss or a restore);
	// enforcement must converge it, and a converged state is a no-op.
	second.setCredential(SocksCred{User: "drifted", Pass: "drifted-pass"})
	if err := c.enforceFixedCreds(); err != nil {
		t.Fatal(err)
	}
	if second.credential() != fixed.fixedCred() {
		t.Fatal("enforcement did not converge drifted credential", second.credential())
	}
	starts = runtime.starts
	if err := c.enforceFixedCreds(); err != nil || runtime.starts != starts {
		t.Fatal("converged enforcement must be a no-op")
	}
}

// The settings handler itself must unify every tunnel, not just the
// first, in one request.
func TestSocksSettingsHandlerUnifiesAllTunnels(t *testing.T) {
	n, _, ts := rollbackFixture(t)
	usePanel(t, n)
	m := NewManager(32, t.TempDir())
	second := &Tunnel{Slot: 2, Port: 17930, Status: "up", Node: Node{HostName: "b"}, Cred: SocksCred{User: "user-two", Pass: "pass-two-123"}}
	third := &Tunnel{Slot: 3, Port: 17931, Status: "up", Node: Node{HostName: "c"}, Cred: SocksCred{User: "user-three", Pass: "pass-three-123"}}
	m.tunnels[1] = ts[0]
	m.tunnels[2] = second
	m.tunnels[3] = third
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &Console{m: m, ctx: ctx}
	if err := c.loadSocksSettings(); err != nil {
		t.Fatal(err)
	}
	body := `{"port_min":58000,"port_max":60000,"cred_mode":"fixed","fixed_user":"fixeduser","fixed_pass":"fixedpass123","apply_creds":true}`
	req := httptest.NewRequest("POST", "/api/console/socks/settings", strings.NewReader(body))
	rec := httptest.NewRecorder()
	c.apiSocksSettings(rec, req)
	if rec.Code != 200 {
		t.Fatalf("settings save failed: %d %s", rec.Code, rec.Body.String())
	}
	for _, tun := range []*Tunnel{ts[0], second, third} {
		if tun.credential() != (SocksCred{User: "fixeduser", Pass: "fixedpass123"}) {
			t.Fatal("handler did not unify slot", tun.Slot, tun.credential())
		}
	}
}
