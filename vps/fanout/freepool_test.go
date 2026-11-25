package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freePoolSourceServers(t *testing.T, geonodeBody string, geonodeCode int, proxyscrapeBody string, proxyscrapeCode int) {
	t.Helper()
	geonode := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(geonodeCode)
		fmt.Fprint(w, geonodeBody)
	}))
	proxyscrape := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(proxyscrapeCode)
		fmt.Fprint(w, proxyscrapeBody)
	}))
	t.Cleanup(geonode.Close)
	t.Cleanup(proxyscrape.Close)
	oldGeonode, oldProxyScrape := freePoolGeonodeURL, freePoolProxyScrapeURL
	freePoolGeonodeURL, freePoolProxyScrapeURL = geonode.URL, proxyscrape.URL
	t.Cleanup(func() { freePoolGeonodeURL, freePoolProxyScrapeURL = oldGeonode, oldProxyScrape })
}

const freePoolGeonodeSample = `{"data":[
	{"ip":"5.180.40.55","port":"1080","country":"KZ","asn":"AS200590","isp":"NLS Kazakhstan LLC","upTime":95.2,"latency":92.5},
	{"ip":"1.2.3.4","port":1080,"country":"JP","asn":"AS123","isp":"Example ISP","upTime":80},
	{"ip":"999.1.1.1","port":"1080","country":"US","upTime":99}
]}`

const freePoolProxyScrapeSample = "socks5://1.2.3.4:1080\r\nsocks5://9.9.9.9:1080\ngarbage line\nsocks5://8.8.8.8:99999\n"

func TestFetchFreePoolNodesMergesSources(t *testing.T) {
	freePoolSourceServers(t, freePoolGeonodeSample, 200, freePoolProxyScrapeSample, 200)
	nodes, err := fetchFreePoolNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 3 {
		t.Fatalf("merged nodes = %d, want 3: %+v", len(nodes), nodes)
	}
	// Geonode entries come first, ordered by upTime descending; the
	// invalid-IP row is dropped.
	if nodes[0].HostName != "fp-5.180.40.55-1080" || nodes[1].HostName != "fp-1.2.3.4-1080" || nodes[2].HostName != "fp-9.9.9.9-1080" {
		t.Fatalf("unexpected order/content: %v / %v / %v", nodes[0].HostName, nodes[1].HostName, nodes[2].HostName)
	}
	dup := nodes[1]
	if dup.CountryCode != "JP" || dup.Country != "日本" || dup.ASN != "AS123" || dup.ISP != "Example ISP" {
		t.Fatalf("geonode metadata should win the dedupe: %+v", dup)
	}
	for _, n := range nodes {
		if n.Source != "freepool" || n.SocksHost != n.IP || n.SocksPort != 1080 || n.Config != "" || n.Residential {
			t.Fatalf("bad freepool node shape: %+v", n)
		}
	}
	if nodes[2].CountryCode != "" {
		t.Fatalf("proxyscrape-only entry must not invent a country: %+v", nodes[2])
	}
}

func TestFetchFreePoolNodesSingleSourceFailure(t *testing.T) {
	freePoolSourceServers(t, "", 500, freePoolProxyScrapeSample, 200)
	nodes, err := fetchFreePoolNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %d, want 2 from the surviving source", len(nodes))
	}
}

func TestFetchFreePoolNodesBothSourcesFail(t *testing.T) {
	freePoolSourceServers(t, "", 500, "", 503)
	if _, err := fetchFreePoolNodes(context.Background()); err == nil {
		t.Fatal("both sources failing must return an error")
	}
}

func TestFetchFreePoolNodesCap(t *testing.T) {
	var body strings.Builder
	for i := 0; i < 450; i++ {
		fmt.Fprintf(&body, "socks5://10.%d.%d.1:1080\n", i/256, i%256)
	}
	freePoolSourceServers(t, `{"data":[]}`, 200, body.String(), 200)
	nodes, err := fetchFreePoolNodes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != freePoolMaxNodes {
		t.Fatalf("nodes = %d, want cap %d", len(nodes), freePoolMaxNodes)
	}
}

func TestFreePoolEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pool.json")
	t.Setenv("FANOUT_POOL_CONFIG", path)
	if !freePoolEnabled() {
		t.Fatal("missing config file must default to enabled")
	}
	if err := os.WriteFile(path, []byte(`{"freepool_enabled":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	if freePoolEnabled() {
		t.Fatal("explicit false must disable the free pool")
	}
	if err := os.WriteFile(path, []byte(`{"freepool_enabled":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if !freePoolEnabled() {
		t.Fatal("explicit true must enable the free pool")
	}
	if err := os.WriteFile(path, []byte(`{"other":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if !freePoolEnabled() {
		t.Fatal("missing field must default to enabled")
	}
}

func stubFetchFuncs(t *testing.T, nodes []Node, nodesErr error, free []Node, freeErr error) {
	t.Helper()
	oldNodes, oldFree := fetchNodesFunc, fetchFreePoolFn
	fetchNodesFunc = func(time.Duration) ([]Node, error) { return nodes, nodesErr }
	fetchFreePoolFn = func(context.Context) ([]Node, error) { return free, freeErr }
	t.Cleanup(func() { fetchNodesFunc, fetchFreePoolFn = oldNodes, oldFree })
}

func TestRefreshNodesMergesFreePool(t *testing.T) {
	t.Setenv("FANOUT_POOL_CONFIG", filepath.Join(t.TempDir(), "absent.json"))
	vpn := []Node{
		{HostName: "public-vpn-1.example", IP: "203.0.113.1", Config: "cfg"},
		{HostName: "fp-9.9.9.9-1080", IP: "9.9.9.9", Config: "cfg-wins"},
	}
	free := []Node{
		{HostName: "fp-9.9.9.9-1080", IP: "9.9.9.9", Source: "freepool", SocksHost: "9.9.9.9", SocksPort: 1080},
		{HostName: "fp-8.8.8.8-1080", IP: "8.8.8.8", Source: "freepool", SocksHost: "8.8.8.8", SocksPort: 1080},
	}
	stubFetchFuncs(t, vpn, nil, free, nil)
	m := NewManager(4, t.TempDir())
	count, err := m.RefreshNodes()
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("count = %d, want 3 (2 vpngate + 1 new freepool)", count)
	}
	nodes, _ := m.Nodes()
	byHost := map[string]Node{}
	for _, n := range nodes {
		byHost[n.HostName] = n
	}
	if byHost["fp-9.9.9.9-1080"].Source == "freepool" {
		t.Fatal("hostname collision must keep the VPN Gate node")
	}
	if byHost["fp-8.8.8.8-1080"].Source != "freepool" {
		t.Fatal("freepool node missing after merge")
	}
}

func TestRefreshNodesFreePoolFailureIsNotFatal(t *testing.T) {
	t.Setenv("FANOUT_POOL_CONFIG", filepath.Join(t.TempDir(), "absent.json"))
	stubFetchFuncs(t, []Node{{HostName: "public-vpn-1.example", Config: "cfg"}}, nil, nil, fmt.Errorf("boom"))
	m := NewManager(4, t.TempDir())
	count, err := m.RefreshNodes()
	if err != nil || count != 1 {
		t.Fatalf("count=%d err=%v, want 1/nil", count, err)
	}
}

func TestRefreshNodesVPNGateFailureStillFails(t *testing.T) {
	t.Setenv("FANOUT_POOL_CONFIG", filepath.Join(t.TempDir(), "absent.json"))
	stubFetchFuncs(t, nil, fmt.Errorf("pool down"), []Node{{HostName: "fp-8.8.8.8-1080", Source: "freepool"}}, nil)
	m := NewManager(4, t.TempDir())
	if _, err := m.RefreshNodes(); err == nil {
		t.Fatal("VPN Gate failure must still fail the refresh")
	}
}

func TestRefreshNodesFreePoolDisabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pool.json")
	if err := os.WriteFile(path, []byte(`{"freepool_enabled":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FANOUT_POOL_CONFIG", path)
	called := false
	oldNodes, oldFree := fetchNodesFunc, fetchFreePoolFn
	fetchNodesFunc = func(time.Duration) ([]Node, error) { return []Node{{HostName: "h", Config: "c"}}, nil }
	fetchFreePoolFn = func(context.Context) ([]Node, error) { called = true; return nil, nil }
	t.Cleanup(func() { fetchNodesFunc, fetchFreePoolFn = oldNodes, oldFree })
	m := NewManager(4, t.TempDir())
	if _, err := m.RefreshNodes(); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Fatal("disabled free pool must not be fetched")
	}
}

func TestThirdPartyHTTPClientCredentials(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	anon := thirdPartyHTTPClient(ThirdPartyProxy{Host: "1.2.3.4", Port: 1080})
	defer anon.CloseIdleConnections()
	u, err := anon.Transport.(*http.Transport).Proxy(req)
	if err != nil {
		t.Fatal(err)
	}
	if u.User != nil {
		t.Fatalf("credential-free proxy must not carry userinfo: %v", u.User)
	}
	authed := thirdPartyHTTPClient(ThirdPartyProxy{Host: "1.2.3.4", Port: 1080, Username: "user", Password: "pass"})
	defer authed.CloseIdleConnections()
	u, err = authed.Transport.(*http.Transport).Proxy(req)
	if err != nil {
		t.Fatal(err)
	}
	if u.User == nil || u.User.Username() != "user" {
		t.Fatalf("credentialed proxy lost its userinfo: %v", u)
	}
}

func TestFreePoolCheckResultMapping(t *testing.T) {
	score := 42
	node := Node{HostName: "fp-1.2.3.4-1080", Source: "freepool", SocksHost: "1.2.3.4", SocksPort: 1080}
	rec := ThirdPartyRecord{Status: "passed", ActualIP: "1.2.3.4", Country: "JP", IPType: "datacenter", LatencyMS: 123.5, IPTest: &IPTestInfo{Kind: "IDC 机房", Usage: "代理", Composite: &score}}
	got := freePoolCheckResult(node, rec)
	if got.Protocol != "socks5" || got.Host != node.HostName || got.Status != "passed" || got.Code != "" ||
		got.ActualIP != "1.2.3.4" || got.Country != "JP" || got.IPType != "datacenter" || got.LatencyMS != 123.5 ||
		got.IPTest == nil || *got.IPTest.Composite != 42 {
		t.Fatalf("mapping lost fields: %+v", got)
	}
	if got.ProfileSHA != profileDigest("") {
		t.Fatalf("profile sha = %q, want digest of empty config", got.ProfileSHA)
	}
	failed := freePoolCheckResult(node, ThirdPartyRecord{Status: "failed", Code: "proxy_https_failed"})
	if failed.Status != "failed" || failed.Code != "proxy_https_failed" || failed.IPType != "unknown" {
		t.Fatalf("failed mapping wrong: %+v", failed)
	}
}

func TestValidateThirdPartyForSource(t *testing.T) {
	free := ThirdPartyProxy{Host: "1.2.3.4", Port: 1080, Source: "freepool", Subscribe: true}
	if err := validateThirdPartyForSource(free); err != nil {
		t.Fatalf("freepool entry without credentials must validate: %v", err)
	}
	if err := validateThirdParty(free); err == nil {
		t.Fatal("manual validation must still require credentials")
	}
	manual := free
	manual.Source = ""
	if err := validateThirdPartyForSource(manual); err == nil {
		t.Fatal("manual entry without credentials must fail the source variant too")
	}
	bad := free
	bad.Port = 0
	if err := validateThirdPartyForSource(bad); err == nil {
		t.Fatal("freepool entry with a bad port must fail")
	}
}

func TestProbeFreePoolCandidateUnreachable(t *testing.T) {
	_, _, _, c := thirdPartyFixture(t)
	node := Node{HostName: "fp-127.0.0.1-1", Source: "freepool", SocksHost: "127.0.0.1", SocksPort: 1}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	got := c.probeFreePoolCandidate(ctx, node, func(string) {})
	if got.Status != "failed" || got.Protocol != "socks5" || got.Host != node.HostName || got.ProfileSHA != profileDigest("") {
		t.Fatalf("unreachable freepool probe wrong: %+v", got)
	}
}

// startCheck 必须把免费池候选分发到 SOCKS5 探测而不是 OpenVPN 路径：
// 节点指向 127.0.0.1:1（无服务），结果应为 socks5 协议的 failed
// 并落入控制台结果表，而不是 openvpn 的环境错误。
func TestStartCheckDispatchesFreePoolToSocksProbe(t *testing.T) {
	_, _, m, c := thirdPartyFixture(t)
	node := Node{HostName: "fp-127.0.0.1-1", IP: "127.0.0.1", Source: "freepool", SocksHost: "127.0.0.1", SocksPort: 1}
	m.mu.Lock()
	m.nodes = []Node{node}
	m.mu.Unlock()
	j, err := c.startCheck(CheckRequest{Hosts: []string{node.HostName}, Parallelism: 1})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-j.finished:
	case <-time.After(30 * time.Second):
		t.Fatal("freepool check did not finish")
	}
	c.checksMu.Lock()
	r, ok := c.results[node.HostName]
	c.checksMu.Unlock()
	if !ok {
		t.Fatal("freepool check result was not recorded")
	}
	if r.Protocol != "socks5" || r.Status != "failed" || r.ProfileSHA != profileDigest("") {
		t.Fatalf("freepool check result wrong: %+v", r)
	}
}

func freePoolPromoteFixture(t *testing.T) (*Native, *Console, Node) {
	t.Helper()
	n, _, m, c := thirdPartyFixture(t)
	node := Node{HostName: "fp-198.51.100.23-1080", IP: "198.51.100.23", Source: "freepool", SocksHost: "198.51.100.23", SocksPort: 1080}
	m.mu.Lock()
	m.nodes = []Node{node}
	m.mu.Unlock()
	return n, c, node
}

func promoteRequest(c *Console, host string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	c.apiFreePoolPromote(w, httptest.NewRequest(http.MethodPost, "/api/freepool/promote", strings.NewReader(fmt.Sprintf(`{"host":%q}`, host))))
	return w
}

// 注：promote 的新建入站路径与手动添加第三方代理共用 saveThirdParty(0,…)，
// 其内部 prepareInbound 需要真实 xray 二进制生成 REALITY 密钥并对目标站点
// 做真实 TLS1.3 握手，和上游一样没有单元测试覆盖（靠部署验收）。
// 这里覆盖 promote 的守卫、幂等两条路径，以及无凭据条目走内部保存
// 机器与落盘重载校验的完整链路。
func TestFreePoolPromoteIdempotentWhenExitExists(t *testing.T) {
	n, c, node := freePoolPromoteFixture(t)
	// Not yet checked: promote must refuse.
	if w := promoteRequest(c, node.HostName); w.Code != 409 {
		t.Fatalf("promote before check: code=%d body=%s", w.Code, w.Body.String())
	}
	// Seed the store as a previous successful promote would have left it.
	p := ThirdPartyProxy{Host: node.SocksHost, Port: node.SocksPort, Country: "JP", Remark: "免费池 · JP", Subscribe: true, Source: "freepool"}
	ib := *n.store.Inbounds[0]
	ib.ID, ib.Port, ib.BoundTo, ib.Security = 7, 30007, "", "reality"
	ib.ThirdParty = &p
	ib.Reality = &realityConfig{ServerNames: []string{"example.com"}, PublicKey: "fixture-public", PrivateKey: "fixture-private", ShortIDs: []string{"abcd"}}
	n.store.NextID = 8
	n.store.Inbounds = append(n.store.Inbounds, &ib)
	if err := n.store.save(n.dir); err != nil {
		t.Fatal(err)
	}
	c.checksMu.Lock()
	c.results[node.HostName] = CheckResult{Host: node.HostName, Status: "passed", Country: "JP", ActualIP: "198.51.100.23", CheckedAt: time.Now(), ProfileSHA: profileDigest("")}
	c.checksMu.Unlock()
	before := len(n.store.Inbounds)
	w := promoteRequest(c, node.HostName)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"existing":true`) || !strings.Contains(w.Body.String(), `"id":7`) {
		t.Fatalf("promote existing: code=%d body=%s", w.Code, w.Body.String())
	}
	if len(n.store.Inbounds) != before {
		t.Fatal("idempotent promote created a duplicate inbound")
	}
}

func TestSaveThirdPartyFreePoolNoCredentials(t *testing.T) {
	n, _, m, _ := thirdPartyFixture(t)
	// Turn the fixture's manual entry into a freepool one through the
	// internal save machine (edit path): empty credentials must pass
	// only because Source == "freepool".
	p := ThirdPartyProxy{Host: "198.51.100.23", Port: 1080, Country: "JP", Remark: "免费池 · JP", Subscribe: true, Source: "freepool"}
	if _, err := n.saveThirdParty(2, p, true, "", m.Tunnels()); err != nil {
		t.Fatalf("freepool save rejected: %v", err)
	}
	saved, err := n.thirdPartySnapshot(2)
	if err != nil {
		t.Fatal(err)
	}
	if saved.ThirdParty.Source != "freepool" || saved.ThirdParty.Username != "" || !saved.Enable {
		t.Fatalf("saved freepool entry wrong: %+v", saved.ThirdParty)
	}
	// The same empty-credential shape without the freepool source must fail.
	manual := p
	manual.Source = ""
	if _, err := n.saveThirdParty(2, manual, true, "", m.Tunnels()); err == nil {
		t.Fatal("manual entry without credentials must not save")
	}
	// And the persisted store must reload cleanly with the freepool entry.
	st, err := loadNativeStore(n.dir)
	if err != nil {
		t.Fatalf("store reload with freepool entry failed: %v", err)
	}
	found := false
	for _, ib := range st.Inbounds {
		if ib.ThirdParty != nil && ib.ThirdParty.Source == "freepool" {
			found = true
		}
	}
	if !found {
		t.Fatal("freepool entry missing after reload")
	}
}

func TestFreePoolPromoteRejectsOthers(t *testing.T) {
	_, c, node := freePoolPromoteFixture(t)
	c.checksMu.Lock()
	c.results[node.HostName] = CheckResult{Host: node.HostName, Status: "passed", CheckedAt: time.Now(), ProfileSHA: profileDigest("")}
	c.checksMu.Unlock()
	if w := promoteRequest(c, "public-vpn-9.example"); w.Code != 404 {
		t.Fatalf("unknown host: code=%d", w.Code)
	}
	// Stale results (older than the console's 15 minute window) refuse.
	c.checksMu.Lock()
	r := c.results[node.HostName]
	r.CheckedAt = time.Now().Add(-16 * time.Minute)
	c.results[node.HostName] = r
	c.checksMu.Unlock()
	if w := promoteRequest(c, node.HostName); w.Code != 409 {
		t.Fatalf("stale result: code=%d", w.Code)
	}
}
