package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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

// 存量兼容回归：v0.15.0 promote 生成的 freepool 第三方条目在
// v0.16.0 里没有新建入口了，但既有条目经内部保存机器按原样保存、
// 落盘重载必须继续可用（空凭据只因 Source == "freepool" 放行）。
func TestSaveThirdPartyFreePoolNoCredentials(t *testing.T) {
	n, _, m, _ := thirdPartyFixture(t)
	// Turn the fixture's manual entry into a freepool one through the
	// internal save machine: empty credentials must pass
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

// ---- 免费池上游拨号器（dialViaSocks5Upstream） ----

// fakeSocks5Request 记录假上游看到的一次 CONNECT 请求。
type fakeSocks5Request struct {
	ATYP byte
	Host string
	Port int
}

// fakeSocks5Upstream 是本地假 SOCKS5 上游：记录客户端提供的方法
// 列表与每次 CONNECT 的地址形态，成功时把连接中继到真实目标。
// authRequired 时在方法协商阶段选用户名口令（客户端必须拒绝）；
// rejectCode 非 0 时用它回复 CONNECT（客户端必须报错）。
type fakeSocks5Upstream struct {
	ln           net.Listener
	mu           sync.Mutex
	methods      []byte
	requests     []fakeSocks5Request
	authRequired bool
	rejectCode   byte
}

func startFakeSocks5Upstream(t *testing.T) *fakeSocks5Upstream {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSocks5Upstream{ln: ln}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go f.handle(conn)
		}
	}()
	return f
}

func (f *fakeSocks5Upstream) addr() (string, int) {
	ta := f.ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", ta.Port
}

func (f *fakeSocks5Upstream) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil || head[0] != socksVer5 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	f.mu.Lock()
	f.methods = append([]byte(nil), methods...)
	f.mu.Unlock()
	if f.authRequired {
		_, _ = conn.Write([]byte{socksVer5, authUserPass})
		return
	}
	if _, err := conn.Write([]byte{socksVer5, authNone}); err != nil {
		return
	}
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil || req[0] != socksVer5 || req[1] != cmdConnect {
		return
	}
	rec := fakeSocks5Request{ATYP: req[3]}
	readAddr := func(n int) []byte {
		buf := make([]byte, n)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil
		}
		return buf
	}
	switch req[3] {
	case atypIPv4:
		buf := readAddr(6)
		if buf == nil {
			return
		}
		rec.Host = net.IPv4(buf[0], buf[1], buf[2], buf[3]).String()
		rec.Port = int(buf[4])<<8 | int(buf[5])
	case atypDomain:
		lb := readAddr(1)
		if lb == nil {
			return
		}
		buf := readAddr(int(lb[0]) + 2)
		if buf == nil {
			return
		}
		rec.Host = string(buf[:len(buf)-2])
		rec.Port = int(buf[len(buf)-2])<<8 | int(buf[len(buf)-1])
	case atypIPv6:
		buf := readAddr(18)
		if buf == nil {
			return
		}
		rec.Host = net.IP(buf[:16]).String()
		rec.Port = int(buf[16])<<8 | int(buf[17])
	default:
		return
	}
	f.mu.Lock()
	f.requests = append(f.requests, rec)
	f.mu.Unlock()
	if f.rejectCode != 0 {
		_, _ = conn.Write([]byte{socksVer5, f.rejectCode, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := conn.Write([]byte{socksVer5, repSuccess, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	target, err := net.DialTimeout("tcp", net.JoinHostPort(rec.Host, strconv.Itoa(rec.Port)), 5*time.Second)
	if err != nil {
		return
	}
	defer target.Close()
	_ = conn.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, target); done <- struct{}{} }()
	<-done
}

func (f *fakeSocks5Upstream) lastRequest() (fakeSocks5Request, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.requests) == 0 {
		return fakeSocks5Request{}, false
	}
	return f.requests[len(f.requests)-1], true
}

func TestDialViaSocks5UpstreamDomainPassthrough(t *testing.T) {
	up := startFakeSocks5Upstream(t)
	host, port := up.addr()
	conn, err := dialViaSocks5Upstream(host, port)("tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	rec, ok := up.lastRequest()
	if !ok {
		t.Fatal("upstream saw no CONNECT")
	}
	// example.test 在本机必然解析失败：能连上说明域名是原样交给
	// 上游的（ATYP 0x03 远程 DNS），没有走本机解析。
	if rec.ATYP != atypDomain || rec.Host != "example.test" || rec.Port != 443 {
		t.Fatalf("domain must reach the upstream verbatim: %+v", rec)
	}
	up.mu.Lock()
	methods := append([]byte(nil), up.methods...)
	up.mu.Unlock()
	if len(methods) != 1 || methods[0] != authNone {
		t.Fatalf("client must offer only no-auth, offered %v", methods)
	}
}

func TestDialViaSocks5UpstreamIPv4AndRelay(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	echoPort := echoLn.Addr().(*net.TCPAddr).Port

	up := startFakeSocks5Upstream(t)
	host, port := up.addr()
	conn, err := dialViaSocks5Upstream(host, port)("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(echoPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	rec, ok := up.lastRequest()
	if !ok || rec.ATYP != atypIPv4 || rec.Host != "127.0.0.1" || rec.Port != echoPort {
		t.Fatalf("ipv4 CONNECT wrong: %+v (seen=%v)", rec, ok)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("relay through upstream broken: %q, %v", buf, err)
	}
}

func TestDialViaSocks5UpstreamFailures(t *testing.T) {
	auth := startFakeSocks5Upstream(t)
	auth.authRequired = true
	host, port := auth.addr()
	if conn, err := dialViaSocks5Upstream(host, port)("tcp", "example.test:443"); err == nil {
		conn.Close()
		t.Fatal("upstream demanding auth must fail: free pool is no-auth only")
	}

	reject := startFakeSocks5Upstream(t)
	reject.rejectCode = 0x05
	host, port = reject.addr()
	if conn, err := dialViaSocks5Upstream(host, port)("tcp", "example.test:443"); err == nil {
		conn.Close()
		t.Fatal("upstream CONNECT rejection must fail the dial")
	}

	plain := startFakeSocks5Upstream(t)
	host, port = plain.addr()
	if conn, err := dialViaSocks5Upstream(host, port)("udp", "1.2.3.4:53"); err == nil {
		conn.Close()
		t.Fatal("non-TCP dial through the upstream must fail")
	}
	if _, ok := plain.lastRequest(); ok {
		t.Fatal("rejected network must not reach the upstream at all")
	}
}

// 拨号选择必须按连接现读 t.Node：监听不重建的前提下，隧道换节点
// （VPN Gate ↔ 免费池）后新连接立刻走新链路。
func TestExitDialerFollowsCurrentNode(t *testing.T) {
	up := startFakeSocks5Upstream(t)
	host, port := up.addr()
	tun := &Tunnel{Slot: 1, Node: Node{HostName: "public-vpn-1.example", Config: "cfg"}}
	if _, err := tun.exitDialer()("tcp", "example.test:443"); err == nil {
		t.Fatal("netns dial unexpectedly succeeded without a namespace")
	}
	if _, ok := up.lastRequest(); ok {
		t.Fatal("VPN Gate node must not dial the free pool upstream")
	}
	tun.mu.Lock()
	tun.Node = Node{HostName: "fp-127.0.0.1-1080", Source: "freepool", SocksHost: host, SocksPort: port}
	tun.mu.Unlock()
	conn, err := tun.exitDialer()("tcp", "example.test:443")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if _, ok := up.lastRequest(); !ok {
		t.Fatal("freepool node did not dial through the upstream")
	}
}

// ---- 免费池走主出口：SwapTo / candidatesFor / tryNode ----

func freePoolSwapFixture(t *testing.T, policyCountry string, node Node) (*Manager, *Tunnel) {
	t.Helper()
	m := NewManager(4, t.TempDir())
	p := SlotPolicy{Country: policyCountry, AllowedIPTypes: append([]string(nil), allIPTypes...)}
	tunnel := &Tunnel{Slot: 1, Port: 17931, Status: "up", Policy: &p, Node: Node{HostName: "old.example", CountryCode: "JP"}}
	tunnel.resetWork()
	m.tunnels[1] = tunnel
	m.nodes = []Node{node}
	return m, tunnel
}

func TestSwapToFreePoolCountryMismatchRejected(t *testing.T) {
	node := Node{HostName: "fp-203.0.113.7-1080", Source: "freepool", CountryCode: "JP", SocksHost: "203.0.113.7", SocksPort: 1080}
	m, tunnel := freePoolSwapFixture(t, "US", node)
	if err := m.SwapTo(1, node.HostName); err == nil {
		t.Fatal("country mismatch must reject the swap, same as a VPN Gate node")
	}
	if got := tunnel.snapshot().Node.HostName; got != "old.example" {
		t.Fatalf("rejected swap changed the node: %s", got)
	}
	tunnel.mu.Lock()
	status := tunnel.Status
	tunnel.mu.Unlock()
	if status != "up" {
		t.Fatal("rejected swap disturbed the running exit")
	}
}

func TestSwapToFreePoolAccepted(t *testing.T) {
	// 后台重连刷新节点时不许碰真实网络。
	stubFetchFuncs(t, []Node{{HostName: "old.example", Config: "cfg"}}, nil, nil, fmt.Errorf("no freepool in test"))
	node := Node{HostName: "fp-127.0.0.1-1", Source: "freepool", CountryCode: "JP", SocksHost: "127.0.0.1", SocksPort: 1}
	m, tunnel := freePoolSwapFixture(t, "JP", node)
	if err := m.SwapTo(1, node.HostName); err != nil {
		t.Fatal(err)
	}
	// reconnectTo 在返回前已同步换好 t.Node：端口/槽位不变，
	// 出口身份从这一刻起就是这个免费池节点。
	view := tunnel.snapshot()
	if view.Node.HostName != node.HostName || view.Slot != 1 || view.Port != 17931 {
		t.Fatalf("slot not replaced with the freepool node: %+v", view.Node)
	}
	tunnel.stop()
	m.mu.Lock()
	delete(m.tunnels, 1)
	m.mu.Unlock()
}

// 已绑定的免费池节点由 candidatesFor 打头重试（不经过
// policyCandidates 的过滤）；自动选点则永远不许挑到免费池。
func TestCandidatesForKeepsFreePoolNodeFirst(t *testing.T) {
	m := NewManager(4, t.TempDir())
	p := SlotPolicy{AllowedIPTypes: append([]string(nil), allIPTypes...)}
	fp := Node{HostName: "fp-203.0.113.7-1080", Source: "freepool", SocksHost: "203.0.113.7", SocksPort: 1080}
	vpn := Node{HostName: "public-vpn-1.example", CountryCode: "JP", Config: "cfg"}
	m.nodes = []Node{fp, vpn}
	tunnel := &Tunnel{Slot: 1, Status: "starting", Policy: &p, Node: fp}
	tunnel.resetWork()
	m.tunnels[1] = tunnel
	got := m.candidatesFor(tunnel)
	if len(got) == 0 || got[0].HostName != fp.HostName {
		t.Fatalf("bound freepool node must be retried first: %+v", got)
	}
	for _, n := range m.policyCandidates(p, map[string]bool{}, 1) {
		if n.Source == "freepool" {
			t.Fatal("policyCandidates must never offer freepool nodes")
		}
	}
}

func freeTestPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}

// tryNode 对免费池节点的完整路径：跳过 netns/OpenVPN，基线与验活
// 都经本地 SOCKS → 上游 → 回显服务，出口证据按原样被接受。
func TestTryNodeFreePoolEndToEnd(t *testing.T) {
	// 探测走 cmdOutput（curl/画像子进程）：无特权环境里 setns 回母机
	// 命名空间会被拒，先例（netnsguard_test）是临时摘掉守卫再恢复；
	// 本测试不起任何真实隧道，当前线程本就在母机命名空间。
	prevNetns := mainNetns
	mainNetns = nil
	defer func() { mainNetns = prevNetns }()
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "198.51.100.77")
	}))
	defer echo.Close()
	oldEcho := exitIPEchoURLs
	exitIPEchoURLs = []string{echo.URL, echo.URL}
	defer func() { exitIPEchoURLs = oldEcho }()
	setPublicIPOverride("192.0.2.254")
	defer setPublicIPOverride("")

	up := startFakeSocks5Upstream(t)
	upHost, upPort := up.addr()
	m := NewManager(4, t.TempDir())
	p := SlotPolicy{AllowedIPTypes: append([]string(nil), allIPTypes...)}
	node := Node{HostName: "fp-e2e", Source: "freepool", SocksHost: upHost, SocksPort: upPort}
	tunnel := &Tunnel{Slot: 1, Port: freeTestPort(t), Status: "starting", Policy: &p, Node: node, Cred: SocksCred{User: "u", Pass: "p"}}
	tunnel.resetWork()
	m.tunnels[1] = tunnel
	defer tunnel.stop()
	if err := m.tryNode(tunnel); err != nil {
		t.Fatalf("freepool tryNode: %v", err)
	}
	if tunnel.ExitIP != "198.51.100.77" {
		t.Fatalf("exit ip = %q, want the echo service's answer", tunnel.ExitIP)
	}
	// tryNode 返回 nil 就意味着 acceptExitEvidence 已接受证据；
	// egressSnapshot 要等 publishUp 把状态置 up 后才对外可见，
	// 这里直接看内部记录。
	tunnel.mu.Lock()
	evidenceOK := tunnel.egress != nil && tunnel.egressExpectedIP == "198.51.100.77" && tunnel.egressActualIP == "198.51.100.77"
	tunnel.mu.Unlock()
	if !evidenceOK {
		t.Fatal("exit evidence not accepted for the freepool tunnel")
	}
	if _, ok := up.lastRequest(); !ok {
		t.Fatal("baseline/verify probes never reached the upstream")
	}
}

// 免费池隧道状态落盘要带上 Source/Socks 上游：节点掉出候选列表后
// 恢复出来的 Node 必须仍是免费池节点，否则会按 OpenVPN 路径重建。
func TestPersistedFreePoolTunnelRoundTrip(t *testing.T) {
	node := Node{HostName: "fp-203.0.113.7-1080", Source: "freepool", CountryCode: "JP", SocksHost: "203.0.113.7", SocksPort: 1080}
	st := &persistedState{Tunnels: []persistedTunnel{{
		Slot: 1, Port: 17933, HostName: node.HostName, CountryCode: "JP",
		Source: node.Source, SocksHost: node.SocksHost, SocksPort: node.SocksPort,
		SocksUser: "user", SocksPass: "pass",
	}}}
	blob, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePersistedState(blob, 4, false)
	if err != nil {
		t.Fatal(err)
	}
	// 当前池里已经没有这个节点：靠存盘字段重建。
	tunnels, err := prepareRestoredTunnels(decoded, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tunnels) != 1 {
		t.Fatalf("restored %d tunnels", len(tunnels))
	}
	got := tunnels[0].Node
	if got.Source != "freepool" || got.SocksHost != "203.0.113.7" || got.SocksPort != 1080 {
		t.Fatalf("restored node lost its freepool upstream: %+v", got)
	}
}
