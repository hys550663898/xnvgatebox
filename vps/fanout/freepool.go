package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// 免费代理池：从免 key、免登录的公开列表抓取免费 SOCKS5，
// 作为与 VPN Gate 并列的候选来源并入候选池，一起跑候选检测。
// 这类节点没有 OpenVPN 配置（Config 恒为空），但和 VPN Gate
// 候选走同一条主出口路径：候选页「设为出口」弹窗选一个已有
// Slot 替换进来，隧道的本地 SOCKS 出站改为经远程 SOCKS5 上游
// 拨号（见 dialViaSocks5Upstream 与 Tunnel.exitDialer），端口、
// 凭据与订阅保持不变；节点失效后按该 Slot 原策略自动换点。

const freePoolSource = "freepool"

// freePoolMaxNodes 是单次抓取并入候选池的总量上限，防止公开列表
// 膨胀把候选页和批量检测拖垮。
const freePoolMaxNodes = 400

// 两个来源地址做成包级变量，测试用 httptest 注入。
var (
	freePoolProxyScrapeURL = "https://api.proxyscrape.com/v4/free-proxy-list/get?request=display_proxies&proxy_format=protocolipport&format=text&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all"
	freePoolGeonodeURL     = "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc&protocols=socks5"
)

// freePoolEnabled 读池配置（FANOUT_POOL_CONFIG，默认
// /etc/xnvgatebox/pool.json）的 freepool_enabled 字段。
// 缺省 true；文件读不到、字段缺失或类型不对都按 true 处理，不报错。
func freePoolEnabled() bool {
	blob, err := os.ReadFile(envOr("FANOUT_POOL_CONFIG", "/etc/xnvgatebox/pool.json"))
	if err != nil {
		return true
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(blob, &fields) != nil {
		return true
	}
	if raw, ok := fields["freepool_enabled"]; ok {
		var v bool
		if json.Unmarshal(raw, &v) == nil {
			return v
		}
	}
	return true
}

type freePoolEntry struct {
	IP          string
	Port        int
	CountryCode string
	ASN         string
	ISP         string
	UpTime      float64
}

func (e freePoolEntry) key() string { return e.IP + ":" + strconv.Itoa(e.Port) }

func (e freePoolEntry) node() Node {
	cc := strings.ToUpper(strings.TrimSpace(e.CountryCode))
	country := cc
	if name := countryCN[cc]; name != "" {
		country = name
	}
	return Node{
		Source:      freePoolSource,
		HostName:    fmt.Sprintf("fp-%s-%d", e.IP, e.Port),
		IP:          e.IP,
		Country:     country,
		CountryCode: cc,
		ASN:         e.ASN,
		ISP:         e.ISP,
		SocksHost:   e.IP,
		SocksPort:   e.Port,
		Residential: false,
	}
}

func validFreePoolEndpoint(ip string, port int) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil && port >= 1 && port <= 65535
}

// fetchFreePoolNodes 并发抓两个公开来源，合并去重后转成候选 Node。
// 单个来源失败不致命；两个都失败（或都为空）才返回 error。
// 总超时受 ctx 与内部 30 秒上限共同约束。
func fetchFreePoolNodes(ctx context.Context) ([]Node, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	client := &http.Client{Timeout: 15 * time.Second}
	var wg sync.WaitGroup
	var geonode, proxyscrape []freePoolEntry
	var geonodeErr, proxyscrapeErr error
	wg.Add(2)
	go func() {
		defer wg.Done()
		geonode, geonodeErr = fetchGeonodeEntries(ctx, client)
	}()
	go func() {
		defer wg.Done()
		proxyscrape, proxyscrapeErr = fetchProxyScrapeEntries(ctx, client)
	}()
	wg.Wait()
	nodes := mergeFreePoolEntries(geonode, proxyscrape)
	if len(nodes) == 0 {
		if geonodeErr != nil && proxyscrapeErr != nil {
			return nil, fmt.Errorf("免费代理池两个来源都抓取失败: geonode: %v; proxyscrape: %v", geonodeErr, proxyscrapeErr)
		}
		if geonodeErr != nil {
			return nil, fmt.Errorf("免费代理池抓取失败: %w", geonodeErr)
		}
		if proxyscrapeErr != nil {
			return nil, fmt.Errorf("免费代理池抓取失败: %w", proxyscrapeErr)
		}
		return nil, fmt.Errorf("免费代理池两个来源都没有返回可用条目")
	}
	return nodes, nil
}

func fetchFreePoolBody(ctx context.Context, client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8<<20))
}

func fetchProxyScrapeEntries(ctx context.Context, client *http.Client) ([]freePoolEntry, error) {
	raw, err := fetchFreePoolBody(ctx, client, freePoolProxyScrapeURL)
	if err != nil {
		return nil, err
	}
	return parseProxyScrapeList(string(raw)), nil
}

// parseProxyScrapeList 解析 ProxyScrape 的纯文本列表，
// 每行形如 socks5://1.2.3.4:1080；坏行直接跳过。
func parseProxyScrapeList(body string) []freePoolEntry {
	var out []freePoolEntry
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		line = strings.TrimPrefix(line, "socks5://")
		host, portText, err := net.SplitHostPort(line)
		if err != nil {
			continue
		}
		port, err := strconv.Atoi(portText)
		if err != nil || !validFreePoolEndpoint(host, port) {
			continue
		}
		out = append(out, freePoolEntry{IP: host, Port: port})
	}
	return out
}

// geonodePort 兼容 Geonode 把 port 返回成字符串或数字两种形态。
type geonodePort int

func (p *geonodePort) UnmarshalJSON(raw []byte) error {
	text := strings.Trim(strings.TrimSpace(string(raw)), `"`)
	n, err := strconv.Atoi(text)
	if err != nil {
		return err
	}
	*p = geonodePort(n)
	return nil
}

type geonodeResponse struct {
	Data []struct {
		IP      string      `json:"ip"`
		Port    geonodePort `json:"port"`
		Country string      `json:"country"`
		ASN     string      `json:"asn"`
		ISP     string      `json:"isp"`
		UpTime  float64     `json:"upTime"`
	} `json:"data"`
}

func fetchGeonodeEntries(ctx context.Context, client *http.Client) ([]freePoolEntry, error) {
	raw, err := fetchFreePoolBody(ctx, client, freePoolGeonodeURL)
	if err != nil {
		return nil, err
	}
	return parseGeonodeList(raw)
}

func parseGeonodeList(raw []byte) ([]freePoolEntry, error) {
	var resp geonodeResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("解析 Geonode 列表失败: %w", err)
	}
	out := make([]freePoolEntry, 0, len(resp.Data))
	for _, item := range resp.Data {
		ip := strings.TrimSpace(item.IP)
		port := int(item.Port)
		if !validFreePoolEndpoint(ip, port) {
			continue
		}
		out = append(out, freePoolEntry{
			IP:          ip,
			Port:        port,
			CountryCode: strings.ToUpper(strings.TrimSpace(item.Country)),
			ASN:         strings.TrimSpace(item.ASN),
			ISP:         strings.TrimSpace(item.ISP),
			UpTime:      item.UpTime,
		})
	}
	return out, nil
}

// mergeFreePoolEntries 合并两个来源：Geonode 条目带国家/ASN/在线率
// 元数据，先按 upTime 降序入池；ProxyScrape 只补 Geonode 没有的
// ip:port。总量上限 freePoolMaxNodes。
func mergeFreePoolEntries(geonode, proxyscrape []freePoolEntry) []Node {
	sorted := append([]freePoolEntry(nil), geonode...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].UpTime > sorted[j].UpTime })
	nodes := []Node{}
	seen := map[string]bool{}
	add := func(e freePoolEntry) {
		if len(nodes) >= freePoolMaxNodes || seen[e.key()] {
			return
		}
		seen[e.key()] = true
		nodes = append(nodes, e.node())
	}
	for _, e := range sorted {
		add(e)
	}
	for _, e := range proxyscrape {
		add(e)
	}
	return nodes
}

const socks5UpstreamTimeout = 15 * time.Second

// dialViaSocks5Upstream 返回一个经远程无认证 SOCKS5 上游建立 TCP
// 连接的拨号函数，供免费池隧道的本地 SOCKS 出站使用。
//
// 只报无认证一种方法：公开列表里的免费代理没有凭据，上游若要求
// 认证就直接失败，不尝试空口令。目标域名原样交给上游解析
// （ATYP 0x03），本机不做 DNS 解析——既走远程 DNS，也避免本机
// 解析失败或地址泄漏让连接绕开上游。
func dialViaSocks5Upstream(host string, port int) func(network, addr string) (net.Conn, error) {
	return func(network, addr string) (net.Conn, error) {
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, fmt.Errorf("免费池上游只支持 TCP 连接（%s）", network)
		}
		targetHost, targetPortText, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("目标地址无效: %w", err)
		}
		targetPort, err := strconv.Atoi(targetPortText)
		if err != nil || targetPort < 1 || targetPort > 65535 {
			return nil, fmt.Errorf("目标地址端口无效: %s", addr)
		}
		dialer := net.Dialer{Timeout: socks5UpstreamTimeout}
		conn, err := dialer.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return nil, err
		}
		if err := socks5UpstreamHandshake(conn, targetHost, targetPort); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// socks5UpstreamHandshake 在已连上的上游连接上跑 SOCKS5 方法协商
// 与 CONNECT；成功返回时连接已可直接转发，握手期截止时间随之清除。
func socks5UpstreamHandshake(conn net.Conn, host string, port int) error {
	_ = conn.SetDeadline(time.Now().Add(socks5UpstreamTimeout))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()
	if _, err := conn.Write([]byte{socksVer5, 1, authNone}); err != nil {
		return fmt.Errorf("向上游发送 SOCKS5 握手失败: %w", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		return fmt.Errorf("读取上游 SOCKS5 握手回复失败: %w", err)
	}
	if method[0] != socksVer5 {
		return fmt.Errorf("上游 SOCKS5 版本异常: 0x%02x", method[0])
	}
	if method[1] != authNone {
		return fmt.Errorf("上游 SOCKS5 要求认证（方法 0x%02x），免费池只支持无认证上游", method[1])
	}
	req := []byte{socksVer5, cmdConnect, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, atypIPv4)
			req = append(req, v4...)
		} else {
			req = append(req, atypIPv6)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return fmt.Errorf("目标域名长度无效: %q", host)
		}
		req = append(req, atypDomain, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("向上游发送 CONNECT 失败: %w", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("读取上游 CONNECT 回复失败: %w", err)
	}
	if head[0] != socksVer5 {
		return fmt.Errorf("上游 CONNECT 回复版本异常: 0x%02x", head[0])
	}
	if head[1] != repSuccess {
		return fmt.Errorf("上游 SOCKS5 拒绝连接（回复码 0x%02x）", head[1])
	}
	var boundLen int
	switch head[3] {
	case atypIPv4:
		boundLen = 4
	case atypIPv6:
		boundLen = 16
	case atypDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return fmt.Errorf("读取上游绑定地址失败: %w", err)
		}
		boundLen = int(lenByte[0])
	default:
		return fmt.Errorf("上游 CONNECT 回复地址类型异常: 0x%02x", head[3])
	}
	if _, err := io.ReadFull(conn, make([]byte, boundLen+2)); err != nil {
		return fmt.Errorf("读取上游绑定地址失败: %w", err)
	}
	return nil
}

// probeFreePoolCandidate 检测一个免费池候选：它本质上是一个无凭据
// SOCKS5，直接复用第三方 SOCKS5 的探测管线（双 HTTPS 回显一致 +
// 内容校验 + 出口画像 + iptest），结果映射回候选的 CheckResult。
func (c *Console) probeFreePoolCandidate(ctx context.Context, node Node, progress func(string)) CheckResult {
	progress("verify_proxy")
	p := ThirdPartyProxy{Host: node.SocksHost, Port: node.SocksPort, Source: freePoolSource}
	rec := probeThirdParty(ctx, p, c.m.workDir)
	if ctx.Err() != nil {
		return CheckResult{Protocol: "socks5", Host: node.HostName, Status: "cancelled", Code: "cancelled", IPType: "unknown", ProfileSHA: profileDigest(node.Config)}
	}
	return freePoolCheckResult(node, rec)
}

// freePoolCheckResult 把第三方探测记录映射成候选检测结果（纯函数）。
func freePoolCheckResult(node Node, rec ThirdPartyRecord) CheckResult {
	result := CheckResult{
		Protocol:   "socks5",
		Host:       node.HostName,
		Status:     rec.Status,
		Code:       rec.Code,
		ActualIP:   rec.ActualIP,
		Country:    rec.Country,
		IPType:     rec.IPType,
		IPTest:     rec.IPTest,
		LatencyMS:  rec.LatencyMS,
		ProfileSHA: profileDigest(node.Config),
	}
	if result.Status == "" {
		result.Status = "failed"
	}
	if result.IPType == "" {
		result.IPType = "unknown"
	}
	return result
}
