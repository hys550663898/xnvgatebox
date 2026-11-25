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
// 这类节点没有 OpenVPN 配置（Config 恒为空），不能直接建隧道；
// 检测通过后经 /api/freepool/promote 生成一条独立的第三方形态出口。

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

func (c *Console) realityServerName() string {
	c.targetMu.Lock()
	defer c.targetMu.Unlock()
	if c.plan != nil && c.plan.ServerName != "" {
		return c.plan.ServerName
	}
	return "www.tesla.com"
}

// findFreePoolThirdParty 按上游地址找已 promote 的免费池出口，做幂等判断。
func (n *Native) findFreePoolThirdParty(host string, port int) (int, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ib := range n.store.Inbounds {
		if thirdPartyBound(ib) && ib.ThirdParty.Source == freePoolSource && ib.ThirdParty.Host == host && ib.ThirdParty.Port == port {
			return ib.ID, true
		}
	}
	return 0, false
}

// apiFreePoolPromote 把检测通过的免费池候选生成为一条独立出口
// （第三方形态入站，Source="freepool"，无凭据，默认加入订阅）。
// 重复调用同一 host 幂等：返回已存在的出口编号，不重复创建。
func (c *Console) apiFreePoolPromote(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var req struct {
		Host string `json:"host"`
	}
	if err := readConsoleJSON(w, r, &req); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	host := strings.TrimSpace(req.Host)
	nodes, _ := c.m.Nodes()
	var node *Node
	for i := range nodes {
		if nodes[i].HostName == host {
			node = &nodes[i]
			break
		}
	}
	if node == nil || node.Source != freePoolSource {
		writeJSON(w, 404, map[string]string{"error": "候选不存在或不是免费池节点，请刷新候选列表"})
		return
	}
	c.checksMu.Lock()
	result, ok := c.results[host]
	c.checksMu.Unlock()
	if !ok || result.Status != "passed" {
		writeJSON(w, 409, map[string]string{"error": "该节点尚未检测通过，不能设为出口"})
		return
	}
	// 与候选列表的过期口径一致：配置摘要变化或超过 15 分钟视为过期。
	if result.ProfileSHA != profileDigest(node.Config) || time.Since(result.CheckedAt) > 15*time.Minute {
		writeJSON(w, 409, map[string]string{"error": "检测结果已过期，请重新检测后再设为出口"})
		return
	}
	n := thirdPartyNative(w)
	if n == nil {
		return
	}
	if id, exists := n.findFreePoolThirdParty(node.SocksHost, node.SocksPort); exists {
		writeJSON(w, 200, map[string]any{"id": id, "ok": true, "existing": true})
		return
	}
	label := result.Country
	if label == "" {
		label = host
	}
	p := ThirdPartyProxy{
		Host:      node.SocksHost,
		Port:      node.SocksPort,
		Country:   result.Country,
		Remark:    "免费池 · " + label,
		Subscribe: true,
		Source:    freePoolSource,
	}
	id, err := n.saveThirdParty(0, p, true, c.realityServerName(), c.m.Tunnels())
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	invalidateInbounds()
	writeJSON(w, 200, map[string]any{"id": id, "ok": true})
}
