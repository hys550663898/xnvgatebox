package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IPTestInfo is the subset of the iptest.us report shown next to a
// candidate: the network type and the composite score. The composite
// score is a risk-style score from 0 to 100 where lower is cleaner.
type IPTestInfo struct {
	Kind      string `json:"kind,omitempty"`
	Origin    string `json:"origin,omitempty"`
	Composite *int   `json:"composite,omitempty"`
	RiskScore *int   `json:"risk_score,omitempty"`
	Source    string `json:"source,omitempty"`
}

var iptestEndpoint = "https://iptest.us/api/lookup"

type iptestCacheEntry struct {
	info    *IPTestInfo
	expires time.Time
}

// iptestState paces outbound lookups below the published iptest.us
// rate limit (50 requests/minute per caller IP) and caches results so
// re-checking a candidate with a known exit IP costs no request.
var iptestState = struct {
	sync.Mutex
	cache     map[string]iptestCacheEntry
	nextStart time.Time
}{cache: map[string]iptestCacheEntry{}}

var iptestClient = &http.Client{Timeout: 15 * time.Second}

// lookupIPTest queries iptest.us for one exit IP. It is best-effort
// enrichment of a check result: any failure (rate limit, timeout,
// non-IPv4 address, malformed response) returns nil and never fails
// or changes the caller's own check outcome.
func lookupIPTest(ctx context.Context, ip string) *IPTestInfo {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return nil
	}
	iptestState.Lock()
	if ent, ok := iptestState.cache[ip]; ok && time.Now().Before(ent.expires) {
		info := ent.info
		iptestState.Unlock()
		return info
	}
	wait := time.Until(iptestState.nextStart)
	if wait < 0 {
		wait = 0
	}
	iptestState.nextStart = time.Now().Add(wait + 1300*time.Millisecond)
	iptestState.Unlock()
	if wait > 0 {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	body, _ := json.Marshal(map[string]string{"checkyourip": ip})
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, iptestEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "xnvgatebox/iptest-lookup")
	resp, err := iptestClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		iptestState.Lock()
		retry := 30 * time.Second
		if h := strings.TrimSpace(resp.Header.Get("Retry-After")); h != "" {
			if secs, err := strconv.Atoi(h); err == nil && secs > 0 && secs < 600 {
				retry = time.Duration(secs) * time.Second
			}
		}
		if until := time.Now().Add(retry); until.After(iptestState.nextStart) {
			iptestState.nextStart = until
		}
		iptestState.Unlock()
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var payload struct {
		OK   bool `json:"ok"`
		Type struct {
			Kind   string `json:"kind"`
			Origin string `json:"origin"`
		} `json:"type"`
		Risk struct {
			Score  *int   `json:"score"`
			Source string `json:"source"`
		} `json:"risk"`
		Composite *int `json:"composite"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil || !payload.OK {
		return nil
	}
	info := &IPTestInfo{
		Kind:      payload.Type.Kind,
		Origin:    payload.Type.Origin,
		Composite: payload.Composite,
		RiskScore: payload.Risk.Score,
		Source:    payload.Risk.Source,
	}
	if info.Kind == "" && info.Composite == nil {
		return nil
	}
	iptestState.Lock()
	iptestState.cache[ip] = iptestCacheEntry{info: info, expires: time.Now().Add(6 * time.Hour)}
	iptestState.Unlock()
	return info
}
