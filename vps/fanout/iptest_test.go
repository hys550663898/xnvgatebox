package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func resetIPTestState(t *testing.T, url string) {
	t.Helper()
	old := iptestEndpoint
	iptestEndpoint = url
	iptestState.Lock()
	iptestState.cache = map[string]iptestCacheEntry{}
	iptestState.nextStart = time.Time{}
	iptestState.Unlock()
	t.Cleanup(func() {
		iptestEndpoint = old
		iptestState.Lock()
		iptestState.cache = map[string]iptestCacheEntry{}
		iptestState.nextStart = time.Time{}
		iptestState.Unlock()
	})
}

func TestLookupIPTestParsesReport(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		var body struct {
			CheckYourIP string `json:"checkyourip"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.CheckYourIP != "73.162.12.34" {
			t.Errorf("unexpected lookup ip %q", body.CheckYourIP)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true,"ip":"73.162.12.34","type":{"kind":"家庭宽带","origin":"原生 IP"},"risk":{"score":16,"source":"scamalytics.com","vpn":false,"proxy":false,"tor":false,"relay":false},"composite":5}`)
	}))
	defer srv.Close()
	resetIPTestState(t, srv.URL)

	info := lookupIPTest(context.Background(), "73.162.12.34")
	if info == nil {
		t.Fatal("expected iptest info")
	}
	if info.Kind != "家庭宽带" || info.Usage != "优质网络" {
		t.Fatalf("unexpected type %+v", info)
	}
	if info.Composite == nil || *info.Composite != 5 {
		t.Fatalf("unexpected composite %+v", info.Composite)
	}
	if info.RiskScore == nil || *info.RiskScore != 16 || info.Source != "scamalytics.com" {
		t.Fatalf("unexpected risk %+v", info)
	}
	// Second lookup of the same IP must be served from cache.
	if again := lookupIPTest(context.Background(), "73.162.12.34"); again == nil || hits.Load() != 1 {
		t.Fatalf("expected cache hit, server hits=%d again=%v", hits.Load(), again)
	}
}

func TestIPTestUsageClassification(t *testing.T) {
	cases := []struct {
		vpn, proxy, tor, relay bool
		want                   string
	}{
		{false, false, false, false, "优质网络"},
		{true, false, false, false, "VPN"},
		{false, true, false, false, "代理"},
		{false, false, true, false, "Tor"},
		{false, false, false, true, "中继"},
		{true, true, false, false, "代理"},
		{true, true, true, true, "Tor"},
	}
	for _, c := range cases {
		if got := iptestUsage(c.vpn, c.proxy, c.tor, c.relay); got != c.want {
			t.Errorf("iptestUsage(%v,%v,%v,%v) = %q, want %q", c.vpn, c.proxy, c.tor, c.relay, got, c.want)
		}
	}
}

func TestLookupIPTestFailuresAreNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "45")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	resetIPTestState(t, srv.URL)

	if info := lookupIPTest(context.Background(), "8.8.8.8"); info != nil {
		t.Fatalf("429 must yield nil, got %+v", info)
	}
	// The 429 must push the pacing gate out so later lookups wait.
	iptestState.Lock()
	gate := iptestState.nextStart
	iptestState.Unlock()
	if time.Until(gate) < 30*time.Second {
		t.Fatalf("expected pacing gate pushed by Retry-After, gate in %v", time.Until(gate))
	}
	if info := lookupIPTest(context.Background(), "2001:db8::1"); info != nil {
		t.Fatalf("IPv6 must be skipped, got %+v", info)
	}
	if info := lookupIPTest(context.Background(), "not-an-ip"); info != nil {
		t.Fatalf("invalid IP must be skipped, got %+v", info)
	}
}
