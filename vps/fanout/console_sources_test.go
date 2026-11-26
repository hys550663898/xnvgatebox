package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConsoleSourceSettingsPreserveDisabledIntentAndPrivateFields(t *testing.T) {
	c := consoleFixture(t)
	path := filepath.Join(t.TempDir(), "pool.json")
	before := `{"source_urls":["https://private.example/?key=SYNTHETIC_PRIVATE"],"countries":["JP"],"sstp_concurrency":17,"mirror_fallback":{"enabled":false,"max_age_hours":24,"private_note":"SYNTHETIC_PRIVATE"}}`
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FANOUT_POOL_CONFIG", path)
	w := httptest.NewRecorder()
	c.apiSourceSettings(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 || strings.Contains(w.Body.String(), "SYNTHETIC_PRIVATE") || !strings.Contains(w.Body.String(), `"mirror_enabled":false`) {
		t.Fatal("default changed or private settings exposed")
	}
	w = httptest.NewRecorder()
	c.apiSourceSettings(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"mirror_enabled":true,"source_timeout_seconds":8,"mirror_max_age_hours":24}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	blob, _ := os.ReadFile(path)
	var fields map[string]json.RawMessage
	if json.Unmarshal(blob, &fields) != nil {
		t.Fatal("invalid persisted JSON")
	}
	if !strings.Contains(string(fields["source_urls"]), "SYNTHETIC_PRIVATE") || !strings.Contains(string(fields["mirror_fallback"]), "private_note") || string(fields["sstp_concurrency"]) != "17" || !strings.Contains(string(fields["countries"]), "JP") {
		t.Fatal("unrelated private configuration changed")
	}
	settings, _, err := readSourceOptions(path)
	if err != nil || !settings.MirrorEnabled || settings.SourceTimeout != 8 || settings.MirrorMaxAgeHours != 24 {
		t.Fatal("source preferences not persisted")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("configuration became public")
	}
	for _, body := range []string{`{}`, `{"mirror_enabled":null}`, `{"mirror_enabled":true,"source_timeout_seconds":100,"mirror_max_age_hours":24}`, `{"mirror_enabled":false,"source_timeout_seconds":8,"mirror_max_age_hours":0}`} {
		w = httptest.NewRecorder()
		c.apiSourceSettings(w, httptest.NewRequest("POST", "/", strings.NewReader(body)))
		after, _ := os.ReadFile(path)
		if w.Code != 400 || string(after) != string(blob) {
			t.Fatal("invalid settings replaced configuration")
		}
	}
}

func TestConsoleSourceSettingsFreePoolToggle(t *testing.T) {
	c := consoleFixture(t)
	path := filepath.Join(t.TempDir(), "pool.json")
	before := `{"source_urls":["https://www.vpngate.net/api/iphone/"],"countries":[]}`
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FANOUT_POOL_CONFIG", path)
	// 缺省开启：GET 带 freepool_enabled:true，且 freePoolEnabled() 口径一致。
	w := httptest.NewRecorder()
	c.apiSourceSettings(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"freepool_enabled":true`) {
		t.Fatal("freepool default not enabled", w.Body.String())
	}
	if !freePoolEnabled() {
		t.Fatal("freePoolEnabled disagrees with settings default")
	}
	// POST 关闭：落盘、GET 与 freePoolEnabled() 都变 false。
	w = httptest.NewRecorder()
	c.apiSourceSettings(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"mirror_enabled":true,"source_timeout_seconds":10,"mirror_max_age_hours":24,"freepool_enabled":false}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	s, _, err := readSourceOptions(path)
	if err != nil || s.FreePoolEnabled {
		t.Fatal("freepool opt-out not persisted")
	}
	if freePoolEnabled() {
		t.Fatal("freePoolEnabled still true after opt-out")
	}
	// POST 不带 freepool 字段（旧客户端）：保持已保存的关闭状态。
	w = httptest.NewRecorder()
	c.apiSourceSettings(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"mirror_enabled":false,"source_timeout_seconds":9,"mirror_max_age_hours":24}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	s, _, err = readSourceOptions(path)
	if err != nil || s.FreePoolEnabled {
		t.Fatal("omitted freepool field reset the switch")
	}
	// POST 重新打开。
	w = httptest.NewRecorder()
	c.apiSourceSettings(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"mirror_enabled":true,"source_timeout_seconds":10,"mirror_max_age_hours":24,"freepool_enabled":true}`)))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if s, _, err = readSourceOptions(path); err != nil || !s.FreePoolEnabled || !freePoolEnabled() {
		t.Fatal("freepool re-enable not persisted")
	}
}

func TestConsoleSourceSettingsDefaultEnabledWithoutOverwritingConfig(t *testing.T) {
	c := consoleFixture(t)
	path := filepath.Join(t.TempDir(), "pool.json")
	before := `{"source_urls":["https://www.vpngate.net/api/iphone/"],"countries":[]}`
	if err := os.WriteFile(path, []byte(before), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FANOUT_POOL_CONFIG", path)
	w := httptest.NewRecorder()
	c.apiSourceSettings(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"mirror_enabled":true`) {
		t.Fatal("legacy defaults differ from fresh installation")
	}
	after, _ := os.ReadFile(path)
	if string(after) != before {
		t.Fatal("read changed configuration")
	}
	w = httptest.NewRecorder()
	c.apiSourceSettings(w, httptest.NewRequest("POST", "/", strings.NewReader(`{"mirror_enabled":false,"source_timeout_seconds":10,"mirror_max_age_hours":24}`)))
	s, _, err := readSourceOptions(path)
	if w.Code != 200 || err != nil || s.MirrorEnabled {
		t.Fatal("explicit opt-out not preserved")
	}
}

func TestPoolSourceViewSeparatesSnapshotAndLocalRetrieval(t *testing.T) {
	now := time.Now().UTC()
	s := poolSourceMetadata{Kind: "mirror", Retrieval: "local_builder", RetrievedAt: now.Format(time.RFC3339), MirrorProvider: poolMirrorProvider,
		SnapshotFetchedAt: now.Add(-4 * time.Hour).Format(time.RFC3339), DataCommit: strings.Repeat("a", 40), IntegrityVerified: true}
	v := publicPoolSource(s)
	if v.Kind != "mirror" || !v.Stale || !v.IntegrityVerified || v.SnapshotFetchedAt == v.RetrievedAt || !strings.Contains(v.Label, "本 VPS") {
		t.Fatal("mirror age or local execution is ambiguous")
	}
	s.MirrorProvider = "SYNTHETIC_PRIVATE"
	blob, _ := json.Marshal(publicPoolSource(s))
	if strings.Contains(string(blob), "SYNTHETIC_PRIVATE") || strings.Contains(string(blob), `"integrity_verified":true`) {
		t.Fatal("unrecognized publisher trusted or exposed")
	}
	s.MirrorProvider = poolMirrorProvider
	s.DataCommit = "bad-commit"
	if publicPoolSource(s).IntegrityVerified {
		t.Fatal("invalid metadata marked checked")
	}
	s.Retrieval = "external_worker"
	if publicPoolSource(s).Kind != "legacy" {
		t.Fatal("external observations represented as local retrieval")
	}
}
