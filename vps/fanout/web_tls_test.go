package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func writeTestCert(t *testing.T, dir string, notBefore, notAfter time.Time) (certFile, keyFile string) {
	return writeTestCertSerial(t, dir, 1, notBefore, notAfter)
}

func writeTestCertSerial(t *testing.T, dir string, serial int64, notBefore, notAfter time.Time) (certFile, keyFile string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "panel.example.com"},
		DNSNames:     []string{"panel.example.com"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certFile = filepath.Join(dir, "fullchain.pem")
	keyFile = filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestLoadManagementCert(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	certFile, keyFile := writeTestCert(t, dir, now.Add(-time.Hour), now.Add(24*time.Hour))
	if _, err := loadManagementCert(certFile, keyFile); err != nil {
		t.Fatal("valid pair rejected", err)
	}
	if _, err := loadManagementCert("", keyFile); err == nil {
		t.Fatal("missing cert path must fail")
	}
	if _, err := loadManagementCert(certFile, filepath.Join(dir, "nope.pem")); err == nil {
		t.Fatal("missing key file must fail")
	}
	expiredCert, expiredKey := writeTestCert(t, dir+"-expired", now.Add(-48*time.Hour), now.Add(-time.Hour))
	_ = expiredKey
	if _, err := loadManagementCert(expiredCert, keyFile); err == nil {
		t.Fatal("mismatched or expired pair must fail")
	}
	if _, err := loadManagementCert(expiredCert, expiredKey); err == nil {
		t.Fatal("expired cert must fail")
	}
}

func TestValidateDomainName(t *testing.T) {
	for _, ok := range []string{"", "panel.example.com", "a.b", "my-host1.example.org"} {
		if err := validateDomainName(ok); err != nil {
			t.Fatal("valid domain rejected", ok, err)
		}
	}
	for _, bad := range []string{"https://panel.example.com", "panel.example.com:8899", "panel example.com", "-bad.com", "bad..com", ".example.com"} {
		if err := validateDomainName(bad); err == nil {
			t.Fatal("invalid domain accepted", bad)
		}
	}
}

func TestWebSettingsHTTPSRoundtrip(t *testing.T) {
	s, err := decodeWebSettings([]byte(`{"port":8899,"https":true,"domain":" panel.example.com ","cert_file":"/root/cert/panel.example.com/fullchain.pem","key_file":"/root/cert/panel.example.com/privkey.pem"}`), 8899)
	if err != nil {
		t.Fatal(err)
	}
	if !s.HTTPS || s.Domain != "panel.example.com" || s.CertFile == "" || s.KeyFile == "" {
		t.Fatal("https fields not decoded/trimmed", s)
	}
	if _, err := decodeWebSettings([]byte(`{"port":8899,"domain":"https://x.com"}`), 8899); err == nil {
		t.Fatal("bad domain must fail decode")
	}
	// HTTPS with a bogus cert path must still decode: startup must not
	// brick on a cert problem; the listener falls back instead.
	if _, err := decodeWebSettings([]byte(`{"port":8899,"https":true,"cert_file":"/nonexistent.pem","key_file":"/nonexistent-key.pem"}`), 8899); err != nil {
		t.Fatal("decode must tolerate unavailable cert files", err)
	}
	if err := validateTLSSettings(WebSettings{HTTPS: true, CertFile: "/nonexistent.pem", KeyFile: "/nonexistent-key.pem"}); err == nil {
		t.Fatal("save-time validation must reject unavailable cert")
	}
}

func TestWebServerServesTLS(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	certFile, keyFile := writeTestCert(t, dir, now.Add(-time.Hour), now.Add(24*time.Hour))
	if _, err := loadWebSettings(dir, 0, false); err != nil {
		t.Fatal(err)
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	srv := newWebServer(h)
	port := freePort(t)
	cfg := WebSettings{Port: port, ListenAddr: "127.0.0.1", HTTPS: true, Domain: "panel.example.com", CertFile: certFile, KeyFile: keyFile}
	if err := srv.reload(cfg); err != nil {
		t.Fatal("tls reload", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	url := "https://127.0.0.1:" + strconv.Itoa(port) + "/"
	deadline := time.Now().Add(3 * time.Second)
	for {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.TLS == nil {
				t.Fatal("response was not TLS")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("TLS listener did not come up", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Plain HTTP against the TLS port must not serve the page.
	if c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second); err == nil {
		c.Close()
	}
	plain := &http.Client{Timeout: time.Second}
	if resp, err := plain.Get("http://127.0.0.1:" + strconv.Itoa(port) + "/"); err == nil {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		// Go's TLS handshake answers plain HTTP with a bare 400 text;
		// what must never happen is serving the actual page over HTTP.
		if resp.StatusCode == 200 || string(body) == "ok" {
			t.Fatal("plain HTTP unexpectedly served the page on TLS port")
		}
	}
	// A bad cert path must fail prepare without touching the live listener.
	bad := cfg
	bad.CertFile = filepath.Join(dir, "missing.pem")
	if err := srv.reload(bad); err == nil {
		t.Fatal("reload with missing cert must fail")
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal("live TLS listener broken by failed reload", err)
	}
	resp.Body.Close()
}

// Regression for the production report: enabling HTTPS while keeping
// the SAME management port failed with "bind: address already in use"
// because the new listener was pre-bound while the old one (same port)
// was still serving. The toggle must swap in place.
func TestWebServerToggleHTTPSOnSamePort(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadWebSettings(dir, 0, false); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certFile, keyFile := writeTestCert(t, dir, now.Add(-time.Hour), now.Add(24*time.Hour))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	srv := newWebServer(h)
	port := freePort(t)
	base := WebSettings{Port: port, ListenAddr: "127.0.0.1"}
	if err := srv.reload(base); err != nil {
		t.Fatal(err)
	}
	waitServe(t, port)

	withTLS := base
	withTLS.HTTPS = true
	withTLS.Domain = "panel.example.com"
	withTLS.CertFile = certFile
	withTLS.KeyFile = keyFile
	if err := srv.applyWebSettings(withTLS); err != nil {
		t.Fatal("same-port HTTPS toggle must not fail with address in use", err)
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, Timeout: time.Second}
	url := "https://127.0.0.1:" + strconv.Itoa(port) + "/"
	deadline := time.Now().Add(6 * time.Second)
	for {
		resp, err := client.Get(url)
		if err == nil {
			resp.Body.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("TLS did not come up on the same port after toggle", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// And back to plain HTTP on the same port.
	if err := srv.applyWebSettings(base); err != nil {
		t.Fatal("toggle back to HTTP", err)
	}
	waitServe(t, port)
}

// While HTTPS stays on, replacing the cert files and re-saving must
// rotate the served certificate without rebinding the port.
func TestWebServerCertRotationWithoutRebind(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadWebSettings(dir, 0, false); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certFile, keyFile := writeTestCertSerial(t, dir, 11, now.Add(-time.Hour), now.Add(24*time.Hour))
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	srv := newWebServer(h)
	port := freePort(t)
	cfg := WebSettings{Port: port, ListenAddr: "127.0.0.1", HTTPS: true, CertFile: certFile, KeyFile: keyFile}
	if err := srv.reload(cfg); err != nil {
		t.Fatal(err)
	}
	peerSerial := func() int64 {
		conn, err := tls.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64()
	}
	deadline := time.Now().Add(3 * time.Second)
	for peerSerial() != 11 {
		if time.Now().After(deadline) {
			t.Fatal("initial cert not served")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Renewal replaces the files in place; re-saving the same settings
	// must serve the new certificate on the same listener.
	writeTestCertSerial(t, dir, 22, now.Add(-time.Hour), now.Add(24*time.Hour))
	if err := srv.applyWebSettings(cfg); err != nil {
		t.Fatal(err)
	}
	if got := peerSerial(); got != 22 {
		t.Fatal("cert rotation did not take effect", got)
	}
}
