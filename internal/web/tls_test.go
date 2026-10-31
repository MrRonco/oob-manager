package web

import (
	"crypto/tls"
	"net/http"
	"slices"
	"testing"
	"time"
)

func TestTLSConfig(t *testing.T) {
	c := TLSConfig()
	if c.MinVersion != tls.VersionTLS12 {
		t.Fatalf("MinVersion = %x", c.MinVersion)
	}
	if len(c.CipherSuites) == 0 {
		t.Fatal("TLS 1.2 suites must be pinned")
	}
	for _, id := range c.CipherSuites {
		name := tls.CipherSuiteName(id)
		for _, s := range tls.InsecureCipherSuites() {
			if s.ID == id {
				t.Errorf("insecure suite %s allowed", name)
			}
		}
		if !slices.Contains(aeadECDHE(), id) {
			t.Errorf("suite %s is not ECDHE+AEAD", name)
		}
	}
	if !slices.Contains(c.NextProtos, "h2") {
		t.Error("h2 not offered")
	}
	if c.CurvePreferences[0] != tls.X25519MLKEM768 {
		t.Errorf("first curve = %v, want X25519MLKEM768", c.CurvePreferences[0])
	}
}

func aeadECDHE() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}
}

func TestTLSConfigReturnsFreshValue(t *testing.T) {
	a := TLSConfig()
	a.CipherSuites[0] = 0
	if TLSConfig().CipherSuites[0] == 0 {
		t.Fatal("TLSConfig shares state between calls")
	}
}

func TestNewServerTimeouts(t *testing.T) {
	s := NewServer(":8443", http.NotFoundHandler(), nil)
	checks := []struct {
		name      string
		got, want time.Duration
	}{
		{"ReadHeaderTimeout", s.ReadHeaderTimeout, 5 * time.Second},
		{"ReadTimeout", s.ReadTimeout, 15 * time.Second},
		{"WriteTimeout", s.WriteTimeout, 30 * time.Second},
		{"IdleTimeout", s.IdleTimeout, 60 * time.Second},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
	if s.MaxHeaderBytes != 16<<10 {
		t.Errorf("MaxHeaderBytes = %d", s.MaxHeaderBytes)
	}
	if s.TLSConfig == nil || s.TLSConfig.MinVersion != tls.VersionTLS12 {
		t.Error("server must default to TLSConfig()")
	}
	if s.ErrorLog == nil {
		t.Error("ErrorLog must route to slog")
	}
}
