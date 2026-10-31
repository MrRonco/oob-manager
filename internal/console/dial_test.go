package console

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/config"
	"oob-manager/internal/console/rfbtest"
	"oob-manager/internal/secrets"
)

func rsaKexTarget(t *testing.T, pin string, quirk bool) Target {
	t.Helper()
	s := serverCfg(config.KindIDRAC8, true, pin)
	if quirk {
		s.Console.VNC.Quirks = append(s.Console.VNC.Quirks, config.QuirkIDRAC8RSAKexTLS)
	}
	tg, err := TargetFor(s, secrets.New("x"))
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

// An iDRAC8 2.8x VNC port offers only RSA key exchange: the default TLS config fails,
// the idrac8_rsa_kex_tls quirk connects.
func TestRSAKexQuirkDial(t *testing.T) {
	fake := rfbtest.New(t, rfbtest.Options{TLS: true, RSAKeyExchangeOnly: true})
	without := rsaKexTarget(t, fake.PinSHA256(), false)
	if without.RSAKeyExchange {
		t.Fatal("quirk off but RSAKeyExchange set")
	}
	if _, err := dialTarget(context.Background(), redirect(fake.Addr()), without); !errors.Is(err, ErrTLS) {
		t.Fatalf("without quirk: err = %v, want ErrTLS", err)
	}
	with := rsaKexTarget(t, fake.PinSHA256(), true)
	if !with.RSAKeyExchange {
		t.Fatal("quirk on but RSAKeyExchange unset")
	}
	c, err := dialTarget(context.Background(), redirect(fake.Addr()), with)
	if err != nil {
		t.Fatalf("with quirk: %v", err)
	}
	defer c.Close()
	st := c.(*tls.Conn).ConnectionState() //nolint:errcheck,forcetypeassert // TLS target
	if st.Version != tls.VersionTLS12 || !isRSAKexGCM(st.CipherSuite) {
		t.Errorf("negotiated %x / %s", st.Version, tls.CipherSuiteName(st.CipherSuite))
	}
	if p := probeBanner(context.Background(), redirect(fake.Addr()), with, time.Now()); p.State != ProbeOK {
		t.Errorf("probe with quirk = %q", p.State)
	}
	if p := probeBanner(context.Background(), redirect(fake.Addr()), without, time.Now()); p.State != ProbeTLS {
		t.Errorf("probe without quirk = %q", p.State)
	}
}

func isRSAKexGCM(id uint16) bool {
	return id == tls.TLS_RSA_WITH_AES_256_GCM_SHA384 || id == tls.TLS_RSA_WITH_AES_128_GCM_SHA256
}

func TestVNCTLSConfigSuites(t *testing.T) {
	pin := make([]byte, 32)
	if c := vncTLS(pin, false); c.CipherSuites != nil || c.MinVersion != tls.VersionTLS12 {
		t.Errorf("default config = suites %v min %x", c.CipherSuites, c.MinVersion)
	}
	c := vncTLS(pin, true)
	if c.MinVersion != tls.VersionTLS12 {
		t.Errorf("min version %x", c.MinVersion)
	}
	n := len(c.CipherSuites)
	if n < 3 || c.CipherSuites[n-2] != tls.TLS_RSA_WITH_AES_256_GCM_SHA384 ||
		c.CipherSuites[n-1] != tls.TLS_RSA_WITH_AES_128_GCM_SHA256 {
		t.Fatalf("suites = %v: RSA kex GCM suites must come last", c.CipherSuites)
	}
	for _, id := range c.CipherSuites[:n-2] {
		name := tls.CipherSuiteName(id)
		if !strings.HasPrefix(name, "TLS_ECDHE_") {
			t.Errorf("%s before the RSA suites: only ECDHE suites may precede them", name)
		}
	}
	insecure := tls.InsecureCipherSuites()
	for _, id := range c.CipherSuites {
		if !isRSAKexGCM(id) && slices.ContainsFunc(insecure, func(s *tls.CipherSuite) bool { return s.ID == id }) {
			t.Errorf("insecure suite %s", tls.CipherSuiteName(id))
		}
		if name := tls.CipherSuiteName(id); !strings.Contains(name, "GCM") && !strings.Contains(name, "CHACHA20") {
			t.Errorf("%s: only AEAD suites (no CBC/SHA1)", name)
		}
	}
}

// With SSL on, iDRAC8 still answers a client that sends no ClientHello with a plain
// "RFB 003.008\n" banner. A tls=true target must report that as a TLS failure and never
// fall back to plain RFB.
func TestTLSTargetNeverDowngrades(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("RFB 003.008\n"))
			time.Sleep(50 * time.Millisecond)
			_ = c.Close()
		}
	}()
	for _, quirk := range []bool{false, true} {
		tg := rsaKexTarget(t, strings.Repeat("ab", 32), quirk)
		if _, err := dialTarget(context.Background(), redirect(ln.Addr().String()), tg); !errors.Is(err, ErrTLS) {
			t.Errorf("quirk %v: dial err = %v, want ErrTLS", quirk, err)
		}
		if p := probeBanner(context.Background(), redirect(ln.Addr().String()), tg, time.Now()); p.State != ProbeTLS {
			t.Errorf("quirk %v: probe = %q, want %q (never ready over plain RFB)", quirk, p.State, ProbeTLS)
		}
	}
}
