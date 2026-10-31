package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/config"
	"oob-manager/internal/console/rfbtest"
	"oob-manager/internal/secrets"
	"oob-manager/internal/store"
)

type nopAudit struct{}

func (nopAudit) Record(context.Context, audit.Entry) (store.AuditRecord, error) {
	return store.AuditRecord{}, nil
}

func consoleTestConfig(pin string) config.Config {
	off := false
	vnc := config.Server{ID: "r1", Name: "One", BMC: config.BMCConfig{Address: "192.0.2.10", Kind: config.KindIDRAC8},
		TLSPinSHA256: pin, Credentials: config.CredentialRef{ReadOnly: "r1-ro", VNC: "r1-vnc"}}
	vnc.Console.Graphical = config.GraphicalVNC
	vnc.Console.VNC = config.VNCConfig{Port: 5901, TLS: &off}
	kvm := config.Server{ID: "r2", Name: "Two", BMC: config.BMCConfig{Address: "192.0.2.11", Kind: config.KindIDRAC9,
		Timeouts: config.BMCTimeouts{Request: 5 * time.Second}},
		TLSPinSHA256: pin, Credentials: config.CredentialRef{ReadOnly: "r2-ro", Operator: "r2-op", VNC: "missing"}}
	kvm.Console.Graphical = config.GraphicalVNC
	kvm.Console.VNC = config.VNCConfig{Port: 5901, TLS: &off}
	ipmi := config.Server{ID: "r3", Name: "Three", BMC: config.BMCConfig{Address: "192.0.2.12", Kind: config.KindIPMI}}
	return config.Config{Servers: []config.Server{vnc, kvm, ipmi},
		Console: config.ConsoleSettings{IdleTimeout: time.Minute, MaxSession: time.Hour}}
}

func TestBuildConsoles(t *testing.T) {
	mock := redfishmock.New(t, redfishmock.FixtureDir(t, "idrac9-r240"), redfishmock.WithKVMSession())
	fake := rfbtest.New(t, rfbtest.Options{})
	creds, err := secrets.ParseCredentials([]byte("r1-vnc: {password: abcdefghij}\nr2-op: {username: " +
		redfishmock.OperatorUser + ", password: " + redfishmock.OperatorPassword + "}\n"))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	e := env{vncDial: func(ctx context.Context, n, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, n, fake.Addr())
	}, kvmEndpoint: func(config.Server) string { return mock.URL() }}
	cfg := consoleTestConfig(mock.PinSHA256())
	svc, kvm, err := buildConsoles(cfg, creds, nopAudit{}, e, log)
	if err != nil {
		t.Fatal(err)
	}
	if st := svc.Status("r1"); !st.Configured || !st.HasPassword || len(st.Warnings) != 1 {
		t.Errorf("r1 = %+v", st)
	}
	if st := svc.Status("r2"); !st.Configured || st.HasPassword {
		t.Errorf("r2 (credential missing) = %+v", st)
	}
	for _, want := range []string{"VNC credential missing", "longer than 8", "without TLS"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, logs.String())
		}
	}
	if strings.Contains(logs.String(), "abcdefghij") {
		t.Fatal("password logged")
	}
	if !kvm.Available("r2") || kvm.Available("r1") || kvm.Available("r3") {
		t.Error("kvm availability")
	}
	link, err := kvm.Launch(context.Background(), "r2")
	if err != nil || !strings.HasPrefix(link.Reveal(), "https://192.0.2.11/console?") {
		t.Fatalf("launch = %v %v", link.Reveal(), err)
	}
	if _, err := kvm.Launch(context.Background(), "r1"); err == nil {
		t.Error("launch without operator login accepted")
	}
	urls := bmcWebURL(cfg)
	if urls("r1") != "https://192.0.2.10:443/" || urls("r3") != "" {
		t.Errorf("bmc urls %q %q", urls("r1"), urls("r3"))
	}
	if defaultEndpoint(cfg.Servers[0]) != "https://192.0.2.10:443" {
		t.Error(defaultEndpoint(cfg.Servers[0]))
	}
}

func TestBuildConsolesRejectsBadPin(t *testing.T) {
	cfg := consoleTestConfig("zz")
	on := true
	cfg.Servers[0].Console.VNC.TLS = &on
	creds, _ := secrets.ParseCredentials([]byte("r1-vnc: {password: x}\n"))
	if _, _, err := buildConsoles(cfg, creds, nopAudit{}, env{}, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("invalid pin accepted")
	}
}

func TestBuildConsolesLogsRSAKeyExchange(t *testing.T) {
	cfg := consoleTestConfig(strings.Repeat("ab", 32))
	on := true
	cfg.Servers[0].Console.VNC = config.VNCConfig{Port: 5901, TLS: &on,
		Quirks: []config.VNCQuirk{config.QuirkIDRAC8RSAKexTLS}}
	cfg.Servers[1].Console.VNC.Quirks = []config.VNCQuirk{config.QuirkIDRAC8RSAKexTLS} // TLS off: no warning
	creds, _ := secrets.ParseCredentials([]byte("r1-vnc: {password: abcdefgh}\n"))
	var logs bytes.Buffer
	if _, _, err := buildConsoles(cfg, creds, nopAudit{}, env{}, slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(logs.String(), "RSA key exchange"); n != 1 || !strings.Contains(logs.String(), "server=r1") {
		t.Errorf("want one RSA key exchange warning for r1, got %d:\n%s", n, logs.String())
	}
}
