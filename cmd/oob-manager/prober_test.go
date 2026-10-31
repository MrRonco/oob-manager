package main

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/bmcssh/sshtest"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/config"
	"oob-manager/internal/console/rfbtest"
	"oob-manager/internal/registry"
	"oob-manager/internal/secrets"
	"oob-manager/internal/secrets/credstore"
	"oob-manager/internal/store"
	"oob-manager/internal/web/ui"
)

func redirectTo(addr string) func(ctx context.Context, network, _ string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
}

// TestProberTestConnection runs Test connection against a Redfish mock, a fake VNC
// server and a fake BMC SSH service: every step is read-only and nothing is written.
func TestProberTestConnection(t *testing.T) {
	mock := redfishmock.New(t, redfishmock.FixtureDir(t, "idrac9-r240"), redfishmock.WithFanFloor())
	vnc := rfbtest.New(t, rfbtest.Options{TLS: true})
	ssh := sshtest.New(t, sshtest.Options{})
	yml := `tls: { cert_file: /c, key_file: /k }
public_url: https://oob.example.test
servers:
  - id: edge
    name: Edge
    bmc: { address: 192.0.2.11, kind: idrac9 }
    tls_pin_sha256: "` + mock.PinSHA256() + `"
    ssh_host_key: "` + ssh.HostKeyLine() + `"
    credentials: { readonly: edge-ro, operator: edge-op, vnc: edge-vnc }
    console: { serial: bmcssh, graphical: vnc, vnc: { tls_pin_sha256: "` + vnc.PinSHA256() + `" } }
`
	file, err := config.Parse([]byte(yml))
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	cs, _ := credstore.New(key)
	aud := audit.NewLogger(db.Audit(), nil, nil, quietLog())
	reg, err := registry.New(context.Background(), registry.Config{DB: db, Audit: aud, File: file, Creds: cs, Logger: quietLog()})
	if err != nil {
		t.Fatal(err)
	}
	creds, _ := secrets.ParseCredentials([]byte("edge-ro: {username: " + redfishmock.User + ", password: " + redfishmock.Password + "}\n"))
	e := env{newDriver: func(s config.Server, ro secrets.Credential) (bmc.Driver, error) {
		return bmcDriverAt(s, ro, mock.URL())
	},
		kvmEndpoint: func(config.Server) string { return mock.URL() }, vncDial: redirectTo(vnc.Addr()), sshDial: redirectTo(ssh.Addr())}
	p := newProber(reg, creds, e, aud, quietLog())
	if err = p.StartTest("edge", "alice"); err != nil {
		t.Fatal(err)
	}
	if err = p.StartTest("edge", "alice"); !errors.Is(err, ui.ErrTestRunning) {
		t.Fatalf("second start: %v", err)
	}
	var res ui.ServerTest
	waitUntil(t, "test finished", func() bool { r, _ := p.LastTest("edge"); res = r; return !r.Running })
	names := []string{}
	for _, st := range res.Steps {
		names = append(names, st.Name)
		if !st.OK {
			t.Errorf("step %s failed: %s", st.Name, st.Detail)
		}
	}
	if !res.OK || res.Kind != config.KindIDRAC9 || strings.Join(names, ",") !=
		"Redfish,Kind,Firmware,Reset actions,License,Fan limits,VNC banner,SSH host key" {
		t.Fatalf("result = %+v", res)
	}
	// Nothing is written: the only non-GET requests are session logins and logouts.
	for _, r := range mock.Requests() {
		if r.Method != "GET" && !strings.Contains(r.Path, "/SessionService/Sessions") {
			t.Fatalf("the test wrote to the BMC: %s %s", r.Method, r.Path)
		}
	}
	if ssh.AuthAttempts() != 0 || vnc.Stats().AuthOK+vnc.Stats().AuthFailures != 0 {
		t.Fatal("the test tried to log in to SSH or VNC")
	}
	recs, _ := db.AuditSearch().Search(context.Background(), store.AuditFilter{Action: ActionServerTest, Limit: 5})
	if len(recs) != 1 || recs[0].Result != audit.ResultOK || recs[0].Principal != "alice" {
		t.Fatalf("audit = %+v", recs)
	}
	if err = p.StartTest("ghost", "alice"); !errors.Is(err, registry.ErrNotFound) {
		t.Fatalf("unknown server: %v", err)
	}
	// Fingerprint fetches go through bmcDial in tests and never send HTTP.
	p.e.bmcDial = redirectTo(strings.TrimPrefix(mock.URL(), "https://"))
	info, err := p.FetchTLS(context.Background(), netip.MustParseAddrPort("192.0.2.11:443"), false)
	if err != nil || info.SPKI != mock.PinSHA256() {
		t.Fatalf("fetch tls: %v", err)
	}
	p.e.bmcDial = redirectTo(ssh.Addr())
	hk, err := p.FetchSSH(context.Background(), netip.MustParseAddrPort("192.0.2.11:22"), false)
	if err != nil || hk.Line != ssh.HostKeyLine() {
		t.Fatalf("fetch ssh: %v", err)
	}
}

func TestDetectKindAndSteps(t *testing.T) {
	cases := []struct {
		f    bmc.CapabilityFlags
		want config.BMCKind
	}{
		{bmc.CapabilityFlags{Product: "Integrated Dell Remote Access Controller", BMCModel: "13G Monolithic"}, config.KindIDRAC8},
		{bmc.CapabilityFlags{Product: "Integrated Remote Access Controller", BMCModel: "14G Monolithic"}, config.KindIDRAC9},
		{bmc.CapabilityFlags{Product: "Integrated Remote Access Controller", BMCFirmware: "2.86"}, config.KindIDRAC8},
		{bmc.CapabilityFlags{Product: "OpenBMC"}, config.KindRedfish},
	}
	for _, c := range cases {
		if got := detectKind(c.f); got != c.want {
			t.Errorf("%+v: %s want %s", c.f, got, c.want)
		}
	}
	if st := kindStep(config.KindIDRAC8, config.KindIDRAC9); st.OK || !strings.Contains(st.Detail, "set to idrac8") {
		t.Fatalf("kind mismatch step = %+v", st)
	}
	if resetDetail(nil) == "" || nonEmpty("") != "unknown" || classOf(errors.New("x")) != "error" {
		t.Fatal("helpers")
	}
}

func quietLog() *slog.Logger { return slog.New(slog.DiscardHandler) }
