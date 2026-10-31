package main

import (
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/bmcsec"
	"oob-manager/internal/config"
	"oob-manager/internal/secrets"
)

const vncTestPin = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// securityConfig is two servers on TEST-NET addresses: an iDRAC8 with the VNC console
// over TLS (its own pin) and the serial console on a custom SSH port, and an iDRAC9 with
// no consoles. extra is added at the top level.
func securityConfig(t *testing.T, pin, extra string) config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`tls: { cert_file: /c, key_file: /k }
public_url: https://oob.example.test
` + extra + `servers:
  - id: alpha
    name: Alpha
    bmc: { address: 192.0.2.10, kind: idrac8 }
    tls_pin_sha256: "` + pin + `"
    credentials: { readonly: alpha-ro, operator: alpha-op, vnc: alpha-vnc }
    console:
      serial: bmcssh
      graphical: vnc
      ssh: { port: 2222 }
      vnc: { port: 5902, tls_pin_sha256: "` + vncTestPin + `" }
  - id: bravo
    name: Bravo
    bmc: { address: 192.0.2.11, kind: idrac9, port: 8443 }
    tls_pin_sha256: "` + pin + `"
    credentials: { readonly: bravo-ro }
    console: { serial: none, graphical: none }
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestSecurityTarget(t *testing.T) {
	cfg := securityConfig(t, testPin, "")
	alpha, _ := cfg.Server("alpha")
	open := map[string]bool{"alpha": true}
	tg, err := securityTarget(alpha, func(id string) bool { return open[id] })
	if err != nil {
		t.Fatal(err)
	}
	if tg.Addr != netip.MustParseAddr("192.0.2.10") || tg.HTTPSPort != 443 || hex.EncodeToString(tg.Pin) != testPin ||
		tg.SSHPort != 2222 || tg.ConsoleActive == nil || !tg.ConsoleActive() {
		t.Fatalf("target %+v", tg)
	}
	// iDRAC8's default VNC quirks include the RSA key exchange suites.
	if tg.VNC == nil || tg.VNC.Port != 5902 || hex.EncodeToString(tg.VNC.Pin) != vncTestPin || !tg.VNC.RSAKeyExchange {
		t.Fatalf("vnc target %+v", tg.VNC)
	}
	// An iDRAC8's VNC port is left to the console; any other kind's is probed.
	if tg.VNC.NotProbed != bmcsec.NotProbedIDRAC8 {
		t.Fatalf("an iDRAC8's VNC port must not be probed: %q", tg.VNC.NotProbed)
	}
	other := alpha
	other.BMC.Kind = config.KindIDRAC9
	if tg9, err9 := securityTarget(other, nil); err9 != nil || tg9.VNC == nil || tg9.VNC.NotProbed != "" {
		t.Fatalf("an iDRAC9's VNC port is probed: %+v %v", tg9.VNC, err9)
	}
	open["alpha"] = false
	if tg.ConsoleActive() {
		t.Fatal("the console state is read live")
	}

	bravo, _ := cfg.Server("bravo")
	tg, err = securityTarget(bravo, nil)
	if err != nil || tg.HTTPSPort != 8443 || tg.VNC != nil || tg.SSHPort != 0 || tg.ConsoleActive != nil {
		t.Fatalf("no consoles: %+v %v", tg, err)
	}
	// VNC without TLS has no certificate to probe.
	off := false
	alpha.Console.VNC.TLS = &off
	if tg, _ = securityTarget(alpha, nil); tg.VNC != nil {
		t.Fatalf("plain VNC probed: %+v", tg.VNC)
	}
	alpha.TLSPinSHA256 = "not hex"
	if _, err = securityTarget(alpha, nil); err == nil {
		t.Fatal("a bad pin was accepted")
	}
}

func TestSecurityInputs(t *testing.T) {
	cfg := securityConfig(t, testPin, "security: { min_firmware: { idrac8: \"2.86.86.86\" } }\n")
	in := securityInputs(cfg)
	want := map[string]bmcsec.Inputs{
		"alpha": {Kind: "idrac8", MinFirmware: "2.86.86.86", VNC: true, VNCTLS: true, SerialSSH: true, Address: "192.0.2.10:443"},
		"bravo": {Kind: "idrac9", Address: "192.0.2.11:8443"},
	}
	if len(in) != len(want) || in["alpha"] != want["alpha"] || in["bravo"] != want["bravo"] {
		t.Fatalf("inputs %+v", in)
	}
}

func TestPostureForFollowsTheSection(t *testing.T) {
	rt := &serverRuntime{base: securityConfig(t, testPin, ""), log: quietLog()}
	alpha, _ := rt.base.Server("alpha")
	if rt.postureFor(alpha) == nil {
		t.Fatal("the checks are on by default")
	}
	ipmi := alpha
	ipmi.BMC.Kind = config.KindIPMI
	if rt.postureFor(ipmi) != nil {
		t.Fatal("IPMI has no posture reader")
	}
	bad := alpha
	bad.BMC.Address = "not an address"
	if rt.postureFor(bad) != nil {
		t.Fatal("a server whose address cannot be read is not checked")
	}
	rt.base = securityConfig(t, testPin, "security: { enabled: false }\n")
	if rt.postureFor(alpha) != nil {
		t.Fatal("security.enabled: false turns the checks off")
	}
}

// TestPostureReadsTheMockAndRefusesProbesWithoutADialer runs a server's posture reader
// against a mock BMC. Without env.probeDial no probe leaves the process (the configured
// TEST-NET address is never dialled); with a dialer the probes reach only the fakes.
// Either way the mock sees reads only.
func TestPostureReadsTheMockAndRefusesProbesWithoutADialer(t *testing.T) {
	mock := redfishmock.New(t, redfishmock.FixtureDir(t, "idrac9-r240"), redfishmock.WithWSMan())
	cfg := securityConfig(t, mock.PinSHA256(), "")
	bravo, _ := cfg.Server("bravo")
	d, err := bmcDriverAt(bravo, secrets.Credential{Username: redfishmock.User, Password: secrets.New(redfishmock.Password)}, mock.URL())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rt := &serverRuntime{base: cfg, log: quietLog()}
	p, err := rt.postureFor(bravo)(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Redfish.Protocols.Read.OK() || p.Web.Read.State != bmc.ReadFailed || p.Web.Usable() {
		t.Fatalf("posture without a dialer: redfish %+v web %+v", p.Redfish.Protocols.Read, p.Web.Read)
	}
	var dialed []string
	rt.e.probeDial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialed = append(dialed, addr)
		if addr != "192.0.2.11:8443" {
			return nil, errors.New("nothing listens at " + addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(mock.URL(), "https://"))
	}
	if p, err = rt.postureFor(bravo)(ctx, d); err != nil || !p.Web.Usable() || p.WSMan.Status != 401 {
		t.Fatalf("posture with a dialer: %+v %+v %v", p.Web.Read, p.WSMan, err)
	}
	for _, a := range dialed {
		if !strings.HasPrefix(a, "192.0.2.11:") {
			t.Fatalf("a probe dialled %s, not the configured BMC address", a)
		}
	}
	for _, r := range mock.Requests() {
		login := r.Method == "POST" && r.Path == mock.SessionsURI()
		if r.Method != "GET" && r.Method != "HEAD" && !login {
			t.Fatalf("the checks sent %s %s", r.Method, r.Path)
		}
	}
	if mock.OtherWrites() != 0 {
		t.Fatalf("writes: %d", mock.OtherWrites())
	}
}

func TestProbeDialerRefusesByDefault(t *testing.T) {
	if _, err := probeDialer(env{})(context.Background(), "tcp", "192.0.2.10:443"); !errors.Is(err, errProbeDialOff) {
		t.Fatalf("err = %v", err)
	}
}

func TestSecurityCountsAdapter(t *testing.T) {
	if securityCounts(nil) != nil || uiSecurity(nil) != nil {
		t.Fatal("no service, no hooks")
	}
}

// TestSecurityServiceOverTheRuntime builds the service the way serve does: the pollers
// read each server's posture on their own tier, the service evaluates it, re-runs go to
// the fleet (with the cooldown) and /metrics gets the counts.
func TestSecurityServiceOverTheRuntime(t *testing.T) {
	d := newDeployment(t, "")
	cfg, err := config.Load(d.configPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c, err := openCore(ctx, cfg, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.close() }()
	reg, err := c.openRegistry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	file, err := secrets.ParseCredentials([]byte("r240-ro: {username: " + redfishmock.User + ", password: " + redfishmock.Password + "}\n"))
	if err != nil {
		t.Fatal(err)
	}
	e := env{ctx: ctx, newDriver: d.mockDrivers(t)}
	rt, err := newRuntime(ctx, cfg, c, reg, file, e, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	sec, err := buildSecurity(ctx, cfg, c, rt, nil, quietLog())
	if err != nil || sec == nil {
		t.Fatalf("service %v %v", sec, err)
	}
	done := make(chan struct{})
	go func() { rt.fleet.Run(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	waitUntil(t, "the first security check run", func() bool {
		st, ok := rt.fleet.Server("r240")
		return ok && st.HasPosture
	})
	r, ok := sec.Report("r240")
	if !ok || len(r.Findings) == 0 {
		t.Fatalf("report %v %+v", ok, r)
	}
	n, ok := securityCounts(sec)("r240")
	if total := n.Pass + n.Info + n.Warn + n.Fail + n.Unknown + n.CantRead + n.Accepted; !ok || total != len(r.Findings) {
		t.Fatalf("counts %+v for %d findings", n, len(r.Findings))
	}
	if in, ok := rt.securityInput("r240"); !ok || in.Kind != "idrac9" {
		t.Fatalf("inputs %+v %v", in, ok)
	}
	if _, ok := rt.securityInput("nope"); ok {
		t.Fatal("inputs of an unknown server")
	}
	st, _ := rt.fleet.Server("r240")
	if rt.serverName("r240") != st.Name || rt.serverName("nope") != "nope" {
		t.Fatalf("names %q %q", rt.serverName("r240"), rt.serverName("nope"))
	}
	a := admin.Actor{Username: "alice", Method: "local", Role: "admin"}
	if err := sec.Rerun(ctx, a, "r240"); err != nil {
		t.Fatal(err)
	}
	var cd *bmcsec.CooldownError
	if err := sec.Rerun(ctx, a, "r240"); !errors.As(err, &cd) {
		t.Fatalf("second re-run: %v", err)
	}
	if _, ok := securityCounts(sec)("nope"); ok {
		t.Fatal("counts of an unknown server")
	}
	off := false
	cfg.Security.Enabled = &off
	if s, err := buildSecurity(ctx, cfg, c, rt, nil, quietLog()); s != nil || err != nil {
		t.Fatalf("security.enabled: false builds %v %v", s, err)
	}
}
