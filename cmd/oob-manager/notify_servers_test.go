package main

// repopolicy:allow private-addresses -- browser-added servers must sit inside the default bmc_networks, the RFC 1918 blocks

import (
	"context"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/bmcssh/sshtest"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/config"
	"oob-manager/internal/console/rfbtest"
	"oob-manager/internal/maint"
	"oob-manager/internal/notify"
	"oob-manager/internal/secrets"
)

// TestRuntimeSyncsNotifications: a server added in Settings → Servers can be put in
// maintenance, keeps its window while disabled, and loses it (audited as system) when it is
// removed, without a restart; the detector never sees a disabled server.
func TestRuntimeSyncsNotifications(t *testing.T) {
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
	e := env{ctx: ctx, newDriver: func(s config.Server, ro secrets.Credential) (bmc.Driver, error) {
		return bmcDriverAt(s, ro, d.mock.URL())
	}, kvmEndpoint: func(config.Server) string { return d.mock.URL() }}
	rt, err := newRuntime(ctx, cfg, c, reg, file, e, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	_, ms, err := attachNotify(ctx, cfg, c, file, rt, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	var bg sync.WaitGroup
	defer bg.Wait()
	defer cancel()
	bg.Go(func() { rt.fleet.Run(ctx) })
	bg.Go(func() { rt.run(ctx) })

	a := admin.Actor{Username: "alice", Method: "local"}
	addServer(t, reg, a, "hot1", "10.9.2.10", d.mock.PinSHA256())
	waitUntil(t, "hot server in the fleet", func() bool { _, ok := rt.fleet.Server("hot1"); return ok })
	if _, err = ms.Start(ctx, a, "hot1", maint.StartRequest{Reason: "rack move", Duration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	x, _ := reg.Current().DBEntry("hot1")
	if _, err = reg.SetEnabled(ctx, a, "hot1", x.Rev, false); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "disabled server leaves the fleet", func() bool { _, ok := rt.fleet.Server("hot1"); return !ok })
	if _, ok := ms.Window("hot1"); !ok {
		t.Fatal("a disabled server lost its maintenance window")
	}
	x, _ = reg.Current().DBEntry("hot1")
	if err = reg.Delete(ctx, a, "hot1", x.Rev); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "removed server's window dropped", func() bool { _, ok := ms.Window("hot1"); return !ok })
	if ws, _ := c.db.Maint().Windows(ctx); len(ws) != 0 {
		t.Fatalf("stale window rows: %+v", ws)
	}
}

// TestProberReportsTrust: Test connection reports a VNC certificate or SSH host key that
// does not match the confirmed one to the notifications, and a matching one as resolved.
func TestProberReportsTrust(t *testing.T) {
	vnc := rfbtest.New(t, rfbtest.Options{TLS: true})
	otherVNC := rfbtest.New(t, rfbtest.Options{TLS: true})
	ssh := sshtest.New(t, sshtest.Options{})
	otherSSH := sshtest.New(t, sshtest.Options{})
	srv := func(vncPin, hostKey string) config.Server {
		t.Helper()
		f, err := config.Parse([]byte(`tls: { cert_file: /c, key_file: /k }
public_url: https://oob.example.test
servers:
  - id: edge
    name: Edge
    bmc: { address: 192.0.2.11, kind: idrac9 }
    tls_pin_sha256: "` + vnc.PinSHA256() + `"
    ssh_host_key: "` + hostKey + `"
    credentials: { readonly: edge-ro, operator: edge-op, vnc: edge-vnc }
    console: { serial: bmcssh, graphical: vnc, vnc: { tls_pin_sha256: "` + vncPin + `" } }
`))
		if err != nil {
			t.Fatal(err)
		}
		return f.Servers[0]
	}
	type call struct {
		id, what string
		ok       bool
	}
	var got []call
	p := &prober{e: env{vncDial: redirectTo(vnc.Addr()), sshDial: redirectTo(ssh.Addr())}, now: time.Now, log: quietLog(),
		trust: func(id, what string, ok bool) { got = append(got, call{id, what, ok}) }}
	ctx := context.Background()
	if st := p.vncStep(ctx, srv(otherVNC.PinSHA256(), ssh.HostKeyLine())); st.OK {
		t.Fatalf("vnc step with a wrong pin passed: %+v", st)
	}
	if st := p.sshStep(ctx, srv(vnc.PinSHA256(), otherSSH.HostKeyLine())); st.OK {
		t.Fatalf("ssh step with a wrong key passed: %+v", st)
	}
	if st := p.sshStep(ctx, srv(vnc.PinSHA256(), ssh.HostKeyLine())); !st.OK {
		t.Fatalf("ssh step: %+v", st)
	}
	if st := p.vncStep(ctx, srv(vnc.PinSHA256(), ssh.HostKeyLine())); !st.OK {
		t.Fatalf("vnc step: %+v", st)
	}
	want := []call{{"edge", notify.TrustVNC, false}, {"edge", notify.TrustSSHKey, false},
		{"edge", notify.TrustSSHKey, true}, {"edge", notify.TrustVNC, true}}
	if len(got) != len(want) {
		t.Fatalf("trust calls = %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("trust call %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	var nilTap *lateTap
	nilTap.Trust("edge", notify.TrustVNC, false) // no service yet: a no-op
	nilTap.keep(nil)
}

// TestSettingsLockedCoversServersAndIntegrations: settings.locked [servers, integrations]
// locks Settings → Servers (registry) and Settings → Notifications (targets) together.
func TestSettingsLockedCoversServersAndIntegrations(t *testing.T) {
	d := newDeployment(t, "")
	write(t, d.configPath, []byte("settings: { locked: [servers, integrations] }\n"+configYAML(d.dir, "")))
	cfg, err := config.Load(d.configPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	c, err := openCore(ctx, cfg, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.close() }()
	reg, err := c.openRegistry(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reg.Current().Locked {
		t.Fatal("servers section not locked")
	}
	svc, err := buildNotify(ctx, cfg, c, secrets.Credentials{}, nil, nil, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	if !svc.Locked() {
		t.Fatal("integrations section not locked")
	}
	a := admin.Actor{Username: "alice", Method: "local"}
	if err := svc.Create(ctx, a, notify.Target{ID: "t1", Name: "T", Kind: notify.KindWebhook, URL: "https://192.0.2.1/h",
		Enabled: true}, notify.Secrets{}); err == nil {
		t.Fatal("a target was created in a locked section")
	}
}
