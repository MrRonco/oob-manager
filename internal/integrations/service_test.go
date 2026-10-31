package integrations

// repopolicy:allow private-addresses -- tests the private-network egress policy of integration targets

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/config"
	"oob-manager/internal/settings"
	"oob-manager/internal/store"
	"oob-manager/internal/tlspin/tlspintest"
)

const baseYAML = `tls: { cert_file: /c, key_file: /k }
public_url: https://oob.example.test
`

// receiver is a GELF input (plain TCP, or TLS with cert): every frame's "_action" (or
// short message) lands on got.
type receiver struct {
	addr string
	got  chan string
}

func newReceiver(t *testing.T, cert *tls.Certificate) *receiver {
	t.Helper()
	var ln net.Listener
	var err error
	if cert != nil {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{*cert}, MinVersion: tls.VersionTLS12})
	} else {
		ln, err = (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	r := &receiver{addr: ln.Addr().String(), got: make(chan string, 200)}
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go r.read(c)
		}
	}()
	return r
}

func (r *receiver) read(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		frame, err := br.ReadBytes(0)
		if err != nil {
			return
		}
		var m map[string]any
		if json.Unmarshal(frame[:len(frame)-1], &m) == nil {
			s, _ := m["_action"].(string)
			if s == "" {
				s, _ = m["short_message"].(string)
			}
			r.got <- s
		}
	}
}

// waitAction waits for a frame naming action and returns everything seen before it.
func (r *receiver) waitAction(t *testing.T, action string) []string {
	t.Helper()
	var seen []string
	deadline := time.After(5 * time.Second)
	for {
		select {
		case a := <-r.got:
			seen = append(seen, a)
			if strings.Contains(a, action) {
				return seen
			}
		case <-deadline:
			t.Fatalf("no %s frame; saw %v", action, seen)
		}
	}
}

func (r *receiver) none(t *testing.T, action string, within time.Duration) {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case a := <-r.got:
			if strings.Contains(a, action) {
				t.Fatalf("unexpected %s frame", action)
			}
		case <-deadline:
			return
		}
	}
}

type fixture struct {
	db     *store.DB
	set    *settings.Service
	svc    *Service
	sw     *audit.SwitchSink
	actor  admin.Actor
	routes map[string]string // configured "ip:port" → receiver address
	onDial func(addr string) // called before each dial (nil: none)
	mu     sync.Mutex
	trust  []TrustChange
	cancel context.CancelFunc
	done   chan struct{}
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newFixture(t *testing.T, extraYAML string, routes map[string]string) *fixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	file, err := config.Parse([]byte(extraYAML + baseYAML))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{db: db, sw: &audit.SwitchSink{}, routes: routes,
		actor: admin.Actor{UserID: "u1", Username: "alice", Role: authz.RoleAdmin, IP: "192.0.2.1", Method: "local"}}
	lg := audit.NewLogger(db.Audit(), f.sw, nil, quiet())
	if f.set, err = settings.New(ctx, settings.Config{DB: db, Audit: lg, File: file, Logger: quiet()}); err != nil {
		t.Fatal(err)
	}
	pol := Policy{Allowed: file.GELFNetworks(), Self: SelfEndpoints(addrs("10.0.0.2"), []uint16{8443})}
	tuning := audit.ShipperConfig{DialTimeout: time.Second, WriteTimeout: time.Second, BackoffMin: 10 * time.Millisecond,
		BackoffMax: 50 * time.Millisecond, FlushTimeout: time.Second, PinPause: 100 * time.Millisecond}
	f.svc, err = New(Config{Settings: f.set, Audit: lg, Switch: f.sw, Policy: pol, Dial: f.dial, Tuning: tuning,
		Logger: quiet(), OnTrust: f.onTrust, PreviousTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	to, ok := f.routes[addr]
	hook := f.onDial
	f.mu.Unlock()
	if hook != nil {
		hook(addr)
	}
	if !ok {
		return nil, errors.New("test: no route to " + addr)
	}
	return (&net.Dialer{}).DialContext(ctx, network, to)
}

// route points a configured address at a receiver (safe while shippers dial).
func (f *fixture) route(addr, to string) {
	f.mu.Lock()
	f.routes[addr] = to
	f.mu.Unlock()
}

func (f *fixture) onTrust(c TrustChange) {
	f.mu.Lock()
	f.trust = append(f.trust, c)
	f.mu.Unlock()
}

func (f *fixture) trustEvents() []TrustChange {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]TrustChange(nil), f.trust...)
}

func (f *fixture) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel, f.done = cancel, make(chan struct{})
	go func() { f.svc.Run(ctx); close(f.done) }()
	t.Cleanup(f.stop)
}

func (f *fixture) stop() {
	if f.cancel != nil {
		f.cancel()
		<-f.done
		f.cancel = nil
	}
}

func (f *fixture) update(t *testing.T, form map[string]string, pin settings.PinOrigin) []settings.Change {
	t.Helper()
	ch, err := f.svc.Update(context.Background(), f.actor, f.set.Current().Rev, form, pin)
	if err != nil {
		t.Fatalf("update %v: %v", form, err)
	}
	return ch
}

func (f *fixture) audited(t *testing.T, action string) []store.AuditRecord {
	t.Helper()
	recs, err := f.db.AuditSearch().Search(context.Background(), store.AuditFilter{Action: action, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func enable(addr string) map[string]string {
	return map[string]string{config.KeyGELFEnabled: "on", config.KeyGELFAddress: addr, config.KeyGELFTransport: "tcp"}
}

// TestApplyOrdering: switching from A to B records the update row on A (the old
// destination learns who redirected the stream, and where to) and the applied row on B.
func TestApplyOrdering(t *testing.T) {
	a, b := newReceiver(t, nil), newReceiver(t, nil)
	f := newFixture(t, "", map[string]string{"10.0.0.30:12201": a.addr, "10.0.0.31:12201": b.addr})
	f.run(t)
	f.update(t, enable("10.0.0.30:12201"), settings.PinOrigin{})
	a.waitAction(t, ActionApplied)
	if st := f.svc.Stats(); !st.Active {
		t.Fatalf("stats %+v", st)
	}
	f.update(t, map[string]string{config.KeyGELFAddress: "10.0.0.31:12201"}, settings.PinOrigin{})
	a.waitAction(t, settings.ActionIntegrationsUpdate)
	b.waitAction(t, ActionApplied)
	a.none(t, ActionApplied, 100*time.Millisecond)
	if f.svc.Applied().Address != "10.0.0.31:12201" {
		t.Fatalf("applied %+v", f.svc.Applied())
	}
	// An unchanged target is not re-applied.
	f.svc.Apply(context.Background())
	if n := len(f.audited(t, ActionApplied)); n != 2 {
		t.Fatalf("%d applied rows", n)
	}
}

func TestDisable(t *testing.T) {
	a := newReceiver(t, nil)
	f := newFixture(t, "", map[string]string{"10.0.0.30:12201": a.addr})
	f.run(t)
	f.update(t, enable("10.0.0.30:12201"), settings.PinOrigin{})
	a.waitAction(t, ActionApplied)
	f.update(t, map[string]string{config.KeyGELFEnabled: "off"}, settings.PinOrigin{})
	a.waitAction(t, settings.ActionIntegrationsUpdate) // flushed by the old shipper
	if st := f.svc.Stats(); st.Active || f.sw.Current() != nil {
		t.Fatalf("still shipping: %+v", st)
	}
	if r := f.svc.SendTest(context.Background(), f.actor); r.OK || r.Class != audit.ClassOff {
		t.Fatalf("test while disabled %+v", r)
	}
}

// TestStartsBeforeRun: a target saved in the database is built by New and started by
// Run; rows recorded in between are queued, not lost.
func TestStartsBeforeRun(t *testing.T) {
	a := newReceiver(t, nil)
	routes := map[string]string{"10.0.0.30:12201": a.addr}
	f := newFixture(t, "", routes)
	f.update(t, enable("10.0.0.30:12201"), settings.PinOrigin{}) // applied before Run: queued
	f.run(t)
	a.waitAction(t, ActionApplied)
	f.stop()
	if f.svc.Stats().Connected {
		t.Fatal("connected after Run returned")
	}
}

func TestUpdateRefusals(t *testing.T) {
	f := newFixture(t, "", map[string]string{})
	ctx := context.Background()
	for _, addr := range []string{"10.0.0.2:8443", "127.0.0.1:12201", "203.0.113.4:12201"} {
		if _, err := f.svc.Update(ctx, f.actor, 0, enable(addr), settings.PinOrigin{}); !errors.Is(err, settings.ErrInvalid) {
			t.Errorf("%s: %v", addr, err)
		}
	}
	if _, err := f.svc.Update(ctx, f.actor, 5, enable("10.0.0.30:12201"), settings.PinOrigin{}); !errors.Is(err, settings.ErrConflict) {
		t.Fatalf("stale: %v", err)
	}
	if n := len(f.audited(t, ActionApplied)); n != 0 {
		t.Fatalf("refused updates applied %d times", n)
	}
	locked := newFixture(t, "settings: { locked: [integrations] }\n", nil)
	if !locked.svc.Locked() {
		t.Fatal("not locked")
	}
	if _, err := locked.svc.Update(ctx, locked.actor, 0, enable("10.0.0.30:12201"), settings.PinOrigin{}); !errors.Is(err, settings.ErrLocked) {
		t.Fatalf("locked: %v", err)
	}
	if _, err := New(Config{}); err == nil {
		t.Fatal("New without dependencies")
	}
}

func TestReset(t *testing.T) {
	a := newReceiver(t, nil)
	f := newFixture(t, "", map[string]string{"10.0.0.30:12201": a.addr})
	f.run(t)
	f.update(t, enable("10.0.0.30:12201"), settings.PinOrigin{})
	ch, err := f.svc.Reset(context.Background(), f.actor, f.set.Current().Rev, config.KeyGELFEnabled)
	if err != nil || len(ch) != 1 || f.svc.Stats().Active {
		t.Fatalf("reset %+v %v %+v", ch, err, f.svc.Stats())
	}
	if ch, err := f.svc.Reset(context.Background(), f.actor, f.set.Current().Rev, config.KeyGELFEnabled); err != nil || ch != nil {
		t.Fatalf("second reset %+v %v", ch, err)
	}
}

func TestSendTest(t *testing.T) {
	a := newReceiver(t, nil)
	f := newFixture(t, "", map[string]string{"10.0.0.30:12201": a.addr})
	f.run(t)
	f.update(t, enable("10.0.0.30:12201"), settings.PinOrigin{})
	a.waitAction(t, ActionApplied)
	r := f.svc.SendTest(context.Background(), f.actor)
	if !r.OK || r.Class != "" || !r.ConnectedAfter {
		t.Fatalf("test %+v", r)
	}
	a.waitAction(t, "oob-manager GELF test by alice")
	rows := f.audited(t, ActionTest)
	if len(rows) != 2 || rows[1].Result != audit.ResultStarted || rows[0].Result != audit.ResultOK ||
		rows[0].CorrelationID != rows[1].CorrelationID || !strings.Contains(rows[0].ParamsJSON, `"connected_after":true`) {
		t.Fatalf("rows %+v", rows)
	}
	// The server goes away: the test reports the class and is audited as an error.
	f.route("10.0.0.30:12201", "127.0.0.1:1")
	f.update(t, map[string]string{config.KeyGELFServerName: "logs.example.test"}, settings.PinOrigin{}) // rebuilds the shipper
	r = f.svc.SendTest(context.Background(), f.actor)
	if r.OK || r.Class != audit.ClassDial {
		t.Fatalf("down %+v", r)
	}
	if rows := f.audited(t, ActionTest); rows[0].Result != audit.ResultError || rows[0].ErrorClass != audit.ClassDial {
		t.Fatalf("rows %+v", rows[0])
	}
}

func TestFingerprint(t *testing.T) {
	issued := tlspintest.Issued(t)
	cert := issued.TLS()
	tlsRecv := newReceiver(t, &cert)
	f := newFixture(t, "", map[string]string{"10.0.0.32:6514": tlsRecv.addr})
	info, err := f.svc.Fingerprint(context.Background(), f.actor, "10.0.0.32:6514", "gelf.example.test")
	if err != nil || info.SPKI != issued.Leaf.SPKI() || info.Recommended() != issued.CA.SPKI() {
		t.Fatalf("info %+v %v", info, err)
	}
	if _, err := f.svc.Fingerprint(context.Background(), f.actor, "127.0.0.1:6514", ""); err == nil {
		t.Fatal("loopback fetched")
	}
	if _, err := f.svc.Fingerprint(context.Background(), f.actor, "10.0.0.33:6514", "logs.example.test"); err == nil {
		t.Fatal("unrouted fetch succeeded")
	}
	rows := f.audited(t, ActionFingerprint)
	// Newest first: a started row before each fetch, then its result.
	if len(rows) != 6 || rows[5].Result != audit.ResultStarted || rows[4].Result != audit.ResultOK ||
		rows[2].ErrorClass != ClassPolicy || rows[0].ErrorClass != "unreachable" ||
		!strings.Contains(rows[4].ParamsJSON, `"address":"10.0.0.32","port":6514`) {
		t.Fatalf("rows %+v", rows)
	}
}

// TestPinMismatchAndRecovery: a wrong pin pauses shipping and raises one trust event;
// confirming the right pin swaps in a shipper whose first connection resolves it.
func TestPinMismatchAndRecovery(t *testing.T) {
	issued := tlspintest.Issued(t)
	cert := issued.TLS()
	tlsRecv := newReceiver(t, &cert)
	f := newFixture(t, "", map[string]string{"10.0.0.32:6514": tlsRecv.addr})
	f.run(t)
	wrong := tlspintest.SelfSigned(t).Leaf.SPKI()
	form := map[string]string{config.KeyGELFEnabled: "on", config.KeyGELFAddress: "10.0.0.32:6514",
		config.KeyGELFTransport: "tls", config.KeyGELFPin: wrong, config.KeyGELFServerName: "gelf.example.test"}
	f.update(t, form, settings.PinOrigin{})
	// The shipper sets the mismatch flag just before it calls back: wait for the event.
	waitFor(t, func() bool { return f.svc.Stats().PinMismatch && len(f.trustEvents()) == 1 })
	if ev := f.trustEvents(); ev[0] != TrustMismatch {
		t.Fatalf("trust events %v", ev)
	}
	tlsRecv.none(t, ActionApplied, 50*time.Millisecond)
	f.update(t, map[string]string{config.KeyGELFPin: issued.CA.SPKI()}, settings.PinOrigin{Via: "fetched", Pinned: "issuer"})
	tlsRecv.waitAction(t, ActionApplied)
	waitFor(t, func() bool { ev := f.trustEvents(); return len(ev) == 2 && ev[1] == TrustResolved })
	if st := f.svc.Stats(); st.PinMismatch || !st.TLS {
		t.Fatalf("stats %+v", st)
	}
}

func TestServerName(t *testing.T) {
	cases := map[config.GELF]string{
		{Address: "10.0.0.5:1"}:                                  "",
		{Address: "logs.example.test:1"}:                         "logs.example.test",
		{Address: "10.0.0.5:1", ServerName: "logs.example.test"}: "logs.example.test",
		{Address: "nonsense"}:                                    "",
	}
	for g, want := range cases {
		if got := serverName(g); got != want {
			t.Errorf("%+v: %q", g, got)
		}
	}
	if hostOf("x") != "" || portOf("x") != 0 || fetchClass(errors.New("x")) != "error" {
		t.Fatal("helpers")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestTrustPerGeneration: moving the destination withdraws the open alert, the new
// target's own mismatch is reported, and a late callback of a replaced shipper changes
// nothing.
func TestTrustPerGeneration(t *testing.T) {
	issued := tlspintest.Issued(t)
	cert := issued.TLS()
	recv := newReceiver(t, &cert)
	f := newFixture(t, "", map[string]string{"10.0.0.32:6514": recv.addr, "10.0.0.33:6514": recv.addr})
	f.run(t)
	wrong := tlspintest.SelfSigned(t).Leaf.SPKI()
	f.update(t, map[string]string{config.KeyGELFEnabled: "on", config.KeyGELFAddress: "10.0.0.32:6514",
		config.KeyGELFTransport: "tls", config.KeyGELFPin: wrong}, settings.PinOrigin{})
	waitFor(t, func() bool { return len(f.trustEvents()) == 1 })
	old := f.svc.gen.Load()
	f.update(t, map[string]string{config.KeyGELFAddress: "10.0.0.33:6514"}, settings.PinOrigin{})
	waitFor(t, func() bool { ev := f.trustEvents(); return len(ev) == 3 })
	if ev := f.trustEvents(); ev[1] != TrustWithdrawn || ev[2] != TrustMismatch {
		t.Fatalf("events %v", ev)
	}
	f.svc.connected(old) // a late callback from the replaced shipper
	if ev := f.trustEvents(); len(ev) != 3 {
		t.Fatalf("stale callback reported %v", ev)
	}
	rows := f.audited(t, ActionApplied)
	if len(rows) < 2 || !strings.Contains(rows[0].ParamsJSON, `"queued_on_previous":`) ||
		!strings.Contains(rows[0].ParamsJSON, `"previous_confirmed":`) {
		t.Fatalf("applied rows %+v", rows)
	}
}

func TestAuditedHostIsBounded(t *testing.T) {
	if got := hostOf(strings.Repeat("a", 400) + ":1"); len(got) != maxAuditHost {
		t.Fatalf("host %d chars", len(got))
	}
}
