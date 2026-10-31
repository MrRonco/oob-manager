package integrations

// repopolicy:allow private-addresses -- tests the private-network egress policy of integration targets

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/settings"
	"oob-manager/internal/store"
	"oob-manager/internal/tlspin/tlspintest"
	"oob-manager/internal/tofu"
)

// TestPreviousDestinationConfirmed: the applied row says whether the update row reached
// the previous destination before the swap: yes for a live one, no for one that is down
// (Apply then waits at most Config.PreviousTimeout).
func TestPreviousDestinationConfirmed(t *testing.T) {
	a, b := newReceiver(t, nil), newReceiver(t, nil)
	f := newFixture(t, "", map[string]string{"10.0.0.30:12201": a.addr, "10.0.0.31:12201": b.addr})
	f.run(t)
	f.update(t, enable("10.0.0.30:12201"), settings.PinOrigin{})
	a.waitAction(t, ActionApplied)
	f.update(t, map[string]string{config.KeyGELFAddress: "10.0.0.31:12201"}, settings.PinOrigin{})
	if rows := f.audited(t, ActionApplied); !strings.Contains(rows[0].ParamsJSON, `"previous_confirmed":true`) {
		t.Fatalf("live previous: %s", rows[0].ParamsJSON)
	}
	f.route("10.0.0.31:12201", "127.0.0.1:1") // B goes down before the next move
	f.update(t, map[string]string{config.KeyGELFServerName: "logs.example.test"}, settings.PinOrigin{})
	start := time.Now()
	f.update(t, map[string]string{config.KeyGELFAddress: "10.0.0.30:12201"}, settings.PinOrigin{})
	if d := time.Since(start); d > f.svc.cfg.PreviousTimeout+time.Second {
		t.Fatalf("Apply waited %v", d)
	}
	if rows := f.audited(t, ActionApplied); !strings.Contains(rows[0].ParamsJSON, `"previous_confirmed":false`) {
		t.Fatalf("down previous: %s", rows[0].ParamsJSON)
	}
}

func TestApplyAfterRunDoesNothing(t *testing.T) {
	a := newReceiver(t, nil)
	f := newFixture(t, "", map[string]string{"10.0.0.30:12201": a.addr})
	f.run(t)
	f.stop()
	if _, err := f.set.UpdateIntegrations(context.Background(), f.actor, 0, enable("10.0.0.30:12201"), settings.PinOrigin{}); err != nil {
		t.Fatal(err)
	}
	f.svc.Apply(context.Background())
	if f.svc.Stats().Active || f.sw.Current() != nil {
		t.Fatal("a shipper was installed after Run returned")
	}
}

// TestCountersCarryAcrossSwaps: sent and dropped are totals over every shipper, so a
// swap does not reset the /metrics counters.
func TestCountersCarryAcrossSwaps(t *testing.T) {
	a, b := newReceiver(t, nil), newReceiver(t, nil)
	f := newFixture(t, "", map[string]string{"10.0.0.30:12201": a.addr, "10.0.0.31:12201": b.addr})
	f.run(t)
	f.update(t, enable("10.0.0.30:12201"), settings.PinOrigin{})
	a.waitAction(t, ActionApplied)
	waitFor(t, func() bool { return f.svc.Stats().Sent >= 1 }) // the applied row
	before := f.svc.Stats().Sent
	f.update(t, map[string]string{config.KeyGELFAddress: "10.0.0.31:12201"}, settings.PinOrigin{})
	b.waitAction(t, ActionApplied)
	waitFor(t, func() bool { return f.svc.Stats().Sent > before })
}

func TestDialerTriesEveryAllowedAnswer(t *testing.T) {
	r := &fakeResolver{answers: [][]netip.Addr{addrs("10.0.0.8", "10.0.0.9")}}
	var dialled []string
	base := func(_ context.Context, _, addr string) (net.Conn, error) {
		dialled = append(dialled, addr)
		if addr == "10.0.0.9:12201" {
			c, _ := net.Pipe()
			return c, nil
		}
		return nil, errors.New("refused")
	}
	c, err := testPolicy(r).Dialer(base)(context.Background(), "tcp", "logs.example.test:12201")
	if err != nil || c == nil || len(dialled) != 2 {
		t.Fatalf("dialled %v: %v", dialled, err)
	}
	_ = c.Close()
}

func TestPolicyRefusalOnSaveIsAudited(t *testing.T) {
	f := newFixture(t, "", nil)
	if _, err := f.svc.Update(context.Background(), f.actor, 0, enable("10.0.0.2:8443"), settings.PinOrigin{}); !errors.Is(err, settings.ErrInvalid) {
		t.Fatalf("own endpoint: %v", err)
	}
	rows := f.audited(t, settings.ActionIntegrationsUpdate)
	if len(rows) != 1 || rows[0].Result != audit.ResultDenied || rows[0].ErrorClass != ClassPolicy {
		t.Fatalf("rows %+v", rows)
	}
}

func TestFingerprintRefusesABadServerName(t *testing.T) {
	f := newFixture(t, "", map[string]string{})
	_, err := f.svc.Fingerprint(context.Background(), f.actor, "10.0.0.32:6514", "bad name\x00")
	var pe *PolicyError
	if !errors.As(err, &pe) || !strings.Contains(pe.Reason, "server name") {
		t.Fatalf("bad SNI: %v", err)
	}
}

// failingRecorder refuses every row: nothing may be dialled or sent then.
type failingRecorder struct{}

func (failingRecorder) Record(context.Context, audit.Entry) (store.AuditRecord, error) {
	return store.AuditRecord{}, errors.New("audit store down")
}

func TestNoAuditRowNoNetwork(t *testing.T) {
	f := newFixture(t, "", nil)
	dialled := false
	svc, err := New(Config{Settings: f.set, Audit: failingRecorder{}, Switch: &audit.SwitchSink{},
		Dial:   func(context.Context, string, string) (net.Conn, error) { dialled = true; return nil, errors.New("x") },
		Policy: Policy{Allowed: config.DefaultGELFNetworks()}, Logger: quiet()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Fingerprint(context.Background(), f.actor, "10.0.0.32:6514", ""); err == nil || dialled {
		t.Fatalf("fetch without its started row: %v dialled=%v", err, dialled)
	}
	if r := svc.SendTest(context.Background(), f.actor); r.OK || r.Class != ClassAudit {
		t.Fatalf("test without its started row: %+v", r)
	}
}

// TestApplyWaitDoesNotBlockReaders: while Apply waits for a previous destination that is
// down, page reads (Applied) answer at once and shutdown is not held up.
func TestApplyWaitDoesNotBlockReaders(t *testing.T) {
	a := newReceiver(t, nil)
	f := newFixture(t, "", map[string]string{"10.0.0.30:12201": a.addr})
	f.svc.cfg.PreviousTimeout = 2 * time.Second
	f.run(t)
	f.update(t, enable("10.0.0.30:12201"), settings.PinOrigin{})
	a.waitAction(t, ActionApplied)
	f.route("10.0.0.30:12201", "127.0.0.1:1")
	f.update(t, map[string]string{config.KeyGELFServerName: "logs.example.test"}, settings.PinOrigin{}) // a down shipper
	f.svc.cfg.Switch.Enqueue(audit.Message{Short: "pending"})                                           // something to wait for
	done := make(chan struct{})
	go func() {
		_, _ = f.svc.Update(context.Background(), f.actor, f.set.Current().Rev,
			map[string]string{config.KeyGELFServerName: "other.example.test"}, settings.PinOrigin{})
		close(done)
	}()
	time.Sleep(100 * time.Millisecond) // Apply is now waiting
	start := time.Now()
	_ = f.svc.Applied()
	_ = f.svc.Stats()
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("readers waited %v behind Apply", d)
	}
	start = time.Now()
	f.stop()
	if d := time.Since(start); d > time.Second {
		t.Fatalf("shutdown waited %v behind Apply", d)
	}
	<-done
}

// TestCountersNeverDip: sampled throughout a swap, the sent total never goes down.
func TestCountersNeverDip(t *testing.T) {
	a, b := newReceiver(t, nil), newReceiver(t, nil)
	f := newFixture(t, "", map[string]string{"10.0.0.30:12201": a.addr, "10.0.0.31:12201": b.addr})
	f.run(t)
	f.update(t, enable("10.0.0.30:12201"), settings.PinOrigin{})
	a.waitAction(t, ActionApplied)
	waitFor(t, func() bool { return f.svc.Stats().Sent >= 1 })
	stop := make(chan struct{})
	dipped := make(chan uint64, 1)
	go func() {
		last := f.svc.Stats().Sent
		for {
			select {
			case <-stop:
				close(dipped)
				return
			default:
			}
			cur := f.svc.Stats().Sent
			if cur < last {
				dipped <- cur
				return
			}
			last = cur
		}
	}()
	f.update(t, map[string]string{config.KeyGELFAddress: "10.0.0.31:12201"}, settings.PinOrigin{})
	b.waitAction(t, ActionApplied)
	close(stop)
	if v, ok := <-dipped; ok {
		t.Fatalf("sent dipped to %d during the swap", v)
	}
}

// TestDialerSharesTheTimeout: a black-holed first answer gets only its share of the dial
// timeout, so a reachable second answer is still dialled in time (with a real dialer).
func TestDialerSharesTheTimeout(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			_ = c.Close()
		}
	}()
	r := &fakeResolver{answers: [][]netip.Addr{addrs("10.0.0.8", "10.0.0.9")}}
	base := func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == "10.0.0.8:12201" { // a black hole: answers nothing until the deadline
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	c, err := testPolicy(r).Dialer(base)(ctx, "tcp", "logs.example.test:12201")
	if err != nil {
		t.Fatalf("second answer not reached: %v", err)
	}
	_ = c.Close()
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("took %v: the first answer used the whole timeout", d)
	}
	if actx, acancel := attemptContext(context.Background(), 3); actx.Err() != nil {
		t.Fatal("no deadline: the attempt must not be cut")
	} else {
		acancel()
	}
}

// TestFingerprintEveryAnswer: a name is fetched at every address it resolves to; the
// same certificate everywhere is fine, different ones are refused (the shipper might
// use any answer), and so are more than MaxFetchAnswers addresses.
func TestFingerprintEveryAnswer(t *testing.T) {
	one := tlspintest.Issued(t)
	other := tlspintest.Issued(t)
	c1, c2 := one.TLS(), other.TLS()
	r1, r1b, r2 := newReceiver(t, &c1), newReceiver(t, &c1), newReceiver(t, &c2)
	f := newFixture(t, "", map[string]string{"10.0.0.41:6514": r1.addr, "10.0.0.42:6514": r1b.addr, "10.0.0.43:6514": r2.addr})
	res := &fakeResolver{answers: [][]netip.Addr{addrs("10.0.0.41", "10.0.0.42")}}
	f.svc.cfg.Policy.Resolver = res
	info, err := f.svc.Fingerprint(context.Background(), f.actor, "logs.example.test:6514", "gelf.example.test")
	if err != nil || info.SPKI != one.Leaf.SPKI() {
		t.Fatalf("same certificate: %+v %v", info, err)
	}
	res.answers, res.calls = [][]netip.Addr{addrs("10.0.0.41", "10.0.0.43")}, atomic.Int32{}
	var pe *PolicyError
	if _, err := f.svc.Fingerprint(context.Background(), f.actor, "logs.example.test:6514", "gelf.example.test"); !errors.As(err, &pe) || pe.Class != ClassMultiCert {
		t.Fatalf("different certificates: %v", err)
	}
	res.answers = [][]netip.Addr{addrs("10.0.0.41", "10.0.0.42", "10.0.0.44", "10.0.0.45", "10.0.0.46")}
	if _, err := f.svc.Fingerprint(context.Background(), f.actor, "logs.example.test:6514", ""); !errors.As(err, &pe) || pe.Class != ClassMultiCert {
		t.Fatalf("too many answers: %v", err)
	}
}

// TestTrustWithdrawnAfterTheWait: the replaced shipper keeps running while Apply waits
// for it, and may report a mismatch then. Disabling or moving the target must still end
// with no open alert, so the next target's first good connection reports no recovery.
func TestTrustWithdrawnAfterTheWait(t *testing.T) {
	for _, move := range []bool{true, false} {
		a, b := newReceiver(t, nil), newReceiver(t, nil)
		f := newFixture(t, "", map[string]string{"10.0.0.30:12201": a.addr, "10.0.0.31:12201": b.addr})
		f.run(t)
		f.update(t, enable("10.0.0.30:12201"), settings.PinOrigin{})
		a.waitAction(t, ActionApplied)
		// A goes down and a rebuilt shipper cannot reach it: Apply then waits PreviousTimeout.
		f.route("10.0.0.30:12201", "127.0.0.1:1")
		f.update(t, map[string]string{config.KeyGELFServerName: "logs.example.test"}, settings.PinOrigin{})
		old := f.svc.gen.Load()
		f.mu.Lock()
		f.onDial = func(addr string) { // the old shipper reports a mismatch while Apply waits
			if addr == "10.0.0.30:12201" {
				f.svc.pinMismatch(old, audit.ClassTLSPin)
			}
		}
		f.mu.Unlock()
		if move {
			f.update(t, map[string]string{config.KeyGELFAddress: "10.0.0.31:12201"}, settings.PinOrigin{})
		} else {
			f.update(t, map[string]string{config.KeyGELFEnabled: "off"}, settings.PinOrigin{})
			f.update(t, enable("10.0.0.31:12201"), settings.PinOrigin{})
		}
		b.waitAction(t, ActionApplied)
		waitFor(t, func() bool { return f.svc.Stats().Connected })
		f.stop()
		ev := f.trustEvents()
		if f.svc.trustOpen.Load() || len(ev) == 0 || ev[len(ev)-1] != TrustWithdrawn {
			t.Fatalf("move=%v: open=%v events %v", move, f.svc.trustOpen.Load(), ev)
		}
		for _, e := range ev {
			if e == TrustResolved {
				t.Fatalf("move=%v: spurious recovery in %v", move, ev)
			}
		}
	}
}

// TestFingerprintSlowAnswersInParallel: the answers of a name are fetched at the same
// time, each within its own dial and handshake bounds, so a name whose every answer is
// slow still fits the request's budget of one fetch (FetchTimeout), not one per answer.
func TestFingerprintSlowAnswersInParallel(t *testing.T) {
	issued := tlspintest.Issued(t)
	cert := issued.TLS()
	r1, r2, r3 := newReceiver(t, &cert), newReceiver(t, &cert), newReceiver(t, &cert)
	f := newFixture(t, "", map[string]string{"10.0.0.41:6514": r1.addr, "10.0.0.42:6514": r2.addr, "10.0.0.43:6514": r3.addr})
	f.svc.cfg.Policy.Resolver = &fakeResolver{answers: [][]netip.Addr{addrs("10.0.0.41", "10.0.0.42", "10.0.0.43")}}
	const delay = 300 * time.Millisecond
	var inFlight, peak atomic.Int32
	f.svc.cfg.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		select { // a slow network: every answer takes delay to connect
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return f.dial(ctx, network, addr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*delay+delay/2) // less than three in a row
	defer cancel()
	info, err := f.svc.Fingerprint(ctx, f.actor, "logs.example.test:6514", "gelf.example.test")
	if err != nil || info.SPKI != issued.Leaf.SPKI() {
		t.Fatalf("slow answers: %+v %v", info, err)
	}
	if p := peak.Load(); p != 3 {
		t.Fatalf("%d answers fetched at once, want 3", p)
	}
	if FetchTimeout < 2*tofu.DefaultDialTimeout+tofu.DefaultHandshakeTimeout {
		t.Fatalf("FetchTimeout %v leaves no time to resolve, dial and handshake", FetchTimeout)
	}
}
