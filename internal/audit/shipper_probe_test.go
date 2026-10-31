package audit

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/tlspin/tlspintest"
)

// TestProbeReportsTheFailureClass: a TLS handshake failure and a write failure are
// reported as such, not as "dial".
func TestProbeReportsTheFailureClass(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ln, _ := listen(t) // plain TCP: a TLS client fails the handshake
	tlsCfg := pinnedConfig(t, ln.Addr().String(), tlspintest.SelfSigned(t).Leaf.SPKI())
	tlsCfg.WriteTimeout = 300 * time.Millisecond
	tlsCfg.DialTimeout = 300 * time.Millisecond
	if c := ErrorClassOf(runShipper(t, tlsCfg).Probe(ctx, Message{Short: "x"})); c != ClassTLS && c != ClassTimeout {
		t.Fatalf("TLS against plain TCP: %q", c)
	}
	// Write failure: the connection is closed under the writer.
	client, server := net.Pipe()
	_ = server.Close()
	wcfg := fastConfig("192.0.2.30:12201")
	wcfg.Dial = func(context.Context, string, string) (net.Conn, error) { return client, nil }
	if c := ErrorClassOf(runShipper(t, wcfg).Probe(ctx, Message{Short: "x"})); c != ClassWrite {
		t.Fatalf("write failure: %q", c)
	}
}

// TestProbeBypassesThePinPause: after a mismatch the worker waits PinPause before it
// dials again, but Send test dials now: still pinned (nothing written to a wrong
// certificate); once the right certificate is back, a good probe ends the pause.
func TestProbeBypassesThePinPause(t *testing.T) {
	issued := tlspintest.Issued(t)
	var good atomic.Bool
	wrong := newTLSReceiver(t, issued.LeafOnly())
	right := newTLSReceiver(t, issued.TLS())
	cfg := pinnedConfig(t, "gelf.example.test:12201", issued.CA.SPKI())
	cfg.Dial = func(ctx context.Context, n, _ string) (net.Conn, error) {
		target := wrong.addr
		if good.Load() {
			target = right.addr
		}
		return (&net.Dialer{}).DialContext(ctx, n, target)
	}
	s := runShipper(t, cfg) // default pause: 5 minutes
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if c := ErrorClassOf(s.Probe(ctx, Message{Short: "first"})); c != ClassTLSPin {
		t.Fatalf("wrong certificate: %q", c)
	}
	if c := ErrorClassOf(s.Probe(ctx, Message{Short: "again"})); c != ClassTLSPin {
		t.Fatalf("a probe during the pause did not dial: %q", c)
	}
	if n := wrong.raw.Load(); n != 0 {
		t.Fatalf("%d bytes written to the wrong server", n)
	}
	good.Store(true)
	if err := s.Probe(ctx, Message{Short: "probe after renewal"}); err != nil {
		t.Fatalf("good probe: %v", err)
	}
	expectFrame(t, right.got, "probe after renewal")
	if st := s.Stats(); st.PinMismatch {
		t.Fatal("a good probe left the mismatch set")
	}
	s.Enqueue(Message{Short: "queued row", Timestamp: t0}) // the pause is over: rows flow
	expectFrame(t, right.got, "queued row")
}

func TestShipperExpiredCertificateUnderIssuerPin(t *testing.T) {
	p := tlspintest.IssuedExpired(t)
	r := newTLSReceiver(t, p.TLS())
	cfg := pinnedConfig(t, r.addr, p.CA.SPKI())
	var classes atomic.Value
	cfg.OnPinMismatch = func(class string) { classes.Store(class) }
	s := runShipper(t, cfg)
	s.Enqueue(Message{Short: "x"})
	waitFor(t, func() bool { c, _ := classes.Load().(string); return c == ClassTLSExpired })
	if st := s.Stats(); !st.PinMismatch || st.LastError != ClassTLSExpired {
		t.Fatalf("stats %+v", st)
	}
}

// TestEnqueueAfterRunIsCounted: a finished shipper refuses and counts; a frame held
// for a retry when Run is cancelled goes to flush instead of being dropped.
func TestEnqueueAfterRunIsCounted(t *testing.T) {
	s, err := NewShipper(fastConfig("192.0.2.30:12201"), quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.Run(ctx)
	if s.Enqueue(Message{Short: "late"}) || s.Stats().Dropped != 1 {
		t.Fatalf("late enqueue accepted: %+v", s.Stats())
	}
}

func TestHeldFrameIsFlushed(t *testing.T) {
	ln, got := listen(t)
	var up atomic.Bool
	cfg := fastConfig(ln.Addr().String())
	cfg.BackoffMin, cfg.BackoffMax = time.Hour, time.Hour // the worker holds the frame
	cfg.Dial = func(ctx context.Context, n, a string) (net.Conn, error) {
		if !up.Load() {
			return nil, errors.New("refused")
		}
		return (&net.Dialer{}).DialContext(ctx, n, a)
	}
	s, err := NewShipper(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	s.Enqueue(Message{Short: "held across shutdown", Timestamp: t0})
	waitFor(t, func() bool { return s.Stats().LastError == ClassDial && s.holding.Load() })
	up.Store(true)
	cancel()
	<-done
	select {
	case m := <-got:
		if msg, _ := m["short_message"].(string); !strings.Contains(msg, "held across shutdown") {
			t.Fatalf("frame %v", m)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("held frame not flushed; stats %+v", s.Stats())
	}
	if s.Stats().Dropped != 0 {
		t.Fatalf("dropped %d", s.Stats().Dropped)
	}
}

func TestWaitSent(t *testing.T) {
	ln, got := listen(t)
	s := runShipper(t, fastConfig(ln.Addr().String()))
	for range 5 {
		s.Enqueue(Message{Short: "row", Timestamp: t0})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if !s.WaitSent(ctx) {
		t.Fatal("not sent")
	}
	for range 5 {
		expectGELF(t, got)
	}
	down := fastConfig("192.0.2.30:12201")
	down.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	sd := runShipper(t, down)
	sd.Enqueue(Message{Short: "stuck"})
	short, cancelShort := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelShort()
	if sd.WaitSent(short) {
		t.Fatal("WaitSent reported a frame that was never written")
	}
}

// TestPauseReasonSurvivesAFailedProbe: a probe that cannot even connect during a pin
// pause records its own last error but leaves the pause and its reason alone.
func TestPauseReasonSurvivesAFailedProbe(t *testing.T) {
	issued := tlspintest.Issued(t)
	wrong := newTLSReceiver(t, issued.LeafOnly())
	var down atomic.Bool
	cfg := pinnedConfig(t, "gelf.example.test:12201", issued.CA.SPKI())
	cfg.Dial = func(ctx context.Context, n, _ string) (net.Conn, error) {
		if down.Load() {
			return nil, errors.New("refused")
		}
		return (&net.Dialer{}).DialContext(ctx, n, wrong.addr)
	}
	s := runShipper(t, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if c := ErrorClassOf(s.Probe(ctx, Message{Short: "x"})); c != ClassTLSPin {
		t.Fatalf("first probe %q", c)
	}
	down.Store(true)
	if c := ErrorClassOf(s.Probe(ctx, Message{Short: "y"})); c != ClassDial {
		t.Fatalf("probe while unreachable %q", c)
	}
	st := s.Stats()
	if !st.PinMismatch || st.PauseReason != ClassTLSPin || st.LastError != ClassDial {
		t.Fatalf("stats %+v", st)
	}
}
