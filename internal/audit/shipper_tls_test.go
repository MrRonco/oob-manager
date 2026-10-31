package audit

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/tlspin"
	"oob-manager/internal/tlspin/tlspintest"
)

// tlsReceiver is a GELF TLS input: frames arrive on got; raw counts the application
// bytes received on connections whose handshake completed.
type tlsReceiver struct {
	addr string
	got  chan string
	raw  atomic.Int64
}

func newTLSReceiver(t *testing.T, cert tls.Certificate) *tlsReceiver {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	r := &tlsReceiver{addr: ln.Addr().String(), got: make(chan string, 100)}
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go r.serve(c)
		}
	}()
	return r
}

func (r *tlsReceiver) serve(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		frame, err := br.ReadBytes(0)
		r.raw.Add(int64(len(frame)))
		if err != nil {
			return
		}
		r.got <- string(frame[:len(frame)-1])
	}
}

func pinnedConfig(t *testing.T, addr, pin string) ShipperConfig {
	t.Helper()
	p, err := tlspin.ParseHex(pin)
	if err != nil {
		t.Fatal(err)
	}
	cfg := fastConfig(addr)
	cfg.TLS = tlspin.IssuerConfig(p, "gelf.example.test", ErrPinMismatch)
	return cfg
}

func runShipper(t *testing.T, cfg ShipperConfig) *Shipper {
	t.Helper()
	s, err := NewShipper(cfg, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return s
}

func expectFrame(t *testing.T, got <-chan string, sub string) {
	t.Helper()
	select {
	case f := <-got:
		if !strings.Contains(f, sub) {
			t.Fatalf("frame %s does not contain %q", f, sub)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("no frame containing %q", sub)
	}
}

func TestShipperTLSLeafAndIssuerPins(t *testing.T) {
	self := tlspintest.SelfSigned(t)
	issued := tlspintest.Issued(t)
	cases := []struct {
		name string
		cert tls.Certificate
		pin  string
	}{
		{"self-signed leaf", self.TLS(), self.Leaf.SPKI()},
		{"issued leaf", issued.TLS(), issued.Leaf.SPKI()},
		{"issuer with chain", issued.TLS(), issued.CA.SPKI()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newTLSReceiver(t, tc.cert)
			s := runShipper(t, pinnedConfig(t, r.addr, tc.pin))
			s.Enqueue(Message{Short: "over tls", Timestamp: t0})
			expectFrame(t, r.got, "over tls")
			waitFor(t, func() bool { st := s.Stats(); return st.Connected && st.TLS && st.Sent == 1 })
			st := s.Stats()
			if !st.Active || st.PinMismatch || st.LastSuccess.IsZero() || st.ConnectedSince.IsZero() || st.LastError != "" {
				t.Fatalf("stats %+v", st)
			}
		})
	}
}

// TestShipperTLSWrongPin: the handshake is refused before any frame is written, the
// class is tls_pin, the shipper pauses dialling (queueing meanwhile), reports it once,
// and recovers after the pause when the right certificate is back.
func TestShipperTLSWrongPin(t *testing.T) {
	issued := tlspintest.Issued(t)
	r := newTLSReceiver(t, issued.LeafOnly()) // no chain: an issuer pin cannot match
	cfg := pinnedConfig(t, r.addr, issued.CA.SPKI())
	var now atomic.Int64 // a fake clock: the pause is measured on it
	now.Store(t0.UnixNano())
	cfg.Now = func() time.Time { return time.Unix(0, now.Load()) }
	var mismatches, recoveries, connects atomic.Int32
	cfg.OnPinMismatch = func(class string) {
		if class == ClassTLSPin {
			mismatches.Add(1)
		}
	}
	cfg.OnRecovered = func() { recoveries.Add(1) }
	cfg.OnConnected = func() { connects.Add(1) }
	var dials atomic.Int32
	base := (&net.Dialer{}).DialContext
	cfg.Dial = func(ctx context.Context, n, a string) (net.Conn, error) { dials.Add(1); return base(ctx, n, a) }
	s := runShipper(t, cfg)
	for range 3 {
		s.Enqueue(Message{Short: "secret-free row", Timestamp: t0})
	}
	waitFor(t, func() bool { return s.Stats().PinMismatch && s.Stats().LastError == ClassTLSPin })
	if mismatches.Load() != 1 {
		t.Fatalf("mismatch reported %d times", mismatches.Load())
	}
	before := dials.Load()
	time.Sleep(60 * time.Millisecond) // the worker retries every few ms, but the clock has not moved
	if dials.Load() != before {
		t.Fatalf("dialled %d times during the pause", dials.Load()-before)
	}
	if n := r.raw.Load(); n != 0 {
		t.Fatalf("receiver got %d application bytes", n)
	}
	if st := s.Stats(); st.Queued < 2 || st.Connected || st.Sent != 0 {
		t.Fatalf("stats while paused %+v", st)
	}
	now.Add(int64(DefaultPinPause + time.Second)) // the pause ends: it dials (and fails) again
	waitFor(t, func() bool { return dials.Load() > before })
	if mismatches.Load() != 1 {
		t.Fatalf("one episode reported %d times", mismatches.Load())
	}
	select {
	case f := <-r.got:
		t.Fatalf("frame delivered to an unpinned server: %s", f)
	default:
	}
	if recoveries.Load() != 0 || connects.Load() != 0 {
		t.Fatal("recovered or connected without a good handshake")
	}
}

func TestShipperTLSRecoversAfterPause(t *testing.T) {
	issued := tlspintest.Issued(t)
	var good atomic.Bool
	wrong := newTLSReceiver(t, issued.LeafOnly())
	right := newTLSReceiver(t, issued.TLS())
	cfg := pinnedConfig(t, "gelf.example.test:12201", issued.CA.SPKI())
	cfg.PinPause = 50 * time.Millisecond
	var recoveries atomic.Int32
	cfg.OnRecovered = func() { recoveries.Add(1) }
	cfg.Dial = func(ctx context.Context, n, _ string) (net.Conn, error) {
		target := wrong.addr
		if good.Load() {
			target = right.addr
		}
		return (&net.Dialer{}).DialContext(ctx, n, target)
	}
	s := runShipper(t, cfg)
	s.Enqueue(Message{Short: "queued while paused", Timestamp: t0})
	waitFor(t, func() bool { return s.Stats().PinMismatch })
	good.Store(true)
	expectFrame(t, right.got, "queued while paused")
	waitFor(t, func() bool { return !s.Stats().PinMismatch && recoveries.Load() == 1 })
	if s.Stats().Reconnects != 0 {
		t.Fatalf("reconnects %d (the first good connection is not a reconnect)", s.Stats().Reconnects)
	}
}

// TestShipperTLSAgainstPlainTCP: a plain-TCP GELF input with tls configured fails the
// handshake (class tls) and the frame is never sent in plaintext (no fallback).
func TestShipperTLSAgainstPlainTCP(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	var seen strings.Builder
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(time.Second))
				b, _ := io.ReadAll(c)
				mu.Lock()
				seen.Write(b)
				mu.Unlock()
			}()
		}
	}()
	s := runShipper(t, pinnedConfig(t, ln.Addr().String(), tlspintest.SelfSigned(t).Leaf.SPKI()))
	s.Enqueue(Message{Short: "never in plaintext", Timestamp: t0})
	waitFor(t, func() bool { c := s.Stats().LastError; return c == ClassTLS || c == ClassTimeout })
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(seen.String(), "never in plaintext") {
		t.Fatal("the frame was sent without TLS")
	}
}

func TestShipperReconnectCounter(t *testing.T) {
	ln, got := listen(t)
	var fail atomic.Bool
	cfg := fastConfig(ln.Addr().String())
	base := (&net.Dialer{}).DialContext
	var conns []net.Conn
	var mu sync.Mutex
	cfg.Dial = func(ctx context.Context, n, a string) (net.Conn, error) {
		if fail.Load() {
			return nil, errors.New("refused")
		}
		c, err := base(ctx, n, a)
		mu.Lock()
		conns = append(conns, c)
		mu.Unlock()
		return c, err
	}
	s := runShipper(t, cfg)
	s.Enqueue(Message{Short: "one", Timestamp: t0})
	expectGELF(t, got)
	mu.Lock()
	_ = conns[0].Close() // the next write fails, the shipper reconnects
	mu.Unlock()
	waitFor(t, func() bool {
		s.Enqueue(Message{Short: "two", Timestamp: t0})
		return s.Stats().Reconnects >= 1
	})
	if s.Stats().LastSuccess.IsZero() {
		t.Fatal("no last success")
	}
}

func expectGELF(t *testing.T, got <-chan map[string]any) {
	t.Helper()
	select {
	case <-got:
	case <-time.After(3 * time.Second):
		t.Fatal("no frame")
	}
}

func TestShipperProbe(t *testing.T) {
	ln, got := listen(t)
	s := runShipper(t, fastConfig(ln.Addr().String()))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.Probe(ctx, Message{Short: "probe frame", Timestamp: t0}); err != nil {
		t.Fatalf("probe: %v", err)
	}
	expectGELF(t, got)

	down := fastConfig("127.0.0.1:1")
	down.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	sd := runShipper(t, down)
	err := sd.Probe(ctx, Message{Short: "x"})
	if ErrorClassOf(err) != ClassDial {
		t.Fatalf("probe of a down server: %v (%s)", err, ErrorClassOf(err))
	}
	// A shipper that is not running answers within the caller's deadline.
	idle, _ := NewShipper(fastConfig("127.0.0.1:1"), quietLogger())
	short, cancelShort := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelShort()
	if c := ErrorClassOf(idle.Probe(short, Message{})); c != ClassTimeout {
		t.Fatalf("idle probe class %q", c)
	}
	if c := ErrorClassOf(idle.Probe(context.Background(), Message{Short: strings.Repeat("x", MaxMessageBytes)})); c != ClassEncode {
		t.Fatalf("oversized probe class %q", c)
	}
}

// TestShipperProbeDuringBackoff: a probe is answered while the worker waits to retry a
// held frame (the server is down), instead of waiting for the backoff.
func TestShipperProbeDuringBackoff(t *testing.T) {
	cfg := fastConfig("127.0.0.1:1")
	cfg.BackoffMin, cfg.BackoffMax = time.Second, time.Second
	cfg.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	s := runShipper(t, cfg)
	s.Enqueue(Message{Short: "held"})
	waitFor(t, func() bool { return s.Stats().LastError == ClassDial })
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if c := ErrorClassOf(s.Probe(ctx, Message{Short: "probe"})); c != ClassDial {
		t.Fatalf("probe during backoff: %q", c)
	}
}

func TestErrorClassOf(t *testing.T) {
	cases := map[error]string{
		nil:                      "",
		ErrPinMismatch:           ClassTLSPin,
		errors.New("x"):          ClassDial,
		&ShipError{Class: "x"}:   "x",
		context.DeadlineExceeded: ClassTimeout,
	}
	for err, want := range cases {
		if got := ErrorClassOf(err); got != want {
			t.Errorf("%v: %q, want %q", err, got, want)
		}
	}
	if (&ShipError{Class: ClassPolicy}).Error() == "" {
		t.Fatal("empty error text")
	}
}
