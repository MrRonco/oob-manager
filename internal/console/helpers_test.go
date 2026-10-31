package console

import (
	"bytes"
	"context"
	"errors"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/console/rfb"
	"oob-manager/internal/console/rfbtest"
	"oob-manager/internal/secrets"
	"oob-manager/internal/store"
)

type fakeAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
	fail    bool
}

func (f *fakeAudit) Record(_ context.Context, e audit.Entry) (store.AuditRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return store.AuditRecord{}, errors.New("audit down")
	}
	f.entries = append(f.entries, e)
	return store.AuditRecord{}, nil
}

func (f *fakeAudit) byAction(action string) []audit.Entry {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []audit.Entry
	for _, e := range f.entries {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}

func (f *fakeAudit) waitFor(t *testing.T, action string, n int) []audit.Entry {
	t.Helper()
	waitUntil(t, func() bool { return len(f.byAction(action)) >= n })
	return f.byAction(action)
}

func waitUntil(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// recConn records every byte that crosses the "browser" connection in either direction.
type recConn struct {
	net.Conn
	mu  sync.Mutex
	all bytes.Buffer
}

func (r *recConn) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.mu.Lock()
	r.all.Write(p[:n])
	r.mu.Unlock()
	return n, err
}

func (r *recConn) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.all.Write(p)
	r.mu.Unlock()
	return r.Conn.Write(p)
}

func (r *recConn) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.all.Bytes())
}

// redirect sends every dial to the fake server, whatever the configured address.
func redirect(addr string) DialFunc {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
}

func serverCfg(kind config.BMCKind, tls bool, pin string) config.Server {
	s := config.Server{ID: "r1", Name: "Server one", BMC: config.BMCConfig{Address: "192.0.2.10", Kind: kind},
		TLSPinSHA256: pin}
	s.Console.Graphical = config.GraphicalVNC
	s.Console.VNC = config.VNCConfig{Port: 5901, TLS: &tls}
	if kind == config.KindIDRAC8 {
		s.Console.VNC.Quirks = []config.VNCQuirk{config.QuirkIDRAC8SafeEncodings, config.QuirkIDRAC8LowColour}
	}
	return s
}

type harness struct {
	t     *testing.T
	fake  *rfbtest.Server
	svc   *Service
	audit *fakeAudit
	sess  [32]byte
}

func newHarness(t *testing.T, kind config.BMCKind, mod func(*Config)) *harness {
	t.Helper()
	fake := rfbtest.New(t, rfbtest.Options{})
	tg, err := TargetFor(serverCfg(kind, false, ""), secrets.New(rfbtest.Password))
	if err != nil {
		t.Fatal(err)
	}
	fa := &fakeAudit{}
	cfg := Config{Targets: []Target{tg}, Audit: fa, Dial: redirect(fake.Addr()),
		IdleTimeout: time.Minute, MaxSession: time.Hour, CheckEvery: 20 * time.Millisecond}
	if mod != nil {
		mod(&cfg)
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Shutdown)
	return &harness{t: t, fake: fake, svc: svc, audit: fa, sess: SessionHash("cookie")}
}

func (h *harness) grant(takeover bool) Grant {
	return Grant{ServerID: "r1", UserID: "u1", Username: "admin", Role: "admin", SrcIP: "192.0.2.99",
		Session: h.sess, Takeover: takeover}
}

// browserSession is the browser side of one console: a pipe whose other end Serve owns.
type browserSession struct {
	conn *recConn
	done chan error
	init rfb.ServerInit
}

func (h *harness) open(takeover bool, check Watchdog) *browserSession {
	h.t.Helper()
	ticket, err := h.svc.Issue(h.grant(takeover))
	if err != nil {
		h.t.Fatal(err)
	}
	return h.openTicket(ticket, check)
}

func (h *harness) openTicket(ticket string, check Watchdog) *browserSession {
	h.t.Helper()
	appEnd, browserEnd := net.Pipe()
	b := &browserSession{conn: &recConn{Conn: browserEnd}, done: make(chan error, 1)}
	go func() { b.done <- h.svc.Serve(context.Background(), ticket, "r1", h.sess, appEnd, check) }()
	_ = b.conn.SetDeadline(time.Now().Add(5 * time.Second))
	si, err := rfb.ClientHandshake(b.conn, nil) // the browser has no password: None only
	if err != nil {
		h.t.Fatalf("browser handshake: %v", err)
	}
	_ = b.conn.SetDeadline(time.Time{})
	b.init = si
	go func() { _, _ = readAll(b.conn) }() // drain frames
	return b
}

func readAll(c net.Conn) (int, error) {
	buf := make([]byte, 64<<10)
	total := 0
	for {
		n, err := c.Read(buf)
		total += n
		if err != nil {
			return total, err
		}
	}
}
