package console

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/bmc/bmcssh/sshtest"
	"oob-manager/internal/config"
	"oob-manager/internal/secrets"
)

// fakePeer is the browser end of a serial console: messages pushed with send are read
// by the service; everything the service writes is recorded.
type fakePeer struct {
	in     chan peerMsg
	mu     sync.Mutex
	out    []peerMsg
	closed bool
}

type peerMsg struct {
	typ MessageType
	p   []byte
}

func newPeer() *fakePeer { return &fakePeer{in: make(chan peerMsg, 64)} }

func (f *fakePeer) Read(ctx context.Context) (MessageType, []byte, error) {
	select {
	case m, ok := <-f.in:
		if !ok {
			return 0, nil, io.EOF
		}
		return m.typ, m.p, nil
	case <-ctx.Done():
		return 0, nil, ctx.Err()
	}
}

func (f *fakePeer) Write(_ context.Context, typ MessageType, p []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return io.ErrClosedPipe
	}
	f.out = append(f.out, peerMsg{typ, slices.Clone(p)})
	return nil
}

func (f *fakePeer) send(typ MessageType, p string) { f.in <- peerMsg{typ, []byte(p)} }

// output is every binary byte the browser received.
func (f *fakePeer) output() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b bytes.Buffer
	for _, m := range f.out {
		if m.typ == MessageBinary {
			b.Write(m.p)
		}
	}
	return b.String()
}

// all is every byte the browser received, binary and text.
func (f *fakePeer) all() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	var b bytes.Buffer
	for _, m := range f.out {
		b.Write(m.p)
	}
	return b.Bytes()
}

func (f *fakePeer) statuses() []statusMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []statusMsg
	for _, m := range f.out {
		if m.typ == MessageText {
			var s statusMsg
			_ = json.Unmarshal(m.p, &s)
			out = append(out, s)
		}
	}
	return out
}

func (f *fakePeer) status(typ string) (statusMsg, bool) {
	for _, s := range f.statuses() {
		if s.Type == typ {
			return s, true
		}
	}
	return statusMsg{}, false
}

type serialHarness struct {
	t     *testing.T
	fake  *sshtest.Server
	svc   *SerialService
	audit *fakeAudit
	sess  [32]byte
}

func serialServer(kind config.BMCKind, hostKey string) config.Server {
	s := config.Server{ID: "r1", Name: "Server one", BMC: config.BMCConfig{Address: "192.0.2.10", Kind: kind},
		SSHHostKey: hostKey}
	s.Console.Serial = config.SerialBMCSSH
	s.Console.SSH = config.SSHConfig{Port: 22, Quirks: []config.SSHQuirk{}}
	return s
}

func operator() secrets.Credential {
	return secrets.Credential{Username: sshtest.User, Password: secrets.New(sshtest.Password)}
}

func newSerialHarness(t *testing.T, opts sshtest.Options, mod func(*SerialConfig, *config.Server)) *serialHarness {
	t.Helper()
	fake := sshtest.New(t, opts)
	srv := serialServer(config.KindIDRAC9, fake.HostKeyLine())
	fa := &fakeAudit{}
	cfg := SerialConfig{Audit: fa, Dial: redirect(fake.Addr()), IdleTimeout: time.Minute, MaxSession: time.Hour,
		CheckEvery: 20 * time.Millisecond}
	if mod != nil {
		mod(&cfg, &srv)
	}
	tg, err := SerialTargetFor(srv, operator())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Targets == nil {
		cfg.Targets = []SerialTarget{tg}
	}
	svc, err := NewSerial(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Shutdown)
	return &serialHarness{t: t, fake: fake, svc: svc, audit: fa, sess: SessionHash("cookie")}
}

func (h *serialHarness) grant(takeover bool) Grant {
	return Grant{ServerID: "r1", UserID: "u1", Username: "admin", Role: "admin", SrcIP: "192.0.2.99",
		Session: h.sess, Takeover: takeover}
}

type serialRun struct {
	peer *fakePeer
	done chan error
}

func (h *serialHarness) open(takeover bool, check Watchdog) *serialRun {
	h.t.Helper()
	ticket, err := h.svc.Issue(h.grant(takeover))
	if err != nil {
		h.t.Fatal(err)
	}
	return h.openTicket(ticket, check)
}

func (h *serialHarness) openTicket(ticket string, check Watchdog) *serialRun {
	r := &serialRun{peer: newPeer(), done: make(chan error, 1)}
	go func() { r.done <- h.svc.ServeSerial(context.Background(), ticket, "r1", h.sess, r.peer, check) }()
	return r
}

func (r *serialRun) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("serial session did not end")
		return nil
	}
}

func (r *serialRun) endReason(t *testing.T) string {
	t.Helper()
	waitUntil(t, func() bool { _, ok := r.peer.status("end"); return ok })
	s, _ := r.peer.status("end")
	return s.Reason
}

func (r *serialRun) waitOutput(t *testing.T, want string) {
	t.Helper()
	waitUntil(t, func() bool { return strings.Contains(r.peer.output(), want) })
}
