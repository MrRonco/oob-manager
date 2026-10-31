package console

import (
	"context"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"oob-manager/internal/config"
	"oob-manager/internal/console/rfbtest"
	"oob-manager/internal/secrets"
)

func netPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	go func() { _, _ = readAll(b) }()
	return a, b
}

// refusedDial answers like a closed port, without a real one: a port closed by the test
// can be taken by another listener before it is dialled (review C-L1).
func refusedDial(context.Context, string, string) (net.Conn, error) {
	return nil, &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}
}

func TestBannerProbeStates(t *testing.T) {
	plain := rfbtest.New(t, rfbtest.Options{})
	tlsFake := rfbtest.New(t, rfbtest.Options{TLS: true})
	wrongPin := strings.Repeat("ab", 32)
	cases := map[string]struct {
		addr string
		tls  bool
		pin  string
		want ProbeState
	}{
		"plain ok":      {plain.Addr(), false, "", ProbeOK},
		"tls ok":        {tlsFake.Addr(), true, tlsFake.PinSHA256(), ProbeOK},
		"pin mismatch":  {tlsFake.Addr(), true, wrongPin, ProbePin},
		"tls to plain":  {plain.Addr(), true, wrongPin, ProbeTLS},
		"nothing there": {"", false, "", ProbeRefused},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			tg, err := TargetFor(serverCfg(config.KindIDRAC9, tc.tls, tc.pin), secrets.New("x"))
			if err != nil {
				t.Fatal(err)
			}
			dial := redirect(tc.addr)
			if tc.addr == "" {
				dial = refusedDial
			}
			p := probeBanner(context.Background(), dial, tg, time.Now())
			if p.State != tc.want {
				t.Fatalf("state = %q, want %q", p.State, tc.want)
			}
			if tc.want == ProbeOK && p.Version != 8 {
				t.Errorf("version = %d", p.Version)
			}
		})
	}
	if plain.Stats().AuthOK+plain.Stats().AuthFailures != 0 {
		t.Error("a banner probe must never attempt authentication")
	}
}

func TestBannerProbeNotRFB(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			_, _ = c.Write([]byte("SSH-2.0-x\r\n\r\n"))
			_ = c.Close()
		}
	}()
	tg, _ := TargetFor(serverCfg(config.KindIDRAC9, false, ""), secrets.New("x"))
	if p := probeBanner(context.Background(), redirect(ln.Addr().String()), tg, time.Now()); p.State != ProbeNotRFB {
		t.Fatalf("state = %q", p.State)
	}
}

func TestProbeScheduleAndTLSConsole(t *testing.T) {
	fake := rfbtest.New(t, rfbtest.Options{TLS: true})
	clk := newClock()
	tg, err := TargetFor(serverCfg(config.KindIDRAC9, true, fake.PinSHA256()), secrets.New(rfbtest.Password))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := New(Config{Targets: []Target{tg}, Audit: &fakeAudit{}, Dial: redirect(fake.Addr()), Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	waitUntil(t, func() bool { return svc.Status("r1").Probe.State == ProbeOK })
	cancel()
	<-done
	if svc.probeDue("r1") {
		t.Error("fresh ok probe should not be due")
	}
	clk.add(DefaultProbeEvery)
	if !svc.probeDue("r1") {
		t.Error("ok probe older than the slow tier should be due")
	}
	svc.recordProbe("r1", Probe{State: ProbeRefused, CheckedAt: clk.now()})
	clk.add(DefaultProbeRetry)
	if !svc.probeDue("r1") {
		t.Error("failed probe should be retried after ProbeRetry")
	}
	if !svc.Status("r1").TLS {
		t.Error("TLS flag lost")
	}
}

func TestTargetForAndNew(t *testing.T) {
	s := serverCfg(config.KindIDRAC9, true, "zz")
	if _, err := TargetFor(s, secrets.New("x")); err == nil {
		t.Error("bad pin accepted")
	}
	s.Console.Graphical = config.GraphicalNone
	if _, err := TargetFor(s, secrets.New("x")); err == nil {
		t.Error("server without vnc accepted")
	}
	if _, err := New(Config{}); err == nil {
		t.Error("missing audit accepted")
	}
	tg, _ := TargetFor(serverCfg(config.KindIDRAC9, false, ""), secrets.New("x"))
	if _, err := New(Config{Audit: &fakeAudit{}, Targets: []Target{tg, tg}}); err == nil {
		t.Error("duplicate target accepted")
	}
}

func TestPasswordWarnings(t *testing.T) {
	cases := map[string]struct {
		kind config.BMCKind
		pw   string
		n    int
	}{
		"good idrac9":    {config.KindIDRAC9, "Ab1!xyz9", 0},
		"too long":       {config.KindIDRAC8, "abcdefghij", 1},
		"too short":      {config.KindIDRAC8, "abc", 1},
		"idrac9 simple":  {config.KindIDRAC9, "abcdefgh", 1},
		"idrac8 simple":  {config.KindIDRAC8, "abcdefgh", 0},
		"missing":        {config.KindIDRAC9, "", 0},
		"long and plain": {config.KindIDRAC9, "abcdefghijk", 2},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			w := PasswordWarnings(tc.kind, secrets.New(tc.pw))
			if len(w) != tc.n {
				t.Fatalf("warnings = %v", w)
			}
			for _, msg := range w {
				if tc.pw != "" && strings.Contains(msg, tc.pw) {
					t.Error("warning leaks the password")
				}
			}
		})
	}
}
