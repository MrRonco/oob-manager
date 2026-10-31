package console

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc/bmcssh/sshtest"
	"oob-manager/internal/config"
	"oob-manager/internal/secrets"
)

func TestSerialEchoControlsAndAudit(t *testing.T) {
	h := newSerialHarness(t, sshtest.Options{}, nil)
	r := h.open(false, nil)
	waitUntil(t, func() bool { _, ok := r.peer.status("connected"); return ok })
	r.waitOutput(t, "Connected to Serial Device 2")
	r.peer.send(MessageBinary, "root\x1c\r")
	r.waitOutput(t, "root\r")
	r.peer.send(MessageText, `{"type":"resize","cols":132,"rows":43}`)
	r.peer.send(MessageText, `{"type":"break"}`)
	r.waitOutput(t, "<BREAK>")
	if st := h.svc.Status("r1"); !st.InUse || st.Active.Username != "admin" || st.Last.Class != "" || st.Last.At.IsZero() {
		t.Errorf("status while open = %+v", st)
	}
	r.peer.send(MessageText, `{"type":"quit"}`)
	if reason := r.endReason(t); reason != "quit" {
		t.Errorf("end reason %q", reason)
	}
	if err := r.wait(t); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, func() bool { return h.fake.Active() == 0 })
	in := h.fake.Input()
	if !bytes.Equal(in, []byte("root\r\x1c")) {
		t.Errorf("BMC input %q: the typed quit key must be dropped, the Quit control must send it", in)
	}
	types := h.fake.RequestTypes()
	if !slices.Equal(types, []string{"pty-req", "exec", "window-change", "break"}) {
		t.Errorf("BMC requests %v", types)
	}
	if bytes.Contains(r.peer.all(), []byte(sshtest.Password)) {
		t.Error("the operator password reached the browser")
	}
	start := h.audit.waitFor(t, "console.serial.start", 1)[0]
	stop := h.audit.waitFor(t, "console.serial.stop", 1)[0]
	if start.Result != audit.ResultStarted || stop.CorrelationID != start.CorrelationID || stop.Params["reason"] != "quit" ||
		stop.Params["dropped_bytes"] != int64(1) || stop.Params["breaks"] != int64(1) || stop.Params["bytes_to_bmc"] != int64(5) {
		t.Errorf("audit start %+v stop %+v", start, stop)
	}
	if h.svc.Status("r1").InUse {
		t.Error("still in use after quit")
	}
}

func TestSerialTicketReplayAndBinding(t *testing.T) {
	h := newSerialHarness(t, sshtest.Options{}, nil)
	ticket, err := h.svc.Issue(h.grant(false))
	if err != nil {
		t.Fatal(err)
	}
	other := newPeer()
	if err := h.svc.ServeSerial(context.Background(), ticket, "r1", SessionHash("other cookie"), other, nil); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("ticket from another session: %v", err)
	}
	// Any redeem attempt burns the ticket.
	r := h.openTicket(ticket, nil)
	if err := r.wait(t); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("replayed ticket: %v", err)
	}
	if h.fake.AuthAttempts() != 0 || len(other.all()) != 0 {
		t.Error("an invalid ticket reached the BMC or the browser")
	}
	// A serial ticket never opens a graphical console.
	t2, _ := h.svc.Issue(h.grant(false))
	vnc := newHarness(t, config.KindIDRAC9, nil)
	if _, err := vnc.svc.tickets.redeem(t2, "r1", h.sess); !errors.Is(err, ErrTicketInvalid) {
		t.Errorf("serial ticket redeemed by the graphical console: %v", err)
	}
}

func TestSerialOneSessionAndTakeover(t *testing.T) {
	h := newSerialHarness(t, sshtest.Options{}, nil)
	first := h.open(false, nil)
	first.waitOutput(t, "Serial Device 2")
	var inUse *InUseError
	if _, err := h.svc.Issue(h.grant(false)); !errors.As(err, &inUse) || inUse.Active.Username != "admin" {
		t.Fatalf("second Issue: %v", err)
	}
	second := h.open(true, nil)
	if reason := first.endReason(t); reason != "taken_over" {
		t.Errorf("first end reason %q", reason)
	}
	second.waitOutput(t, "Serial Device 2")
	tk := h.audit.waitFor(t, "console.serial.takeover", 1)[0]
	if tk.Params["previous_user"] != "admin" {
		t.Errorf("takeover audit %+v", tk)
	}
	second.peer.send(MessageText, `{"type":"quit"}`)
	_ = second.wait(t)
}

func TestSerialTimeoutsWatchdogAndShutdown(t *testing.T) {
	cases := map[string]struct {
		mod   func(*SerialConfig, *config.Server)
		check Watchdog
		want  string
	}{
		"idle": {mod: func(c *SerialConfig, _ *config.Server) { c.IdleTimeout = 80 * time.Millisecond }, want: "idle_timeout"},
		"max": {mod: func(c *SerialConfig, _ *config.Server) {
			c.IdleTimeout, c.MaxSession = time.Minute, 80*time.Millisecond
		}, want: "max_session"},
		"watchdog":  {check: func(context.Context) error { return ErrSessionEnded }, want: "session_ended"},
		"forbidden": {check: func(context.Context) error { return errors.New("other") }, want: "session_ended"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newSerialHarness(t, sshtest.Options{}, tc.mod)
			r := h.open(false, tc.check)
			if got := r.endReason(t); got != tc.want {
				t.Errorf("reason %q, want %q", got, tc.want)
			}
			_ = r.wait(t)
		})
	}
	h := newSerialHarness(t, sshtest.Options{}, nil)
	r := h.open(false, nil)
	r.waitOutput(t, "Serial Device 2")
	h.svc.Shutdown()
	if got := r.endReason(t); got != "shutdown" {
		t.Errorf("shutdown reason %q", got)
	}
}

func TestSerialSidesClosingAndProtocol(t *testing.T) {
	for name, tc := range map[string]struct {
		send func(*fakePeer)
		want string
	}{
		"unknown control":  {func(p *fakePeer) { p.send(MessageText, `{"type":"exec","cmd":"racadm"}`) }, "protocol"},
		"extra field":      {func(p *fakePeer) { p.send(MessageText, `{"type":"break","command":"x"}`) }, "protocol"},
		"bad size":         {func(p *fakePeer) { p.send(MessageText, `{"type":"resize","cols":0,"rows":5}`) }, "protocol"},
		"sized break":      {func(p *fakePeer) { p.send(MessageText, `{"type":"break","cols":1}`) }, "protocol"},
		"two objects":      {func(p *fakePeer) { p.send(MessageText, `{"type":"break"}{"type":"quit"}`) }, "protocol"},
		"long control":     {func(p *fakePeer) { p.send(MessageText, strings.Repeat(" ", 300)+`{"type":"break"}`) }, "protocol"},
		"oversized input":  {func(p *fakePeer) { p.send(MessageBinary, strings.Repeat("a", MaxSerialInput+1)) }, "protocol"},
		"unknown type":     {func(p *fakePeer) { p.in <- peerMsg{typ: 9} }, "protocol"},
		"browser closes":   {func(p *fakePeer) { close(p.in) }, "browser_closed"},
		"bmc ends console": {func(p *fakePeer) { p.send(MessageBinary, "x") }, ""},
	} {
		t.Run(name, func(t *testing.T) {
			h := newSerialHarness(t, sshtest.Options{}, nil)
			r := h.open(false, nil)
			r.waitOutput(t, "Serial Device 2")
			tc.send(r.peer)
			if tc.want == "" { // the BMC side ends the console
				r.waitOutput(t, "x")
				h.fake.Close()
				tc.want = "bmc_closed"
			}
			if got := r.endReason(t); got != tc.want {
				t.Errorf("reason %q, want %q", got, tc.want)
			}
			_ = r.wait(t)
			if bytes.Contains(h.fake.Input(), []byte("racadm")) {
				t.Error("a control message reached the BMC")
			}
		})
	}
}

func TestSerialConnectFailures(t *testing.T) {
	other := sshtest.New(t, sshtest.Options{})
	h := newSerialHarness(t, sshtest.Options{}, func(_ *SerialConfig, s *config.Server) { s.SSHHostKey = other.HostKeyLine() })
	r := h.open(false, nil)
	if err := r.wait(t); err == nil {
		t.Fatal("wrong host key connected")
	}
	if s, _ := r.peer.status("error"); s.Class != "host_key" {
		t.Errorf("error status %+v", r.peer.statuses())
	}
	if h.fake.AuthAttempts() != 0 || h.svc.Status("r1").Last.Class != "host_key" {
		t.Errorf("auth attempts %d, status %+v", h.fake.AuthAttempts(), h.svc.Status("r1"))
	}
	stop := h.audit.waitFor(t, "console.serial.stop", 1)[0]
	if stop.Result != audit.ResultError || stop.ErrorClass != "host_key" {
		t.Errorf("stop %+v", stop)
	}

	now := time.Now()
	h = newSerialHarness(t, sshtest.Options{}, func(c *SerialConfig, _ *config.Server) {
		c.Now = func() time.Time { return now }
	})
	cur, _ := h.svc.target("r1")
	must(t, h.svc.SetTargets([]SerialTarget{withPassword(cur, "wrong")}))
	r = h.open(false, nil)
	_ = r.wait(t)
	if _, err := h.svc.Issue(h.grant(false)); !errors.Is(err, ErrCoolingDown) {
		t.Errorf("after a rejected login: %v", err)
	}
	if st := h.svc.Status("r1"); st.RejectedAt.IsZero() || st.Last.Class != "bmc_auth" {
		t.Errorf("status %+v", st)
	}
	now = now.Add(2 * time.Minute)
	if _, err := h.svc.Issue(h.grant(false)); err != nil {
		t.Errorf("after the cooldown: %v", err)
	}
}

func withPassword(t SerialTarget, pw string) SerialTarget {
	t.SSH.Password = secrets.New(pw)
	return t
}

func TestSerialRefusals(t *testing.T) {
	sol := serialServer(config.KindRedfish, "")
	sol.ID, sol.Console.Serial = "sol", config.SerialSOL
	nokey := serialServer(config.KindIDRAC9, "")
	nokey.ID = "nokey"
	nologin := serialServer(config.KindIDRAC9, "ssh-ed25519 AAAA")
	nologin.ID = "nologin"
	var targets []SerialTarget
	for _, s := range []config.Server{sol, nokey, nologin} {
		cred := operator()
		if s.ID == "nologin" {
			cred = secrets.Credential{}
		}
		tg, err := SerialTargetFor(s, cred)
		if err != nil {
			t.Fatal(err)
		}
		targets = append(targets, tg)
	}
	fa := &fakeAudit{}
	svc, err := NewSerial(SerialConfig{Targets: targets, Audit: fa})
	if err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]error{"sol": ErrSerialUnsupported, "nokey": ErrSerialNoHostKey,
		"nologin": ErrSerialNoLogin, "missing": ErrSerialNotConfigured} {
		if _, ierr := svc.Issue(Grant{ServerID: id}); !errors.Is(ierr, want) {
			t.Errorf("%s: %v, want %v", id, ierr, want)
		}
	}
	if st := svc.Status("sol"); !st.Configured || st.Supported || st.Transport != config.SerialSOL {
		t.Errorf("sol status %+v", st)
	}
	if st := svc.Status("nokey"); st.HasHostKey || !st.HasLogin || !st.Supported {
		t.Errorf("nokey status %+v", st)
	}
	if st := svc.Status("missing"); st.Configured {
		t.Error("unknown server configured")
	}
	if _, terr := SerialTargetFor(serialServerNone(), operator()); terr == nil {
		t.Error("serial none built a target")
	}
	if _, nerr := NewSerial(SerialConfig{}); nerr == nil {
		t.Error("no audit accepted")
	}
	if _, derr := NewSerial(SerialConfig{Audit: fa, Targets: []SerialTarget{targets[0], targets[0]}}); derr == nil {
		t.Error("duplicate target accepted")
	}
	link, err := sshOpener(nil)(context.Background(), targets[0], TermSize{})
	if !errors.Is(err, ErrSerialUnsupported) || link != nil {
		t.Errorf("SOL opener: %v", err)
	}
	for err, want := range map[error]string{ErrInUse: "in_use", ErrCoolingDown: "cooldown", ErrSerialNoLogin: "no_credential",
		ErrSerialNoHostKey: "no_host_key", ErrSerialUnsupported: "unsupported", errors.New("x"): "unavailable"} {
		if got := SerialErrorClass(err); got != want {
			t.Errorf("SerialErrorClass(%v) = %q", err, got)
		}
	}
}

func serialServerNone() config.Server {
	s := serialServer(config.KindIDRAC9, "")
	s.Console.Serial = config.SerialNone
	return s
}

func TestSerialDeniedStartIsAudited(t *testing.T) {
	h := newSerialHarness(t, sshtest.Options{}, nil)
	ticket, _ := h.svc.Issue(h.grant(false))
	cur, _ := h.svc.target("r1")
	must(t, h.svc.SetTargets([]SerialTarget{withPassword(cur, "")}))
	r := h.openTicket(ticket, nil)
	if err := r.wait(t); !errors.Is(err, ErrSerialNoLogin) {
		t.Fatalf("err = %v", err)
	}
	d := h.audit.waitFor(t, "console.serial.start", 1)[0]
	if d.Result != audit.ResultDenied || d.ErrorClass != "no_credential" {
		t.Errorf("denied audit %+v", d)
	}
}

func TestSerialAuditFailureFailsClosed(t *testing.T) {
	h := newSerialHarness(t, sshtest.Options{}, nil)
	h.audit.fail = true
	r := h.open(false, nil)
	if err := r.wait(t); err == nil {
		t.Fatal("console ran without its audit row")
	}
	if h.fake.Sessions() != 0 || h.fake.AuthAttempts() != 0 {
		t.Error("the BMC was contacted without an audit row")
	}
}

func TestSerialSilentHost(t *testing.T) {
	h := newSerialHarness(t, sshtest.Options{Silent: true}, nil)
	r := h.open(false, nil)
	waitUntil(t, func() bool { _, ok := r.peer.status("connected"); return ok })
	r.peer.send(MessageBinary, "\r")
	waitUntil(t, func() bool { return bytes.Equal(h.fake.Input(), []byte("\r")) })
	if r.peer.output() != "" {
		t.Errorf("output %q", r.peer.output())
	}
	r.peer.send(MessageText, `{"type":"quit"}`)
	_ = r.wait(t)
}

func TestSerialLegacyQuirkFromConfig(t *testing.T) {
	h := newSerialHarness(t, sshtest.Options{Legacy: true}, func(_ *SerialConfig, s *config.Server) {
		s.Console.SSH.Quirks = []config.SSHQuirk{config.QuirkIDRAC8LegacySSH}
	})
	if !h.svc.Status("r1").Legacy {
		t.Error("legacy not reported")
	}
	r := h.open(false, nil)
	r.waitOutput(t, "Serial Device 2")
	r.peer.send(MessageText, `{"type":"quit"}`)
	_ = r.wait(t)
}
