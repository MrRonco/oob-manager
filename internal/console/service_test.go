package console

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"slices"
	"testing"
	"time"

	"oob-manager/internal/config"
	"oob-manager/internal/console/rfb"
	"oob-manager/internal/console/rfbtest"
	"oob-manager/internal/secrets"
)

func setEncodings(encs ...int32) []byte {
	b := []byte{rfb.MsgSetEncodings, 0}
	b = binary.BigEndian.AppendUint16(b, uint16(len(encs))) //nolint:gosec // test input
	for _, e := range encs {
		b = binary.BigEndian.AppendUint32(b, uint32(e)) //nolint:gosec // two's complement on purpose
	}
	return b
}

var noVNCEncodings = []int32{rfb.EncTight, rfb.EncTightPNG, rfb.EncZRLE, rfb.EncRaw, rfb.EncCopyRect,
	-26, -254, rfb.EncDesktopSize, rfb.EncLastRect, -258, -308, -312, -313, -1063131698, rfb.EncCursor}

func key(down bool, sym uint32) []byte {
	b := []byte{rfb.MsgKeyEvent, 0, 0, 0}
	if down {
		b[1] = 1
	}
	return binary.BigEndian.AppendUint32(b, sym)
}

func TestConsoleEndToEndPasswordNeverReachesBrowser(t *testing.T) {
	h := newHarness(t, config.KindIDRAC9, nil)
	b := h.open(false, nil)
	if b.init.Name != rfbtest.DefaultName || b.init.Width != rfbtest.DefaultWidth {
		t.Errorf("browser ServerInit = %+v", b.init)
	}
	fbur := []byte{rfb.MsgFramebufferUpdateRequest, 0, 0, 0, 0, 0, 0, 64, 0, 48}
	for _, m := range [][]byte{setEncodings(noVNCEncodings...), fbur, key(true, 0x61), key(false, 0x61)} {
		if _, err := b.conn.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	waitUntil(t, func() bool { return len(h.fake.Keys()) == 2 && h.fake.Stats().Updates == 1 })
	got := h.fake.Encodings()[0]
	if slices.Contains(got, -258) || slices.Contains(got, -1063131698) || !slices.Contains(got, rfb.EncTight) {
		t.Errorf("BMC got encodings %v", got)
	}
	_ = b.conn.Close()
	if err := <-b.done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if bytes.Contains(b.conn.bytes(), []byte(rfbtest.Password)) {
		t.Fatal("the VNC password crossed the browser connection")
	}
	start := h.audit.waitFor(t, "console.vnc.start", 1)[0]
	stop := h.audit.waitFor(t, "console.vnc.stop", 1)[0]
	if start.Result != "started" || stop.Result != "ok" || stop.Params["reason"] != "browser_closed" ||
		stop.CorrelationID != start.CorrelationID || stop.ServerID != "r1" || stop.Principal != "admin" {
		t.Errorf("audit start %+v stop %+v", start, stop)
	}
	if _, ok := stop.Params["duration_s"]; !ok {
		t.Error("stop audit has no duration")
	}
	if h.svc.Status("r1").InUse {
		t.Error("slot not released")
	}
}

func TestConsoleIDRAC8QuirksAndDisallowedMessage(t *testing.T) {
	h := newHarness(t, config.KindIDRAC8, nil)
	b := h.open(false, nil)
	if b.init.Name != lowColourName {
		t.Errorf("low-colour quirk: name %q", b.init.Name)
	}
	_, _ = b.conn.Write(setEncodings(noVNCEncodings...))
	waitUntil(t, func() bool { return len(h.fake.Encodings()) == 1 })
	if got := h.fake.Encodings()[0]; !slices.Equal(got, []int32{rfb.EncRaw, rfb.EncCopyRect, rfb.EncDesktopSize}) {
		t.Errorf("safe encodings quirk: BMC got %v", got)
	}
	_, _ = b.conn.Write([]byte{255, 0, 0, 0, 0, 0, 0, 0}) // QEMU client message: not allowed
	<-b.done
	stop := h.audit.waitFor(t, "console.vnc.stop", 1)[0]
	if stop.Params["reason"] != "protocol" {
		t.Errorf("reason = %v", stop.Params["reason"])
	}
	if slices.Contains(h.fake.MessageTypes(), 255) {
		t.Error("a disallowed message reached the BMC")
	}
}

func TestConsoleOneSessionAndTakeover(t *testing.T) {
	h := newHarness(t, config.KindIDRAC9, nil)
	first := h.open(false, nil)
	waitUntil(t, func() bool { return h.svc.Status("r1").InUse })
	st := h.svc.Status("r1")
	if st.Active.Username != "admin" || st.Active.Since.IsZero() {
		t.Errorf("active = %+v", st.Active)
	}
	_, err := h.svc.Issue(h.grant(false))
	var inUse *InUseError
	if !errors.As(err, &inUse) || inUse.Active.Username != "admin" || !errors.Is(err, ErrInUse) {
		t.Fatalf("second console: %v", err)
	}
	if inUse.Error() == "" {
		t.Error("empty error text")
	}
	second := h.open(true, nil)
	<-first.done
	reasons := []any{}
	for _, e := range h.audit.waitFor(t, "console.vnc.stop", 1) {
		reasons = append(reasons, e.Params["reason"])
	}
	if !slices.Contains(reasons, any("taken_over")) {
		t.Errorf("first session stop reasons %v", reasons)
	}
	if tk := h.audit.waitFor(t, "console.vnc.takeover", 1)[0]; tk.Params["previous_user"] != "admin" {
		t.Errorf("takeover audit %+v", tk)
	}
	_ = second.conn.Close()
	<-second.done
}

func TestConsoleTimeoutsAndWatchdog(t *testing.T) {
	cases := map[string]struct {
		mod   func(*Config)
		check Watchdog
		want  string
	}{
		"idle":    {func(c *Config) { c.IdleTimeout = 150 * time.Millisecond }, nil, "idle_timeout"},
		"max":     {func(c *Config) { c.MaxSession = 150 * time.Millisecond }, nil, "max_session"},
		"stepup":  {nil, func(context.Context) error { return ErrStepUpExpired }, "stepup_expired"},
		"session": {nil, func(context.Context) error { return errors.New("gone") }, "session_ended"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, config.KindIDRAC9, tc.mod)
			b := h.open(false, tc.check)
			<-b.done
			if r := h.audit.waitFor(t, "console.vnc.stop", 1)[0].Params["reason"]; r != tc.want {
				t.Errorf("reason = %v, want %s", r, tc.want)
			}
		})
	}
}

func TestConsoleWrongPasswordCoolsDown(t *testing.T) {
	h := newHarness(t, config.KindIDRAC9, nil)
	tg, _ := TargetFor(serverCfg(config.KindIDRAC9, false, ""), secrets.New("Wrong!pw"))
	must(t, h.svc.SetTargets([]Target{tg}))
	ticket, err := h.svc.Issue(h.grant(false))
	if err != nil {
		t.Fatal(err)
	}
	appEnd, browserEnd := netPipe(t)
	err = h.svc.Serve(context.Background(), ticket, "r1", h.sess, appEnd, nil)
	_ = browserEnd
	if err == nil || classify(err) != "bmc_auth" {
		t.Fatalf("err = %v", err)
	}
	if _, err := h.svc.Issue(h.grant(false)); !errors.Is(err, ErrCoolingDown) {
		t.Fatalf("retry during cooldown: %v", err)
	}
	if st := h.svc.Status("r1"); st.RejectedAt.IsZero() || st.InUse {
		t.Errorf("status = %+v", st)
	}
	if stop := h.audit.waitFor(t, "console.vnc.stop", 1)[0]; stop.ErrorClass != "bmc_auth" || stop.Result != "error" {
		t.Errorf("stop = %+v", stop)
	}
	if h.fake.Stats().AuthFailures != 1 {
		t.Error("exactly one failed VNC login expected")
	}
}

func TestConsoleRefusals(t *testing.T) {
	h := newHarness(t, config.KindIDRAC9, nil)
	appEnd, _ := netPipe(t)
	if err := h.svc.Serve(context.Background(), "bogus", "r1", h.sess, appEnd, nil); !errors.Is(err, ErrTicketInvalid) {
		t.Errorf("bad ticket: %v", err)
	}
	if _, err := h.svc.Issue(Grant{ServerID: "nope"}); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("unknown server: %v", err)
	}
	tg, _ := TargetFor(serverCfg(config.KindIDRAC9, false, ""), secrets.Secret{})
	must(t, h.svc.SetTargets([]Target{tg}))
	if _, err := h.svc.Issue(h.grant(false)); !errors.Is(err, ErrNoPassword) {
		t.Errorf("no credential: %v", err)
	}
	if st := h.svc.Status("r1"); !st.Configured || st.HasPassword {
		t.Errorf("status = %+v", st)
	}
	if st := h.svc.Status("other"); st.Configured {
		t.Error("unknown server reported as configured")
	}
}

func TestConsoleAuditFailureFailsClosed(t *testing.T) {
	h := newHarness(t, config.KindIDRAC9, nil)
	ticket, _ := h.svc.Issue(h.grant(false))
	h.audit.fail = true
	appEnd, _ := netPipe(t)
	if err := h.svc.Serve(context.Background(), ticket, "r1", h.sess, appEnd, nil); err == nil {
		t.Fatal("console started without an audit row")
	}
	if h.fake.Stats().Connections != 0 {
		t.Error("BMC contacted although the audit write failed")
	}
}

func TestConsoleShutdownEndsSessions(t *testing.T) {
	h := newHarness(t, config.KindIDRAC9, nil)
	b := h.open(false, nil)
	h.svc.Shutdown()
	<-b.done
	if r := h.audit.waitFor(t, "console.vnc.stop", 1)[0].Params["reason"]; r != "shutdown" {
		t.Errorf("reason = %v", r)
	}
}
