package bmcsec

import (
	"context"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/notify"
)

func securityEvents(evs []notify.Event) (findings, reminders []notify.Event) {
	for _, e := range evs {
		switch {
		case e.Class != notify.ClassSecurity:
		case strings.HasPrefix(e.Key, "security/cert/"):
			reminders = append(reminders, e)
		default:
			findings = append(findings, e)
		}
	}
	return findings, reminders
}

func TestNewFindingsAreNotifiedOnce(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	p := withIPMI(good(), true)
	p.Redfish.Protocols.Telnet = bmc.FactOf(true, "np")
	e.serve("srv", p)
	e.svc.Tick(ctx)
	f, _ := securityEvents(e.events())
	if len(f) != 1 || f[0].Count != 2 || f[0].Severity != notify.SeverityWarning || f[0].ServerName != "Server srv" ||
		!strings.Contains(f[0].Message, "IPMI over LAN (Warning)") || !strings.Contains(f[0].Message, "Telnet (Fail)") {
		t.Fatalf("first run %+v", f)
	}
	e.svc.Tick(ctx)
	// A restart reads what was already notified from the database.
	e.svc = e.open()
	e.svc.Tick(ctx)
	if f, _ := securityEvents(e.events()); len(f) != 1 {
		t.Fatalf("nothing new: %d events", len(f))
	}
}

func TestEscalationAndRecurrenceAreNew(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	p := good()
	p.Web.Cert.NotAfter = now.Add(20 * 24 * time.Hour)
	e.serve("srv", p)
	e.svc.Tick(ctx) // the expiry warning (20 days: no reminder bucket yet)
	p.Web.Cert.NotAfter = now.Add(-time.Hour)
	e.serve("srv", p)
	e.svc.Tick(ctx) // warning → fail: new
	p.Web.Cert.NotAfter = now.Add(20 * 24 * time.Hour)
	e.serve("srv", p)
	e.svc.Tick(ctx) // fail → warning: better, not new
	e.serve("srv", good())
	e.svc.Tick(ctx) // resolved
	e.serve("srv", p)
	e.svc.Tick(ctx) // back: new again
	f, r := securityEvents(e.events())
	// Every new finding is a warning or a failure: the message is a warning (D7), so a
	// target at the default "warning and above" receives it.
	if len(f) != 3 || len(r) != 0 || f[1].Severity != notify.SeverityWarning || f[2].Severity != notify.SeverityWarning {
		t.Fatalf("findings %+v reminders %+v", f, r)
	}
}

func TestAcceptedFindingsAreNotNotified(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	e.serve("srv", withIPMI(good(), true))
	if err := e.accept("srv", "svc.ipmi", "known"); err != nil {
		t.Fatal(err)
	}
	e.svc.Tick(ctx)
	if f, _ := securityEvents(e.events()); len(f) != 0 {
		t.Fatalf("accepted: %+v", f)
	}
}

// TestReminderSurvivesARunThatCouldNotReadThePort: a run that could not read the
// certificate (a timeout) keeps the reminder already sent, so the next good read does not
// send the same reminder again.
func TestReminderSurvivesARunThatCouldNotReadThePort(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	p := good()
	p.Web.Cert.NotAfter = now.Add(40 * 24 * time.Hour)
	e.serve("srv", p)
	e.svc.Tick(ctx) // 40 days: nothing yet
	e.advance(11 * 24 * time.Hour)
	e.serve("srv", p)
	e.svc.Tick(ctx) // 29 days: the expiry warning, a finding
	e.advance(16 * 24 * time.Hour)
	e.serve("srv", p)
	e.svc.Tick(ctx) // 13 days: the 14-day reminder
	if _, r := securityEvents(e.events()); len(r) != 1 {
		t.Fatalf("%d reminders before the gap, want 1: %+v", len(r), r)
	}
	unread := good()
	unread.Web = bmc.TLSProbe{Read: bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassTimeout}, Port: 443}
	e.advance(time.Hour)
	e.serve("srv", unread)
	e.svc.Tick(ctx)
	e.advance(time.Hour)
	e.serve("srv", p)
	e.svc.Tick(ctx)
	if _, r := securityEvents(e.events()); len(r) != 1 {
		t.Fatalf("%d reminders across a gap, want 1: %+v", len(r), r)
	}
}

func TestCertificateReminders(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	p := good()
	p.Web.Cert.NotAfter = now.Add(40 * 24 * time.Hour)
	e.serve("srv", p)
	e.svc.Tick(ctx)
	steps := []struct {
		advance time.Duration
		want    int // reminders so far
	}{
		{11 * 24 * time.Hour, 0}, // 29 days left: the expiry warning (a finding), no reminder yet
		{16 * 24 * time.Hour, 1}, // 13 days: the 14-day reminder
		{24 * time.Hour, 1},      // 12 days: nothing
		{6 * 24 * time.Hour, 2},  // 6 days: the 7-day reminder
		{5*24*time.Hour + 12*time.Hour, 3},
		{time.Hour, 3},
	}
	for i, s := range steps {
		e.advance(s.advance)
		e.serve("srv", p)
		e.svc.Tick(ctx)
		if _, r := securityEvents(e.events()); len(r) != s.want {
			t.Fatalf("step %d: %d reminders, want %d: %+v", i, len(r), s.want, r)
		}
	}
	_, r := securityEvents(e.events())
	if r[0].Title != "Server srv: HTTPS certificate expires in 13 days" || r[2].Title != "Server srv: HTTPS certificate expires within a day" {
		t.Fatalf("reminders %q / %q", r[0].Title, r[2].Title)
	}
}

func TestReminderNotDoubledWithANewFinding(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	p := good()
	p.VNC.Cert.SHA256, p.VNC.Cert.NotAfter = "vnc-own-cert", now.Add(5*24*time.Hour) // its own certificate, not the web one
	e.serve("srv", p)
	e.svc.Tick(ctx)
	f, r := securityEvents(e.events())
	if len(f) != 1 || len(r) != 0 || !strings.Contains(f[0].Message, "VNC port certificate (Warning)") {
		t.Fatalf("the new finding says it already: %+v %+v", f, r)
	}
	e.svc.Tick(ctx)
	if _, r := securityEvents(e.events()); len(r) != 0 {
		t.Fatalf("the bucket was recorded: %+v", r)
	}
	p.VNC.Cert.SHA256 = "renewed-but-also-short"
	e.serve("srv", p)
	e.svc.Tick(ctx)
	if f, _ := securityEvents(e.events()); len(f) != 2 {
		t.Fatalf("a new certificate is a new finding: %+v", f)
	}
}

func TestServersLeavingTheFleetAreForgotten(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	e.serve("srv", withIPMI(good(), true))
	e.svc.Tick(ctx)
	e.fl.drop("srv")
	e.svc.Tick(ctx)
	if rows, err := e.db.Security().Notified(ctx); err != nil || len(rows) != 0 {
		t.Fatalf("rows of a server that is gone: %+v %v", rows, err)
	}
	e.serve("srv", withIPMI(good(), true))
	e.svc.Tick(ctx)
	if f, _ := securityEvents(e.events()); len(f) != 2 {
		t.Fatalf("a server that comes back starts over: %d", len(f))
	}
}

func TestRunStopsWithItsContext(t *testing.T) {
	e := newSvcEnv(t)
	e.serve("srv", withIPMI(good(), true))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.svc.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(e.events()) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	if len(e.events()) != 1 {
		t.Fatalf("the first pass runs at once: %d", len(e.events()))
	}
}

// TestAnUnknownGapDoesNotRepeatANotification: a finding that goes warning → unknown (a
// probe hiccup) → warning is one finding, notified once; its bookkeeping survives the gap.
func TestAnUnknownGapDoesNotRepeatANotification(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	warn := good()
	warn.Web.TLS10 = on(true, "p")
	e.serve("srv", warn)
	e.svc.Tick(ctx)
	gap := good()
	gap.Web.TLS10, gap.Web.TLS11 = bmc.Fact[bool]{}, bmc.Fact[bool]{}
	e.serve("srv", gap)
	e.svc.Tick(ctx)
	e.serve("srv", warn)
	e.svc.Tick(ctx)
	if f, _ := securityEvents(e.events()); len(f) != 1 {
		t.Fatalf("warn, unknown, warn: %d messages, want 1: %+v", len(f), f)
	}
	// Resolved for real (a pass) and back: that is new again.
	e.serve("srv", good())
	e.svc.Tick(ctx)
	e.serve("srv", warn)
	e.svc.Tick(ctx)
	if f, _ := securityEvents(e.events()); len(f) != 2 {
		t.Fatalf("after a pass the finding is new again: %d messages", len(f))
	}
}

// TestOneCertificateOnBothPortsIsOneFinding: the VNC server presents the web certificate,
// so its expiry is reported and reminded once, by the web certificate check.
func TestOneCertificateOnBothPortsIsOneFinding(t *testing.T) {
	e := newSvcEnv(t)
	ctx := context.Background()
	p := good() // the VNC probe carries the web certificate
	p.Web.Cert.NotAfter, p.VNC.Cert.NotAfter = now.Add(5*24*time.Hour), now.Add(5*24*time.Hour)
	e.serve("srv", p)
	e.svc.Tick(ctx)
	f, r := securityEvents(e.events())
	if len(f) != 1 || f[0].Count != 1 || !strings.Contains(f[0].Message, "Web certificate expiry (Warning)") ||
		strings.Contains(f[0].Message, "VNC port certificate") {
		t.Fatalf("findings %+v", f)
	}
	if len(r) != 0 {
		t.Fatalf("the new finding carries the reminder: %+v", r)
	}
	e.advance(24 * time.Hour)
	e.serve("srv", p)
	e.svc.Tick(ctx) // 4 days left: still the 7-day bucket, recorded with the finding
	e.advance(3 * 24 * time.Hour)
	e.serve("srv", p)
	e.svc.Tick(ctx) // 1 day left: the 1-day reminder, once
	if _, r := securityEvents(e.events()); len(r) != 1 || r[0].Title != "Server srv: HTTPS certificate expires in 1 day" {
		t.Fatalf("reminders %+v", r)
	}
}

// TestReminderBuckets pins the reminder buckets on their edges.
func TestReminderBuckets(t *testing.T) {
	for days, want := range map[int]int{-1: 0, 0: 1, 1: 1, 2: 7, 7: 7, 8: 14, 14: 14, 15: 0, 400: 0} {
		if got := reminderBucket(days); got != want {
			t.Errorf("reminderBucket(%d) = %d, want %d", days, got, want)
		}
	}
}
