package maint

import (
	"context"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/notify"
)

func reminders(evs []notify.Event) []notify.Event {
	var out []notify.Event
	for _, e := range evs {
		if strings.HasSuffix(e.Title, "still in maintenance") {
			out = append(out, e)
		}
	}
	return out
}

// TestOpenEndedReminder: an "until ended" window sends one reminder per 24 h while it
// lasts (not before the first 24 h, never twice in a day, not after a restart that
// follows a reminder); timed and scheduled windows never send one; the reminder time
// survives a restart.
func TestOpenEndedReminder(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.svc.Start(ctx, alice, "srv-a", StartRequest{Reason: "rack move"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Start(ctx, alice, "srv-b", StartRequest{Reason: "timed", Duration: MaxWindow}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Start(ctx, alice, "srv-c", StartRequest{Reason: "later", StartsAt: t0.Add(29 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	e.advance(OpenEndedAfter - time.Minute)
	e.svc.Tick(ctx)
	if n := len(reminders(e.events())); n != 0 || len(e.svc.OpenEnded()) != 0 {
		t.Fatalf("%d reminders before 24 h", n)
	}
	e.advance(time.Minute)
	e.svc.Tick(ctx)
	e.svc.Tick(ctx)
	rs := reminders(e.events())
	if len(rs) != 1 || rs[0].ServerID != "srv-a" || rs[0].Class != notify.ClassMaintenance || rs[0].Recovery ||
		!strings.Contains(rs[0].Message, "(1 day)") || !strings.Contains(rs[0].Message, "alice: rack move") {
		t.Fatalf("first reminder %+v", rs)
	}
	if oe := e.svc.OpenEnded(); len(oe) != 1 || oe[0].ServerID != "srv-a" {
		t.Fatalf("open-ended list %+v", oe)
	}
	// A restart right after a reminder does not repeat it.
	e.svc = e.open()
	e.advance(23 * time.Hour)
	e.svc.Tick(ctx)
	if n := len(reminders(e.events())); n != 1 {
		t.Fatalf("%d reminders within the second day", n)
	}
	e.advance(time.Hour)
	e.svc.Tick(ctx)
	if rs := reminders(e.events()); len(rs) != 2 || !strings.Contains(rs[1].Message, "(2 days)") {
		t.Fatalf("second reminder %+v", rs)
	}
	// The app was down for three days: one reminder on return, not three.
	e.advance(3 * 24 * time.Hour)
	e.svc.Tick(ctx)
	e.svc.Tick(ctx)
	if n := len(reminders(e.events())); n != 3 {
		t.Fatalf("%d reminders after a gap, want 3", n)
	}
	// Ending it stops the reminders; no audit row per reminder.
	if err := e.svc.End(ctx, bob, "srv-a"); err != nil {
		t.Fatal(err)
	}
	e.advance(48 * time.Hour)
	e.svc.Tick(ctx)
	if n := len(reminders(e.events())); n != 3 || len(e.svc.OpenEnded()) != 0 {
		t.Fatalf("reminder after the end (%d)", n)
	}
	if a := e.auditText(); strings.Count(a, ActionStart) != 3 || strings.Contains(a, "remind") {
		t.Fatalf("audit:\n%s", a)
	}
}

// TestOpenEndedListOrder: OpenEnded lists active until-ended windows older than
// OpenEndedAfter, oldest first.
func TestOpenEndedListOrder(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.svc.Start(ctx, alice, "srv-z", StartRequest{Reason: "first"}); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Hour)
	if _, err := e.svc.Start(ctx, alice, "srv-a", StartRequest{Reason: "second"}); err != nil {
		t.Fatal(err)
	}
	e.advance(OpenEndedAfter)
	oe := e.svc.OpenEnded()
	if len(oe) != 2 || oe[0].ServerID != "srv-z" || oe[1].ServerID != "srv-a" {
		t.Fatalf("order %+v", oe)
	}
	if !oe[0].LongOpenEndedAt(e.clock()) || oe[0].ReminderDueAt(oe[0].StartsAt) {
		t.Fatal("window predicates")
	}
}
