package notify

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

// fakeSuppressor puts the servers in maint into maintenance and acknowledges entries by
// "server/log/id".
type fakeSuppressor struct {
	mu    sync.Mutex
	maint map[string]bool
	acked map[string]bool
}

func (f *fakeSuppressor) InMaintenance(id string, _ time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.maint[id]
}

func (f *fakeSuppressor) Acked(server, log, id string, _ time.Time) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.acked[server+"/"+log+"/"+id]
}

func (f *fakeSuppressor) set(id string, on bool) { f.mu.Lock(); f.maint[id] = on; f.mu.Unlock() }

// TestMaintenanceSuppressionMatrix: for every class, an event of a server in maintenance
// is sent only when the class is not Mutable; the same event for a server not in
// maintenance always goes out; app-wide events (no server) are never suppressed.
func TestMaintenanceSuppressionMatrix(t *testing.T) {
	r := newReceiver(t, true)
	sup := &fakeSuppressor{maint: map[string]bool{"srv-a": true}, acked: map[string]bool{}}
	env := newSvcEnv(t, r, func(c *Config) { c.Suppress = sup })
	ctx := context.Background()
	if err := env.svc.Create(ctx, alice, target(KindWebhook, r.srv.URL+"/h"), Secrets{}); err != nil {
		t.Fatal(err)
	}
	env.run(t)
	want := 0
	for _, c := range Classes() {
		for _, server := range []string{"srv-a", "srv-b", ""} {
			e := testEvent()
			e.Class, e.ServerID, e.Key = c, server, string(c)+"/"+server
			env.svc.Emit(e)
			suppressed := c.Mutable() && server == "srv-a"
			if !suppressed {
				want++
			}
		}
	}
	waitFor(t, "unsuppressed events", func() bool { return r.count() == want })
	time.Sleep(50 * time.Millisecond)
	if r.count() != want {
		t.Fatalf("%d delivered, want %d", r.count(), want)
	}
	for _, c := range r.requests() {
		cls := Class(c.Header.Get(HeaderEvent))
		if cls.Mutable() && strings.Contains(string(c.Body), `"server":{"id":"srv-a"`) {
			t.Fatalf("suppressed class %s of srv-a delivered", cls)
		}
	}
	for _, c := range []Class{ClassHealth, ClassReachability, ClassSEL, ClassPSU} {
		if !c.Mutable() {
			t.Errorf("%s must be suppressed by maintenance", c)
		}
	}
	for _, c := range []Class{ClassPower, ClassConsole, ClassFan, ClassAuth, ClassAudit, ClassTrust, ClassNotify, ClassMaintenance} {
		if c.Mutable() {
			t.Errorf("security or self class %s must never be suppressed", c)
		}
	}
	// Once the window is over, the same health event is sent.
	sup.set("srv-a", false)
	env.svc.Emit(testEvent())
	waitFor(t, "health after maintenance", func() bool { return r.count() == want+1 })
}

// TestMaintenanceEventRouting: the start/end message goes to targets subscribed to any
// class maintenance pauses, at normal priority, and never to a power-only target.
func TestMaintenanceEventRouting(t *testing.T) {
	until := fixedNow.Add(4 * time.Hour)
	start := MaintenanceEvent(MaintenanceChange{ServerID: "srv-a", ServerName: "Storage node", Started: true,
		Until: until, Reason: "PSU swap\nline two", By: "alice"}, fixedNow)
	end := MaintenanceEvent(MaintenanceChange{ServerID: "srv-a", ServerName: "Storage node", Expired: true, By: "system"}, fixedNow)
	if start.Class != ClassMaintenance || start.Recovery || !end.Recovery || start.Severity != SeverityWarning {
		t.Fatalf("events %+v %+v", start, end)
	}
	if !strings.Contains(start.Message, "until 2026-10-21 18:03 UTC") || !strings.Contains(start.Message, "alice: PSU swap line two") ||
		!strings.Contains(end.Message, "expired") || !strings.Contains(end.Title, "maintenance ended") {
		t.Fatalf("text %q / %q", start.Message, end.Message)
	}
	open := MaintenanceEvent(MaintenanceChange{ServerID: "srv-a", ServerName: "N", Started: true, Reason: "r", By: "a"}, fixedNow)
	if !strings.Contains(open.Message, "until it is ended") {
		t.Fatalf("open-ended text %q", open.Message)
	}
	byUser := MaintenanceEvent(MaintenanceChange{ServerID: "srv-a", ServerName: "N", By: "bob"}, fixedNow)
	if !strings.Contains(byUser.Message, "was ended by bob") {
		t.Fatalf("ended text %q", byUser.Message)
	}
	health := Target{ID: "h", Enabled: true, Classes: []Class{ClassSEL}, MinSeverity: SeverityWarning}
	power := Target{ID: "p", Enabled: true, Classes: []Class{ClassPower}, MinSeverity: SeverityInfo}
	strict := Target{ID: "c", Enabled: true, Classes: []Class{ClassHealth}, MinSeverity: SeverityCritical}
	if !health.Wants(start) || !health.Wants(end) || power.Wants(start) || strict.Wants(start) {
		t.Fatal("maintenance routing")
	}
	if ntfyPriority(start) != 3 || pushoverPriority(health, start) != 0 || gotifyPriority(start) != 2 || ntfyTags(end) != "wrench" {
		t.Fatal("maintenance messages must use normal priority")
	}
	if ClassMaintenance.Label() == string(ClassMaintenance) {
		t.Fatal("no label")
	}
	if _, err := ParseClass("maintenance"); err == nil {
		t.Fatal("maintenance must not be subscribable")
	}
}

// TestAckedEntriesNeverNotified: an acknowledged SEL entry is left out of the "new
// entries" event; an unacknowledged new entry of the same kind is still reported.
func TestAckedEntriesNeverNotified(t *testing.T) {
	sup := &fakeSuppressor{maint: map[string]bool{}, acked: map[string]bool{"srv-a/sel/2": true}}
	d := NewDetector(time.Second)
	d.acked = sup.Acked
	old := bmc.Event{ID: "1", Created: fixedNow.Add(-time.Hour), Severity: bmc.SeverityWarning, Message: "old"}
	acked := bmc.Event{ID: "2", Created: fixedNow, Severity: bmc.SeverityCritical, Message: "fan 1 failed"}
	fresh := bmc.Event{ID: "3", Created: fixedNow.Add(time.Minute), Severity: bmc.SeverityCritical, Message: "fan 1 failed"}
	evs := run(d, healthy(fixedNow, withSEL(old)), healthy(fixedNow, withSEL(old, acked)))
	if len(evs) != 0 {
		t.Fatalf("acked entry reported: %+v", evs)
	}
	evs = run(d, healthy(fixedNow, withSEL(old, acked, fresh)))
	if len(evs) != 1 || evs[0].Count != 1 || evs[0].Class != ClassSEL {
		t.Fatalf("new entry of the same kind: %+v", evs)
	}
}

// TestMaintenanceEndForgetsServer: a problem confirmed during maintenance (suppressed)
// is reported again after the window ends, because the detector forgets the server.
func TestMaintenanceEndForgetsServer(t *testing.T) {
	r := newReceiver(t, true)
	sup := &fakeSuppressor{maint: map[string]bool{"srv-a": true}, acked: map[string]bool{}}
	fl := &fakeFleet{}
	env := newSvcEnv(t, r, func(c *Config) {
		c.Suppress, c.Fleet, c.Debounce, c.WatchEvery = sup, fl, time.Second, 5*time.Millisecond
	})
	if err := env.svc.Create(context.Background(), alice, target(KindWebhook, r.srv.URL+"/h"), Secrets{}); err != nil {
		t.Fatal(err)
	}
	fl.set(healthy(fixedNow, withHealth(bmc.HealthCritical)))
	env.run(t)
	time.Sleep(40 * time.Millisecond)
	env.advance(2 * time.Second)
	time.Sleep(40 * time.Millisecond) // confirmed while in maintenance: suppressed
	if r.count() != 0 {
		t.Fatalf("delivered during maintenance: %d", r.count())
	}
	sup.set("srv-a", false)
	env.svc.Emit(MaintenanceEvent(MaintenanceChange{ServerID: "srv-a", ServerName: "Storage node", By: "alice"}, fixedNow))
	waitFor(t, "ended message", func() bool { return r.count() == 1 })
	time.Sleep(40 * time.Millisecond)
	env.advance(2 * time.Second)
	waitFor(t, "problem reported again after the window", func() bool { return r.count() == 2 })
	if got := r.requests()[1].Header.Get(HeaderEvent); got != string(ClassHealth) {
		t.Fatalf("second message %s", got)
	}
}

// TestMaintenanceReminderEvent: the daily reminder of an open-ended window is a
// maintenance-class warning (not a recovery), names how long it has lasted, goes to the
// same targets as start and end, at normal priority.
func TestMaintenanceReminderEvent(t *testing.T) {
	since := fixedNow.Add(-50 * time.Hour)
	e := MaintenanceEvent(MaintenanceChange{ServerID: "srv-a", ServerName: "Storage node", Reminder: true,
		Since: since, Reason: "rack move", By: "alice"}, fixedNow)
	if e.Class != ClassMaintenance || e.Recovery || e.Severity != SeverityWarning || e.ServerID != "srv-a" {
		t.Fatalf("event %+v", e)
	}
	if e.Title != "Storage node: still in maintenance" ||
		!strings.Contains(e.Message, "since "+since.UTC().Format("2006-01-02 15:04 MST")+" (2 days)") ||
		!strings.Contains(e.Message, "no end time") || !strings.Contains(e.Message, "alice: rack move") {
		t.Fatalf("text %q / %q", e.Title, e.Message)
	}
	if d := MaintenanceEvent(MaintenanceChange{ServerName: "N", Reminder: true, Since: fixedNow.Add(-30 * time.Hour)}, fixedNow); !strings.Contains(d.Message, "(1 day)") {
		t.Fatalf("one day: %q", d.Message)
	}
	health := Target{ID: "h", Enabled: true, Classes: []Class{ClassHealth}, MinSeverity: SeverityWarning}
	power := Target{ID: "p", Enabled: true, Classes: []Class{ClassPower}, MinSeverity: SeverityInfo}
	if !health.Wants(e) || power.Wants(e) || ntfyPriority(e) != 3 || pushoverPriority(health, e) != 0 {
		t.Fatal("reminder routing or priority")
	}
}
