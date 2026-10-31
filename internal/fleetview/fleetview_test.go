package fleetview

import (
	"context"
	"errors"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
	"oob-manager/internal/web/ui"
)

// fakeReader is a fixed fleet.Reader.
type fakeReader struct{ states []fleet.ServerState }

func (f fakeReader) Servers() []fleet.ServerState { return f.states }

func (f fakeReader) Server(id string) (fleet.ServerState, bool) {
	for _, s := range f.states {
		if s.ID == id {
			return s, true
		}
	}
	return fleet.ServerState{}, false
}

func (f fakeReader) Polled() bool { return len(f.states) > 0 }

var t0 = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func mkLog(n int, complete bool) bmc.EventLog {
	entries := make([]bmc.Event, n)
	for i := range entries {
		entries[i] = bmc.Event{ID: string(rune('a' + i)), Message: "m"}
	}
	return bmc.NewEventLog("/redfish/v1/x", entries, complete)
}

func caps(sel bool) bmc.Capabilities {
	return bmc.NewCapabilities(bmc.CapabilityParams{Flags: bmc.CapabilityFlags{SEL: sel}})
}

func TestServersMapsStateToViews(t *testing.T) {
	snap := bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: t0, PowerState: bmc.PowerOn})
	r := fakeReader{states: []fleet.ServerState{
		{ID: "a", Name: "Alpha", Snapshot: snap, HasSnapshot: true, LastSuccess: t0, PowerSince: t0.Add(-time.Hour),
			PowerCause:   fleet.PowerCause{Action: "on", By: "alice", At: t0.Add(-time.Hour)},
			Capabilities: caps(true), HasCapabilities: true, HasInventory: true},
		{ID: "b", Name: "Beta", LastError: bmc.ClassTimeout},
	}}
	views := New(r, nil).Servers()
	if len(views) != 2 || views[0].ID != "a" || views[1].ID != "b" {
		t.Fatalf("order/ids: %+v", views)
	}
	a := views[0]
	if a.Name != "Alpha" || !a.HasSnapshot || !a.LastSuccess.Equal(t0) || !a.HasCapabilities ||
		!a.HasInventory || a.Snapshot.PowerState() != bmc.PowerOn || a.ErrorClass != bmc.ClassNone ||
		!a.PowerSince.Equal(t0.Add(-time.Hour)) || a.PowerCause != (ui.PowerCause{Action: "on", By: "alice", At: t0.Add(-time.Hour)}) {
		t.Fatalf("a: %+v", a)
	}
	if b := views[1]; b.HasSnapshot || b.ErrorClass != bmc.ClassTimeout {
		t.Fatalf("b: %+v", b)
	}
}

func TestServerLookup(t *testing.T) {
	f := New(fakeReader{states: []fleet.ServerState{{ID: "a", Name: "Alpha"}}}, nil)
	if v, ok := f.Server("a"); !ok || v.Name != "Alpha" {
		t.Fatalf("got %+v %v", v, ok)
	}
	if _, ok := f.Server("zz"); ok {
		t.Fatal("unknown server found")
	}
}

func TestEventsSEL(t *testing.T) {
	ctx := context.Background()
	r := fakeReader{states: []fleet.ServerState{
		{ID: "ok", SEL: mkLog(3, true), HasSEL: true},
		{ID: "failed", SELError: bmc.ClassAuth},
		{ID: "unsupported", SELError: bmc.ClassUnsupported},
		{ID: "nosel", Capabilities: caps(false), HasCapabilities: true},
		{ID: "pending"},
	}}
	f := New(r, nil)
	if l, err := f.Events(ctx, "ok", ui.LogSEL); err != nil || l.Len() != 3 || !l.Complete() {
		t.Fatalf("ok: %v %v", l.Len(), err)
	}
	if _, err := f.Events(ctx, "failed", ui.LogSEL); bmc.Classify(err) != bmc.ClassAuth {
		t.Fatalf("failed: %v", err)
	}
	for _, id := range []string{"unsupported", "nosel", "missing"} {
		if _, err := f.Events(ctx, id, ui.LogSEL); !errors.Is(err, ui.ErrLogUnavailable) {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if l, err := f.Events(ctx, "pending", ui.LogSEL); err != nil || l.Len() != 0 || l.Complete() {
		t.Fatalf("pending: %v %v %v", l.Len(), l.Complete(), err)
	}
}

func TestEventsLifecycle(t *testing.T) {
	ctx := context.Background()
	r := fakeReader{states: []fleet.ServerState{
		{ID: "dell", Lifecycle: mkLog(2, false), HasLifecycle: true},
		{ID: "dellfail", LifecycleError: bmc.ClassTimeout},
		{ID: "dellpending"},
		{ID: "generic", Lifecycle: mkLog(2, true), HasLifecycle: true},
	}}
	f := New(r, func(id string) bool { return id != "generic" })
	if l, err := f.Events(ctx, "dell", ui.LogLifecycle); err != nil || l.Len() != 2 || l.Complete() {
		t.Fatalf("dell: %v %v", l.Len(), err)
	}
	if _, err := f.Events(ctx, "dellfail", ui.LogLifecycle); bmc.Classify(err) != bmc.ClassTimeout {
		t.Fatalf("dellfail: %v", err)
	}
	if l, err := f.Events(ctx, "dellpending", ui.LogLifecycle); err != nil || l.Len() != 0 {
		t.Fatalf("dellpending: %v", err)
	}
	if _, err := f.Events(ctx, "generic", ui.LogLifecycle); !errors.Is(err, ui.ErrLogUnavailable) {
		t.Fatalf("generic: %v", err)
	}
	if _, err := New(r, nil).Events(ctx, "dell", ui.LogLifecycle); !errors.Is(err, ui.ErrLogUnavailable) {
		t.Fatalf("nil lifecycle func must mean no lifecycle log: %v", err)
	}
	if _, err := f.Events(ctx, "dell", ui.LogKind("bogus")); !errors.Is(err, ui.ErrLogUnavailable) {
		t.Fatalf("bogus kind: %v", err)
	}
}

func TestClassErrorRoundTrips(t *testing.T) {
	for _, c := range []bmc.ErrorClass{bmc.ClassTimeout, bmc.ClassTLS, bmc.ClassAuth, bmc.ClassBMC,
		bmc.ClassNotFound, bmc.ClassUnreachable, bmc.ClassProtocol, bmc.ClassConfig, bmc.ClassOther} {
		if got := bmc.Classify(classError(c)); got != c {
			t.Errorf("class %s round-tripped to %s", c, got)
		}
	}
}

func TestEventsHonoursContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	f := New(fakeReader{states: []fleet.ServerState{{ID: "ok", SEL: mkLog(1, true), HasSEL: true}}}, nil)
	if _, err := f.Events(ctx, "ok", ui.LogSEL); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v", err)
	}
}

func TestViewCarriesPollTimingAndTiers(t *testing.T) {
	at := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	f := New(fakeReader{states: []fleet.ServerState{{ID: "a", LastPollDuration: 4 * time.Second,
		StaleAfter: time.Hour, SELAsOf: at, SELOverdue: true, LifecycleAsOf: at.Add(time.Minute),
		LifecycleOverdue: true, InventoryAsOf: at.Add(time.Hour), InventoryOverdue: true}}}, nil)
	v, _ := f.Server("a")
	if v.LastPollDuration != 4*time.Second || v.StaleAfter != time.Hour || !v.SELAsOf.Equal(at) || !v.SELOverdue ||
		!v.LifecycleAsOf.Equal(at.Add(time.Minute)) || !v.LifecycleOverdue || !v.InventoryAsOf.Equal(at.Add(time.Hour)) || !v.InventoryOverdue {
		t.Fatalf("view %+v", v)
	}
}

func TestViewCarriesTagsAsCopy(t *testing.T) {
	tags := []string{"critical", "edge"}
	f := New(fakeReader{states: []fleet.ServerState{{ID: "a", Tags: tags}}}, nil)
	v, _ := f.Server("a")
	if len(v.Tags) != 2 || v.Tags[0] != "critical" {
		t.Fatalf("tags = %v", v.Tags)
	}
	v.Tags[0] = "mutated"
	if tags[0] != "critical" {
		t.Fatal("view shares the state's tag slice")
	}
}

func TestViewCarriesTheRestartWindow(t *testing.T) {
	w := fleet.RestartWindow{Since: t0, Until: t0.Add(3 * time.Minute), By: "alice"}
	v, _ := New(fakeReader{states: []fleet.ServerState{{ID: "a", Restarting: true, Restart: w}}}, nil).Server("a")
	if !v.Restarting || v.Restart != (ui.RestartWindow{Since: t0, Until: t0.Add(3 * time.Minute), By: "alice"}) {
		t.Fatalf("view %+v", v)
	}
}
