package fleet

import (
	"context"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

// powerDriver answers snapshots with a settable power state and snapshot time.
type powerDriver struct {
	mu    sync.Mutex
	state bmc.PowerState
	at    time.Time
}

func (d *powerDriver) set(s bmc.PowerState, at time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.state, d.at = s, at
}

func (d *powerDriver) Probe(context.Context) (bmc.Capabilities, error) {
	return bmc.NewCapabilities(bmc.CapabilityParams{Flags: bmc.CapabilityFlags{ProbedAt: t0}}), nil
}

func (d *powerDriver) Snapshot(context.Context) (bmc.Snapshot, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: d.at, PowerState: d.state, Health: bmc.HealthOK}), nil
}

func (d *powerDriver) EventLog(context.Context, time.Time) (bmc.EventLog, error) {
	return bmc.NewEventLog("/sel", nil, true), nil
}

func (d *powerDriver) Inventory(context.Context) (bmc.Inventory, error) {
	return bmc.Inventory{}, bmc.ErrBMC
}

// pollAt sets the state the next poll reads, then advances the clock by a minute and
// waits for that poll. The driver is set first: advancing the clock wakes the poller,
// which could otherwise snapshot the previous state.
func pollAt(t *testing.T, h harness, d *powerDriver, st bmc.PowerState) ServerState {
	t.Helper()
	d.set(st, h.clock.Now().Add(time.Minute))
	h.tick(t, 1, time.Minute)
	waitFor(t, "poll", func() bool { return h.state(t, "a").LastSuccess.Equal(h.clock.Now()) })
	return h.state(t, "a")
}

// TestPowerSinceTracksTransitions: PowerSince is when the current power state was first
// seen; it is zero while the onset is unknown (the first poll already found that state)
// and moves only when the state changes.
func TestPowerSinceTracksTransitions(t *testing.T) {
	d := &powerDriver{state: bmc.PowerOn, at: t0}
	h := start(t, Config{Targets: []Target{{ID: "a", Driver: d}}, Interval: time.Minute})
	waitFor(t, "first poll", func() bool { return h.state(t, "a").HasSnapshot })
	if s := h.state(t, "a"); !s.PowerSince.IsZero() {
		t.Fatalf("onset of the first observed state must be unknown, got %v", s.PowerSince)
	}

	d.set(bmc.PowerOff, t0)
	h.tick(t, 1, time.Minute)
	waitFor(t, "off poll", func() bool { return h.state(t, "a").Snapshot.PowerState() == bmc.PowerOff })
	off := h.state(t, "a")
	if !off.PowerSince.Equal(h.clock.Now()) {
		t.Fatalf("PowerSince = %v, want the poll that saw Off (%v)", off.PowerSince, h.clock.Now())
	}

	h.tick(t, 1, time.Minute) // still off: the onset does not move
	waitFor(t, "second off poll", func() bool { return h.state(t, "a").LastSuccess.Equal(h.clock.Now()) })
	if s := h.state(t, "a"); !s.PowerSince.Equal(off.PowerSince) {
		t.Fatalf("PowerSince moved without a state change: %v -> %v", off.PowerSince, s.PowerSince)
	}

	d.set(bmc.PowerOn, t0)
	h.tick(t, 1, time.Minute)
	waitFor(t, "on poll", func() bool { return h.state(t, "a").Snapshot.PowerState() == bmc.PowerOn })
	if s := h.state(t, "a"); !s.PowerSince.Equal(h.clock.Now()) {
		t.Fatalf("PowerSince after power on = %v, want %v", s.PowerSince, h.clock.Now())
	}
}

// TestObservePowerOverlaysUntilAPollConfirms (audit R2-08): a verified power action is
// published at once over the last poll's snapshot, survives a poll whose data is older
// than the verification, is kept (with its cause) by a poll that confirms the state, and
// yields to a later poll that sees another state.
func TestObservePowerOverlaysUntilAPollConfirms(t *testing.T) {
	d := &powerDriver{state: bmc.PowerOn, at: t0}
	h := start(t, Config{Targets: []Target{{ID: "a", Driver: d}}, Interval: time.Minute})
	waitFor(t, "first poll", func() bool { return h.state(t, "a").HasSnapshot })

	verified := h.clock.Now().Add(20 * time.Second)
	obs := PowerObservation{State: bmc.PowerOff, At: verified, Action: "force-off", By: "admin"}
	if h.fleet.ObservePower("nope", obs) || !h.fleet.ObservePower("a", obs) {
		t.Fatal("ObservePower: unknown id accepted, or the overlay refused")
	}
	s := h.state(t, "a")
	if s.Snapshot.PowerState() != bmc.PowerOff || !s.Snapshot.PowerAsOf().Equal(verified) || !s.PowerSince.Equal(verified) ||
		s.PowerCause != (PowerCause{Action: "force-off", By: "admin", At: verified}) || !s.LastSuccess.Equal(t0) {
		t.Fatalf("after the observation: %+v", s)
	}
	if h.fleet.ObservePower("a", PowerObservation{State: bmc.PowerOn, At: verified.Add(-time.Second)}) {
		t.Fatal("an older observation replaced a newer one")
	}

	// A poll whose snapshot predates the verification (it started before the reset took
	// effect) does not undo it.
	h.tick(t, 1, time.Minute)
	d.set(bmc.PowerOn, verified.Add(-5*time.Second))
	waitFor(t, "stale poll", func() bool { return h.state(t, "a").LastSuccess.Equal(h.clock.Now()) })
	if s = h.state(t, "a"); s.Snapshot.PowerState() != bmc.PowerOff || s.PowerCause.By != "admin" || !s.PowerSince.Equal(verified) {
		t.Fatalf("an older poll undid the verified state: %+v", s)
	}

	// A newer poll that confirms Off keeps the onset and the cause.
	if s = pollAt(t, h, d, bmc.PowerOff); s.Snapshot.PowerState() != bmc.PowerOff || s.PowerCause.Action != "force-off" ||
		!s.PowerSince.Equal(verified) || !s.Snapshot.PowerAsOf().Equal(s.Snapshot.TakenAt()) {
		t.Fatalf("a confirming poll lost the context: %+v", s)
	}

	// A newer poll that sees On is the newest truth: new onset, no cause.
	if s = pollAt(t, h, d, bmc.PowerOn); s.Snapshot.PowerState() != bmc.PowerOn || s.PowerCause != (PowerCause{}) ||
		!s.PowerSince.Equal(h.clock.Now()) {
		t.Fatalf("a contradicting poll kept the stale context: %+v", s)
	}
}
