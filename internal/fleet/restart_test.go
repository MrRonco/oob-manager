package fleet

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

// endRecorder collects window ends (the callback must not block).
type endRecorder struct{ ch chan RestartEnd }

func newEnds() endRecorder { return endRecorder{ch: make(chan RestartEnd, 4)} }

func (e endRecorder) done(end RestartEnd) { e.ch <- end }

func (e endRecorder) wait(t *testing.T) RestartEnd {
	t.Helper()
	select {
	case end := <-e.ch:
		return end
	case <-time.After(10 * time.Second):
		t.Fatal("the restart window did not end")
		return RestartEnd{}
	}
}

func (e endRecorder) none(t *testing.T) {
	t.Helper()
	select {
	case end := <-e.ch:
		t.Fatalf("unexpected window end %+v", end)
	default:
	}
}

func restartFleet(t *testing.T, d bmc.Driver) harness {
	t.Helper()
	h := start(t, Config{Targets: []Target{target("a", "fa", d)}, Interval: time.Minute,
		RestartQuiet: time.Minute, RestartRetry: 30 * time.Second})
	waitFor(t, "first poll", func() bool { return h.state(t, "a").HasSnapshot })
	return h
}

// stepTo advances the fake clock by d once the poller is parked and waits until it has
// attempted a poll at the new time (or skipped the cycle, when skip is set).
func stepTo(t *testing.T, h harness, d *countingDriver, by time.Duration, wantSnaps int) {
	t.Helper()
	h.tick(t, 1, by)
	waitFor(t, fmt.Sprintf("%d snapshot reads", wantSnaps), func() bool { s, _, _, _ := d.get(); return s == wantSnaps })
}

// stepAfterWake is stepTo for the first step after ExpectRestart: its wake-up left the
// poller's earlier timer registered with the fake clock, so two waiters are pending.
func stepAfterWake(t *testing.T, h harness, d *countingDriver, by time.Duration, wantSnaps int) {
	t.Helper()
	h.tick(t, 2, by)
	waitFor(t, fmt.Sprintf("%d snapshot reads", wantSnaps), func() bool { s, _, _, _ := d.get(); return s == wantSnaps })
}

func TestRestartWindowWaitsThenSeesTheBMCBack(t *testing.T) {
	d := &countingDriver{}
	h := restartFleet(t, d)
	_, _, _, probes := d.get()
	ends := newEnds()
	since := h.clock.Now()
	if err := h.fleet.ExpectRestart("a", RestartWindow{Since: since, Until: since.Add(5 * time.Minute), By: "alice"}, ends.done); err != nil {
		t.Fatal(err)
	}
	if s := h.state(t, "a"); !s.Restarting || s.Restart.By != "alice" || !s.Restart.Until.Equal(since.Add(5*time.Minute)) {
		t.Fatalf("window not published: %+v", s)
	}
	d.setFail(true)
	stepAfterWake(t, h, d, time.Minute, 2) // quiet over: first retry fails
	stepTo(t, h, d, 30*time.Second, 3)
	waitFor(t, "failure recorded", func() bool { return h.state(t, "a").LastError == bmc.ClassUnreachable })
	s := h.state(t, "a")
	if s.ConsecutiveFailures != 0 || !s.FailingSince.IsZero() || s.Breaker != BreakerClosed || !s.Restarting {
		t.Fatalf("a failure inside the window was counted: %+v", s)
	}
	d.setFail(false)
	stepTo(t, h, d, 30*time.Second, 4)
	end := ends.wait(t)
	if end.Outcome != RestartBack || !end.At.Equal(since.Add(2*time.Minute)) || !end.State.HasSnapshot ||
		end.State.Restarting || !end.State.HasCapabilities {
		t.Fatalf("end %+v", end)
	}
	if _, _, _, p := d.get(); p != probes+1 {
		t.Fatalf("the inventory tier did not run right after the return: probes %d -> %d", probes, p)
	}
	if s := h.state(t, "a"); s.Restarting || s.LastError != bmc.ClassNone {
		t.Fatalf("after the return: %+v", s)
	}
	ends.none(t)
}

func TestRestartWindowQuietPeriodSkipsPolls(t *testing.T) {
	d := &countingDriver{}
	h := start(t, Config{Targets: []Target{target("a", "fa", d)}, Interval: 30 * time.Second,
		RestartQuiet: 2 * time.Minute, RestartRetry: 30 * time.Second})
	waitFor(t, "first poll", func() bool { return h.state(t, "a").HasSnapshot })
	now := h.clock.Now()
	if err := h.fleet.ExpectRestart("a", RestartWindow{Since: now, Until: now.Add(5 * time.Minute)}, nil); err != nil {
		t.Fatal(err)
	}
	h.tick(t, 2, 30*time.Second) // the wake-up re-parked the poller for the rest of the quiet period
	if s, _, _, _ := d.get(); s != 1 {
		t.Fatalf("polled during the quiet period (%d reads)", s)
	}
	h.tick(t, 1, 90*time.Second)
	waitFor(t, "first retry", func() bool { s, _, _, _ := d.get(); return s == 2 })
	if s := h.state(t, "a"); !s.LastSuccess.Equal(now.Add(2 * time.Minute)) {
		t.Fatalf("retry at %v, want the end of the quiet period", s.LastSuccess)
	}
}

func TestRestartWindowTimesOutThenCountsFailures(t *testing.T) {
	d := &countingDriver{}
	h := restartFleet(t, d)
	ends := newEnds()
	since := h.clock.Now()
	deadline := since.Add(2 * time.Minute)
	if err := h.fleet.ExpectRestart("a", RestartWindow{Since: since, Until: deadline}, ends.done); err != nil {
		t.Fatal(err)
	}
	d.setFail(true)
	stepAfterWake(t, h, d, time.Minute, 2)
	stepTo(t, h, d, 30*time.Second, 3)
	stepTo(t, h, d, 30*time.Second, 4) // at the deadline: the window ends and this poll counts
	end := ends.wait(t)
	if end.Outcome != RestartTimeout || !end.At.Equal(deadline) {
		t.Fatalf("end %+v", end)
	}
	waitFor(t, "counted failure", func() bool { return h.state(t, "a").ConsecutiveFailures == 1 })
	if s := h.state(t, "a"); !s.FailingSince.Equal(deadline) || s.Restarting {
		t.Fatalf("after the timeout: %+v", s)
	}
}

func TestRestartWindowIsHiddenOnceItsDeadlinePassed(t *testing.T) {
	d := &countingDriver{}
	h := restartFleet(t, d)
	now := h.clock.Now()
	if err := h.fleet.ExpectRestart("a", RestartWindow{Since: now.Add(-10 * time.Minute), Until: now.Add(-time.Minute)}, nil); err != nil {
		t.Fatal(err)
	}
	if h.state(t, "a").Restarting {
		t.Fatal("a window past its deadline is shown as restarting")
	}
}

func TestExpectRestartRefusals(t *testing.T) {
	d := &countingDriver{}
	h := restartFleet(t, d)
	now := h.clock.Now()
	w := RestartWindow{Since: now, Until: now.Add(time.Minute)}
	if err := h.fleet.ExpectRestart("nope", w, nil); !errors.Is(err, ErrUnknownServer) {
		t.Fatalf("unknown: %v", err)
	}
	if err := h.fleet.ExpectRestart("a", RestartWindow{Since: now, Until: now}, nil); err == nil {
		t.Fatal("a window without a deadline was accepted")
	}
	ends := newEnds()
	if err := h.fleet.ExpectRestart("a", w, ends.done); err != nil {
		t.Fatal(err)
	}
	if err := h.fleet.ExpectRestart("a", w, nil); !errors.Is(err, ErrRestarting) {
		t.Fatalf("second window: %v", err)
	}
	if !h.fleet.CancelRestart("a") || h.fleet.CancelRestart("a") || h.fleet.CancelRestart("nope") {
		t.Fatal("CancelRestart results")
	}
	ends.none(t)
	if h.state(t, "a").Restarting {
		t.Fatal("a cancelled window is still shown")
	}
}

func TestExpectRestartRefusesAPausedServer(t *testing.T) {
	d := &pinDriver{mismatch: true}
	h := start(t, Config{Targets: []Target{target("a", "fa", d)}, Interval: time.Minute})
	waitFor(t, "paused", func() bool { return h.state(t, "a").Paused })
	now := h.clock.Now()
	if err := h.fleet.ExpectRestart("a", RestartWindow{Since: now, Until: now.Add(time.Minute)}, nil); !errors.Is(err, ErrPaused) {
		t.Fatalf("err = %v", err)
	}
}

func TestRestartWindowEndsWhenTheCertificateChanges(t *testing.T) {
	d := &pinDriver{}
	h := start(t, Config{Targets: []Target{target("a", "fa", d)}, Interval: time.Minute,
		RestartQuiet: time.Minute, RestartRetry: 30 * time.Second})
	waitFor(t, "first poll", func() bool { return h.state(t, "a").HasSnapshot })
	ends := newEnds()
	now := h.clock.Now()
	if err := h.fleet.ExpectRestart("a", RestartWindow{Since: now, Until: now.Add(5 * time.Minute)}, ends.done); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.mismatch = true
	d.mu.Unlock()
	h.tick(t, 2, time.Minute)
	if end := ends.wait(t); end.Outcome != RestartTimeout || !end.State.PinMismatch {
		t.Fatalf("end %+v", end)
	}
}

func TestApplyEndsTheWindowOfARebuiltServerOnly(t *testing.T) {
	d := &countingDriver{}
	h := restartFleet(t, d)
	now := h.clock.Now()
	ends := newEnds()
	if err := h.fleet.ExpectRestart("a", RestartWindow{Since: now, Until: now.Add(5 * time.Minute)}, ends.done); err != nil {
		t.Fatal(err)
	}
	if err := h.fleet.Apply([]Target{target("a", "fa", &countingDriver{})}); err != nil {
		t.Fatal(err)
	}
	ends.none(t)
	if !h.state(t, "a").Restarting {
		t.Fatal("an unchanged server lost its window")
	}
	if err := h.fleet.Apply([]Target{target("a", "fa-moved", &countingDriver{})}); err != nil {
		t.Fatal(err)
	}
	if end := ends.wait(t); end.Outcome != RestartConfigChanged {
		t.Fatalf("end %+v", end)
	}
	if h.state(t, "a").Restarting {
		t.Fatal("the rebuilt server inherited the window")
	}
}

// TestRestartWindowRecoveryAtTheDeadline (review C-M1): the poll at the deadline is
// still taken; when it succeeds the BMC is back, not timed out.
func TestRestartWindowRecoveryAtTheDeadline(t *testing.T) {
	d := &countingDriver{}
	h := restartFleet(t, d)
	ends := newEnds()
	since := h.clock.Now()
	deadline := since.Add(2 * time.Minute)
	if err := h.fleet.ExpectRestart("a", RestartWindow{Since: since, Until: deadline}, ends.done); err != nil {
		t.Fatal(err)
	}
	d.setFail(true)
	stepAfterWake(t, h, d, time.Minute, 2)
	stepTo(t, h, d, 30*time.Second, 3)
	d.setFail(false)
	stepTo(t, h, d, 30*time.Second, 4) // exactly at the deadline, and the BMC answers
	if end := ends.wait(t); end.Outcome != RestartBack || !end.At.Equal(deadline) {
		t.Fatalf("end %+v", end)
	}
	if s := h.state(t, "a"); s.ConsecutiveFailures != 0 || !s.FailingSince.IsZero() {
		t.Fatalf("after the return: %+v", s)
	}
}

// TestExpectRestartCapsTheWindow (review S-L5): a window longer than MaxRestartWindow is
// refused, so a stored deadline can never hide an outage for long.
func TestExpectRestartCapsTheWindow(t *testing.T) {
	h := restartFleet(t, &countingDriver{})
	now := h.clock.Now()
	if err := h.fleet.ExpectRestart("a", RestartWindow{Since: now, Until: now.Add(MaxRestartWindow + time.Second)}, nil); err == nil {
		t.Fatal("an overlong window was accepted")
	}
	if err := h.fleet.ExpectRestart("a", RestartWindow{Since: now, Until: now.Add(MaxRestartWindow)}, nil); err != nil {
		t.Fatal(err)
	}
}

// TestExpectRestartRacesApply (review C-L1): a window opened on a poller that a
// concurrent Apply retires either fires config_changed or is refused, never left open
// on a retired poller.
func TestExpectRestartRacesApply(t *testing.T) {
	h := restartFleet(t, &countingDriver{})
	for i := range 50 {
		now := h.clock.Now()
		ends := newEnds()
		errc := make(chan error, 1)
		go func() {
			errc <- h.fleet.ExpectRestart("a", RestartWindow{Since: now, Until: now.Add(time.Minute)}, ends.done)
		}()
		if err := h.fleet.Apply([]Target{target("a", fmt.Sprintf("fp-%d", i), &countingDriver{})}); err != nil {
			t.Fatal(err)
		}
		err := <-errc
		ended := false
		select {
		case <-ends.ch:
			ended = true
		default:
		}
		s := h.state(t, "a")
		switch {
		case err != nil && (ended || s.Restarting):
			t.Fatalf("refused window still open or ended: %v ended %v", err, ended)
		case err == nil && !ended && !s.Restarting:
			t.Fatal("an accepted window vanished without its callback")
		}
		h.fleet.CancelRestart("a")
	}
}
