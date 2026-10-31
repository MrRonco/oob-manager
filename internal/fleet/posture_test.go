package fleet

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

// postureFunc is a scripted posture tier: it counts calls and can fail or block.
type postureFunc struct {
	mu      sync.Mutex
	calls   int
	fail    bool
	block   chan struct{} // non-nil: each call waits for a receive
	drivers []bmc.Driver
	// transportFail: the posture comes back without an error but with a probe that
	// timed out; started is Posture.Started (zero: left unset).
	transportFail bool
	started       time.Time
}

func (f *postureFunc) run(ctx context.Context, d bmc.Driver) (bmc.Posture, error) {
	f.mu.Lock()
	f.calls++
	n, fail, block, tf, started := f.calls, f.fail, f.block, f.transportFail, f.started
	f.drivers = append(f.drivers, d)
	f.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return bmc.Posture{}, ctx.Err()
		}
	}
	if fail {
		return bmc.Posture{}, bmc.ErrTimeout
	}
	p := bmc.Posture{Started: started, Duration: time.Duration(n) * time.Second}
	if tf {
		p.SSH.Read = bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassTimeout}
	}
	return p, nil
}

func (f *postureFunc) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *postureFunc) set(fn func(*postureFunc)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func TestPostureTierRunsAtStartAndThenEveryPeriod(t *testing.T) {
	d, pf := &tierDriver{}, &postureFunc{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d, Posture: pf.run}}, Interval: time.Minute,
		InventoryEvery: time.Hour, PostureEvery: 10 * time.Minute})
	waitFor(t, "first posture", func() bool { return h.state(t, "x").HasPosture })
	s := h.state(t, "x")
	if !s.PostureEnabled || !s.PostureAsOf.Equal(t0) || s.PostureError != bmc.ClassNone || s.Posture.Duration != time.Second ||
		s.PostureEvery != 10*time.Minute || s.PostureOverdue || s.PostureRunning {
		t.Fatalf("first posture %+v", s)
	}
	if pf.drivers[0] != d {
		t.Fatal("the tier must get the poller's own driver (one BMC session)")
	}
	for i := 1; i <= 9; i++ {
		h.tick(t, 1, time.Minute)
		waitFor(t, "poll", func() bool { n, _, _ := d.counts(); return n == i+1 })
	}
	if n := pf.count(); n != 1 {
		t.Fatalf("posture ran %d times before its period", n)
	}
	h.tick(t, 1, time.Minute) // t0+10m
	waitFor(t, "second posture", func() bool { return pf.count() == 2 })
	waitFor(t, "published", func() bool { return h.state(t, "x").PostureAsOf.Equal(t0.Add(10 * time.Minute)) })
}

func TestPostureFailureKeepsTheLastAndRetries(t *testing.T) {
	d, pf := &tierDriver{}, &postureFunc{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d, Posture: pf.run}}, Interval: time.Minute,
		EventsEvery: 5 * time.Minute, PostureEvery: 30 * time.Minute})
	waitFor(t, "first posture", func() bool { return h.state(t, "x").HasPosture })
	pf.set(func(f *postureFunc) { f.fail = true })
	for i := range 30 {
		h.tick(t, 1, time.Minute)
		waitFor(t, "poll", func() bool { n, _, _ := d.counts(); return n == i+2 })
	}
	waitFor(t, "failed attempt", func() bool { return pf.count() == 2 })
	waitFor(t, "error recorded", func() bool { return h.state(t, "x").PostureError == bmc.ClassTimeout })
	if s := h.state(t, "x"); !s.HasPosture || !s.PostureAsOf.Equal(t0) {
		t.Fatalf("the last good posture is kept: %+v", s)
	}
	for range 5 {
		h.tick(t, 1, time.Minute)
	}
	waitFor(t, "retried after 5 min, not 30", func() bool { return pf.count() == 3 })
	s := h.state(t, "x")
	if !s.PostureOverdue {
		t.Fatalf("35 min old with a 30 min period plus two intervals is overdue: %+v", s)
	}
}

func TestRequestPostureRunsAtOnce(t *testing.T) {
	d, pf := &tierDriver{}, &postureFunc{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d, Posture: pf.run}}, Interval: time.Minute})
	waitFor(t, "first posture", func() bool { return h.state(t, "x").HasPosture })
	waitFor(t, "idle", func() bool { return h.clock.pending() == 1 })
	if err := h.fleet.RequestPosture("x"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "requested posture", func() bool { return pf.count() == 2 })
	waitFor(t, "request consumed", func() bool { s := h.state(t, "x"); return !s.PostureRequested && s.Posture.Duration == 2*time.Second })
	if n, _, _ := d.counts(); n != 2 {
		t.Fatalf("a request runs one cycle (snapshot first): %d snapshots", n)
	}
}

func TestPostureRunningIsPublished(t *testing.T) {
	d, pf := &tierDriver{}, &postureFunc{block: make(chan struct{})}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d, Posture: pf.run}}})
	waitFor(t, "running", func() bool { return h.state(t, "x").PostureRunning })
	if s := h.state(t, "x"); !s.HasSnapshot || s.HasPosture {
		t.Fatalf("while the tier runs: %+v", s)
	}
	pf.block <- struct{}{}
	waitFor(t, "done", func() bool { s := h.state(t, "x"); return s.HasPosture && !s.PostureRunning })
}

func TestRequestPostureRefusals(t *testing.T) {
	pf := &postureFunc{}
	h := start(t, Config{Targets: []Target{{ID: "with", Driver: &tierDriver{}, Posture: pf.run}, {ID: "without", Driver: &tierDriver{}}}})
	waitFor(t, "polled", func() bool { return h.state(t, "with").HasPosture && h.state(t, "without").HasInventory })
	if err := h.fleet.RequestPosture("nope"); !errors.Is(err, ErrUnknownServer) {
		t.Fatalf("unknown server: %v", err)
	}
	if err := h.fleet.RequestPosture("without"); !errors.Is(err, ErrNoPosture) {
		t.Fatalf("no posture tier: %v", err)
	}
	if s := h.state(t, "without"); s.PostureEnabled || s.HasPosture {
		t.Fatalf("no tier, no posture: %+v", s)
	}
	if err := h.fleet.RequestPosture("with"); err != nil {
		t.Fatal(err)
	}
	if err := h.fleet.RequestPosture("with"); err != nil {
		t.Fatalf("a second request before the first ran is folded into it: %v", err)
	}
}

func TestRequestPosturePaused(t *testing.T) {
	pf := &postureFunc{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: &pinDriver{mismatch: true}, Posture: pf.run}}})
	waitFor(t, "paused", func() bool { return h.state(t, "x").Paused })
	if err := h.fleet.RequestPosture("x"); !errors.Is(err, ErrPaused) {
		t.Fatalf("paused: %v", err)
	}
	if pf.count() != 0 {
		t.Fatal("no posture without a good snapshot")
	}
}

// TestPostureWithTransportFailuresKeepsTheLastAndRetries: a run that came back without
// an error but with a probe that could not reach the BMC (a timeout while the deadline
// ran out) does not replace the posture; it is recorded as a failed run and retried
// within the events period, like an error.
func TestPostureWithTransportFailuresKeepsTheLastAndRetries(t *testing.T) {
	d, pf := &tierDriver{}, &postureFunc{}
	started := t0.Add(-time.Hour)
	pf.set(func(f *postureFunc) { f.started = started })
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d, Posture: pf.run}}, Interval: time.Minute,
		EventsEvery: 5 * time.Minute, PostureEvery: 30 * time.Minute})
	waitFor(t, "first posture", func() bool { return h.state(t, "x").HasPosture })
	if s := h.state(t, "x"); !s.PostureAsOf.Equal(started) {
		t.Fatalf("PostureAsOf is when the run started, not the cycle: %+v", s.PostureAsOf)
	}
	pf.set(func(f *postureFunc) { f.transportFail = true })
	for i := range 30 {
		h.tick(t, 1, time.Minute)
		waitFor(t, "poll", func() bool { n, _, _ := d.counts(); return n == i+2 })
	}
	waitFor(t, "second run", func() bool { return pf.count() == 2 })
	waitFor(t, "error recorded", func() bool { return h.state(t, "x").PostureError == bmc.ClassTimeout })
	if s := h.state(t, "x"); s.Posture.Duration != time.Second || !s.PostureAsOf.Equal(started) {
		t.Fatalf("the previous posture is kept: %+v", s)
	}
	for range 5 {
		h.tick(t, 1, time.Minute)
	}
	waitFor(t, "retried after 5 min, not 30", func() bool { return pf.count() == 3 })
}

// TestPostureFailuresBackOff: failed runs are retried after the events period, then
// after twice that, doubling up to the posture period; a success resets the backoff.
func TestPostureFailuresBackOff(t *testing.T) {
	d, pf := &tierDriver{}, &postureFunc{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d, Posture: pf.run}}, Interval: time.Minute,
		EventsEvery: 5 * time.Minute, PostureEvery: 30 * time.Minute})
	waitFor(t, "first posture", func() bool { return h.state(t, "x").HasPosture })
	pf.set(func(f *postureFunc) { f.fail = true })
	// Runs are due at t0+30 (the period; it fails), then +5, +10, +20 and +30 (the cap).
	runs := map[int]int{30: 2, 35: 3, 45: 4, 65: 5, 95: 6, 125: 7}
	for minute := 1; minute <= 125; minute++ {
		h.tick(t, 1, time.Minute)
		waitFor(t, "poll", func() bool { n, _, _ := d.counts(); return n == minute+1 })
		if want, ok := runs[minute]; ok {
			waitFor(t, "run", func() bool { return pf.count() == want })
		}
		allowed := 1 // the run at start
		if k := largestKeyAtMost(runs, minute); k > 0 {
			allowed = runs[k]
		}
		if pf.count() > allowed {
			t.Fatalf("minute %d: %d runs, more than the backoff allows (%d)", minute, pf.count(), allowed)
		}
	}
	// A success resets the backoff: the next run is one period later.
	pf.set(func(f *postureFunc) { f.fail = false })
	for minute := 126; minute <= 155; minute++ {
		h.tick(t, 1, time.Minute)
		waitFor(t, "poll", func() bool { n, _, _ := d.counts(); return n == minute+1 })
	}
	waitFor(t, "run after the cap", func() bool { return pf.count() == 8 })
	pf.set(func(f *postureFunc) { f.fail = true })
	for minute := 156; minute <= 190; minute++ {
		h.tick(t, 1, time.Minute)
		waitFor(t, "poll", func() bool { n, _, _ := d.counts(); return n == minute+1 })
	}
	waitFor(t, "period, then a 5 min retry", func() bool { return pf.count() == 10 })
}

// largestKeyAtMost is the largest key of m that is <= n (0 when none).
func largestKeyAtMost(m map[int]int, n int) int {
	best := 0
	for k := range m {
		if k <= n && k > best {
			best = k
		}
	}
	return best
}
