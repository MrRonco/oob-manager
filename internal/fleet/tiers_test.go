package fleet

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

// tierDriver is a scripted driver: each tier can fail or take time (ctx-aware).
type tierDriver struct {
	mu                   sync.Mutex
	snaps, events, invs  int
	lcs, closes          int
	failSnap, failEvents bool
	failInv              bool
	snapDelay, slowDelay time.Duration
}

func (d *tierDriver) wait(ctx context.Context, delay time.Duration) error {
	if delay == 0 {
		return nil
	}
	select {
	case <-time.After(delay):
		return nil
	case <-ctx.Done():
		return bmc.ErrTimeout
	}
}

func (d *tierDriver) Probe(context.Context) (bmc.Capabilities, error) {
	return bmc.NewCapabilities(bmc.CapabilityParams{Flags: bmc.CapabilityFlags{SEL: true, ProbedAt: t0}}), nil
}

func (d *tierDriver) Snapshot(ctx context.Context) (bmc.Snapshot, error) {
	d.mu.Lock()
	d.snaps++
	fail, delay := d.failSnap, d.snapDelay
	d.mu.Unlock()
	if err := d.wait(ctx, delay); err != nil {
		return bmc.Snapshot{}, err
	}
	if fail {
		return bmc.Snapshot{}, bmc.ErrUnreachable
	}
	return bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: t0, Health: bmc.HealthOK}), nil
}

func (d *tierDriver) EventLog(ctx context.Context, _ time.Time) (bmc.EventLog, error) {
	d.mu.Lock()
	d.events++
	fail, delay := d.failEvents, d.slowDelay
	d.mu.Unlock()
	if err := d.wait(ctx, delay); err != nil {
		return bmc.EventLog{}, err
	}
	if fail {
		return bmc.EventLog{}, bmc.ErrBMC
	}
	return bmc.NewEventLog("/sel", nil, true), nil
}

func (d *tierDriver) LifecycleLog(context.Context, time.Time) (bmc.EventLog, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.lcs++
	return bmc.NewEventLog("/lc", nil, true), nil
}

func (d *tierDriver) Inventory(ctx context.Context) (bmc.Inventory, error) {
	d.mu.Lock()
	d.invs++
	fail, delay := d.failInv, d.slowDelay
	d.mu.Unlock()
	if err := d.wait(ctx, delay); err != nil {
		return bmc.Inventory{}, err
	}
	if fail {
		return bmc.Inventory{}, bmc.ErrBMC
	}
	return bmc.Inventory{}, nil
}

func (d *tierDriver) Close(context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closes++
	return nil
}

func (d *tierDriver) set(f func(*tierDriver)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f(d)
}

func (d *tierDriver) counts() (snaps, events, invs int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.snaps, d.events, d.invs
}

func TestPerTargetIntervalIsRaisedToCycleTimeout(t *testing.T) {
	slow, fast := &tierDriver{}, &tierDriver{}
	h := start(t, Config{Interval: time.Minute, Targets: []Target{
		{ID: "slow", Driver: slow, CycleTimeout: 150 * time.Second},
		{ID: "fast", Driver: fast},
	}})
	waitFor(t, "first polls", func() bool { a, _, _ := slow.counts(); b, _, _ := fast.counts(); return a == 1 && b == 1 })
	if s := h.state(t, "slow"); s.Interval != 150*time.Second || s.StaleAfter != 450*time.Second {
		t.Fatalf("slow interval %v stale %v", s.Interval, s.StaleAfter)
	}
	if s := h.state(t, "fast"); s.Interval != time.Minute || s.StaleAfter != 3*time.Minute {
		t.Fatalf("fast interval %v stale %v", s.Interval, s.StaleAfter)
	}
	h.tick(t, 2, time.Minute)
	waitFor(t, "fast polled again", func() bool { n, _, _ := fast.counts(); return n == 2 })
	if n, _, _ := slow.counts(); n != 1 {
		t.Fatalf("slow server polled before its interval: %d", n)
	}
	h.tick(t, 2, time.Minute)
	waitFor(t, "fast third", func() bool { n, _, _ := fast.counts(); return n == 3 })
	h.tick(t, 2, 30*time.Second) // t0+150s
	waitFor(t, "slow polled at 150 s", func() bool { n, _, _ := slow.counts(); return n == 2 })
}

func TestTierAsOfOverdueAndRetry(t *testing.T) {
	d := &tierDriver{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d}}, Interval: time.Minute,
		EventsEvery: 5 * time.Minute, InventoryEvery: 30 * time.Minute})
	waitFor(t, "first cycle", func() bool { return h.state(t, "x").HasInventory })
	s := h.state(t, "x")
	if !s.SELAsOf.Equal(t0) || !s.LifecycleAsOf.Equal(t0) || !s.InventoryAsOf.Equal(t0) || s.SELOverdue || s.InventoryOverdue {
		t.Fatalf("first cycle tiers %+v", s)
	}
	d.set(func(d *tierDriver) { d.failEvents, d.failInv = true, true })
	for i := 1; i <= 8; i++ {
		h.tick(t, 1, time.Minute)
		waitFor(t, "poll", func() bool { n, _, _ := d.counts(); return n == i+1 })
	}
	// t0+8m: the SEL refresh at t0+5m failed; the last good SEL (t0) is 8 min old,
	// beyond 5 min + 2 intervals, so the section is overdue. Inventory is not due yet.
	s = h.state(t, "x")
	if !s.SELOverdue || !s.SELAsOf.Equal(t0) || s.SELError != bmc.ClassBMC || !s.HasSEL || s.InventoryOverdue {
		t.Fatalf("t0+8m %+v", s)
	}
	d.set(func(d *tierDriver) { d.failEvents = false })
	h.tick(t, 1, time.Minute)
	h.tick(t, 1, time.Minute) // t0+10m: SEL retried after the 5 min retry period
	waitFor(t, "SEL refreshed", func() bool { return h.state(t, "x").SELAsOf.Equal(t0.Add(10 * time.Minute)) })
	if s := h.state(t, "x"); s.SELOverdue || s.SELError != bmc.ClassNone {
		t.Fatalf("after recovery %+v", s)
	}
	// Inventory is due at t0+30m; it fails, so it is retried 5 min later, not 30.
	for i := 0; i < 20; i++ {
		h.tick(t, 1, time.Minute)
	}
	waitFor(t, "inventory attempt at 30m", func() bool { _, _, inv := d.counts(); return inv == 2 })
	for i := 0; i < 5; i++ {
		h.tick(t, 1, time.Minute)
	}
	waitFor(t, "inventory retry at 35m", func() bool { _, _, inv := d.counts(); return inv == 3 })
}

func TestTiersHaveSeparateBudgets(t *testing.T) {
	d := &tierDriver{snapDelay: 150 * time.Millisecond, slowDelay: 150 * time.Millisecond}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d, CycleTimeout: 250 * time.Millisecond}}})
	waitFor(t, "inventory", func() bool { s := h.state(t, "x"); return s.HasInventory || s.InventoryError != "" })
	if s := h.state(t, "x"); !s.HasSEL || !s.HasInventory || s.SELError != "" || s.InventoryError != "" {
		t.Fatalf("each tier must get its own budget: %+v", s)
	}
}

func TestPollDurationAndRecoveryLogs(t *testing.T) {
	var buf syncBuffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	d := &tierDriver{snapDelay: 20 * time.Millisecond}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d}}, Interval: time.Minute, Logger: log})
	waitFor(t, "first poll", func() bool { return h.state(t, "x").HasSnapshot })
	if got := h.state(t, "x").LastPollDuration; got < 20*time.Millisecond || got > 5*time.Second {
		t.Fatalf("LastPollDuration %v", got)
	}
	d.set(func(d *tierDriver) { d.failSnap = true })
	h.tick(t, 1, time.Minute)
	waitFor(t, "fail 1", func() bool { return h.state(t, "x").ConsecutiveFailures == 1 })
	h.tick(t, 1, time.Minute)
	waitFor(t, "fail 2", func() bool { return h.state(t, "x").ConsecutiveFailures == 2 })
	d.set(func(d *tierDriver) { d.failSnap = false })
	h.tick(t, 1, time.Minute)
	waitFor(t, "recovered", func() bool { return h.state(t, "x").Reachable() })
	h.tick(t, 1, time.Minute)
	waitFor(t, "another ok poll", func() bool { return strings.Count(buf.String(), "poll ok") == 3 })
	out := buf.String()
	if strings.Count(out, "fleet: poll recovered") != 1 || !strings.Contains(out, "level=INFO msg=\"fleet: poll recovered\" server=x failures=2") {
		t.Fatalf("want exactly one INFO recovery line with the failure count:\n%s", out)
	}
	if strings.Count(out, "level=DEBUG msg=\"fleet: poll ok\" server=x duration=") < 3 {
		t.Fatalf("want a DEBUG line per successful poll:\n%s", out)
	}
}

func TestRunClosesDriversOnShutdown(t *testing.T) {
	d := &tierDriver{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d}}})
	waitFor(t, "first poll", func() bool { return h.state(t, "x").HasSnapshot })
	h.stop()
	if d.closes != 1 {
		t.Fatalf("Close called %d times", d.closes)
	}
}

func TestShutdownDeletesRedfishSessions(t *testing.T) {
	tgt, mock := dellTarget(t, "r240", "idrac9-r240", redfishmock.WithTokenOnly())
	h := start(t, Config{Targets: []Target{tgt}})
	waitFor(t, "inventory", func() bool { return h.state(t, "r240").HasInventory })
	if mock.LiveSessions() != 1 || mock.SessionStats().Created != 1 {
		t.Fatalf("one session for the whole first cycle: %+v", mock.SessionStats())
	}
	h.stop()
	if mock.LiveSessions() != 0 || mock.SessionStats().Deleted != 1 {
		t.Fatalf("session not deleted on shutdown: %+v", mock.SessionStats())
	}
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
