package fleet

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

// fwDriver is a tierDriver with a firmware scanner and a scripted inventory firmware list.
type fwDriver struct {
	*tierDriver
	mu        sync.Mutex
	scans     int
	failScan  bool
	block     chan struct{}
	items     []bmc.FirmwareItem // what scans return
	invItems  []bmc.FirmwareItem // what the inventory tier lists
	needAsked int
}

func newFWDriver(items ...bmc.FirmwareItem) *fwDriver {
	return &fwDriver{tierDriver: &tierDriver{}, items: items, invItems: items}
}

func (d *fwDriver) Inventory(ctx context.Context) (bmc.Inventory, error) {
	if _, err := d.tierDriver.Inventory(ctx); err != nil {
		return bmc.Inventory{}, err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	return bmc.NewInventory(bmc.InventoryParams{Firmware: d.invItems}), nil
}

func (d *fwDriver) ScanFirmware(ctx context.Context, need func(bmc.FirmwareItem) bool) (bmc.FirmwareScan, error) {
	d.mu.Lock()
	d.scans++
	fail, block, items := d.failScan, d.block, d.items
	d.mu.Unlock()
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return bmc.FirmwareScan{}, bmc.ErrTimeout
		}
	}
	if fail {
		return bmc.FirmwareScan{}, bmc.ErrBMC
	}
	for _, it := range items {
		if need(it) {
			d.mu.Lock()
			d.needAsked++
			d.mu.Unlock()
		}
	}
	return bmc.NewFirmwareScan(items, len(items), true), nil
}

func (d *fwDriver) scanCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.scans
}

func (d *fwDriver) setFW(f func(*fwDriver)) {
	d.mu.Lock()
	defer d.mu.Unlock()
	f(d)
}

// fakeSink records firmware scans.
type fakeSink struct {
	mu      sync.Mutex
	records []bmc.FirmwareScan
	at      []time.Time
	fail    bool
}

func (s *fakeSink) Need(string, time.Time) func(bmc.FirmwareItem) bool {
	return func(bmc.FirmwareItem) bool { return true }
}

func (s *fakeSink) Record(_ context.Context, _ string, scan bmc.FirmwareScan, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("store down")
	}
	s.records = append(s.records, scan)
	s.at = append(s.at, at)
	return nil
}

func (s *fakeSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

func bios(v string) bmc.FirmwareItem {
	return bmc.FirmwareItem{ID: "Current-159-" + v, State: "Current", ComponentID: "159", Version: v}
}

func TestFirmwareTierRunsAtStartAndEveryPeriod(t *testing.T) {
	d, sink := newFWDriver(bios("2.19.0")), &fakeSink{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d}}, Interval: time.Minute, Firmware: sink,
		InventoryEvery: time.Hour, FirmwareEvery: 10 * time.Minute})
	waitFor(t, "first scan", func() bool { return sink.count() == 1 })
	waitFor(t, "published", func() bool { return h.state(t, "x").FirmwareAsOf.Equal(t0) })
	s := h.state(t, "x")
	if !s.FirmwareEnabled || s.FirmwareError != bmc.ClassNone || s.FirmwareRunning || !s.FirmwareNext.Equal(t0.Add(10*time.Minute)) ||
		s.FirmwareEvery != 10*time.Minute {
		t.Fatalf("first scan %+v", s)
	}
	if d.needAsked != 1 {
		t.Fatalf("the sink's Need reached the driver %d times", d.needAsked)
	}
	for i := 1; i <= 9; i++ {
		h.tick(t, 1, time.Minute)
		waitFor(t, "poll", func() bool { n, _, _ := d.counts(); return n == i+1 })
	}
	if n := d.scanCount(); n != 1 {
		t.Fatalf("scanned %d times before the period", n)
	}
	h.tick(t, 1, time.Minute)
	waitFor(t, "second scan", func() bool { return sink.count() == 2 })
}

func TestFirmwareTierFailureRetriesAndKeepsTheLast(t *testing.T) {
	d, sink := newFWDriver(bios("2.19.0")), &fakeSink{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d}}, Interval: time.Minute, Firmware: sink,
		EventsEvery: 5 * time.Minute, FirmwareEvery: time.Hour})
	waitFor(t, "first scan", func() bool { return sink.count() == 1 })
	d.setFW(func(d *fwDriver) { d.failScan = true })
	if err := h.fleet.Refresh("x", TierFirmware); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "failed scan", func() bool { return h.state(t, "x").FirmwareError == bmc.ClassBMC })
	s := h.state(t, "x")
	if !s.FirmwareAsOf.Equal(t0) || s.FirmwareRequested || s.ConsecutiveFailures != 0 {
		t.Fatalf("a failed scan keeps the last scan time and never counts as a poll failure: %+v", s)
	}
	d.setFW(func(d *fwDriver) { d.failScan = false })
	h.tick(t, 2, time.Minute) // the wake-up left the earlier timer registered
	for range 4 {
		h.tick(t, 1, time.Minute)
	}
	waitFor(t, "retried after 5 min", func() bool { return sink.count() == 2 })
	waitFor(t, "error cleared", func() bool { return h.state(t, "x").FirmwareError == bmc.ClassNone })
	// A sink that cannot store the scan fails the tier too.
	sink.mu.Lock()
	sink.fail = true
	sink.mu.Unlock()
	waitFor(t, "parked", func() bool { return h.clock.pending() == 1 })
	if err := h.fleet.Refresh("x", TierFirmware); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "store failure", func() bool { return h.state(t, "x").FirmwareError == bmc.ClassOther })
}

func TestRefreshFirmwareRunsAtOnce(t *testing.T) {
	d, sink := newFWDriver(bios("2.19.0")), &fakeSink{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d}}, Interval: time.Minute, Firmware: sink})
	waitFor(t, "first scan", func() bool { return sink.count() == 1 })
	waitFor(t, "idle", func() bool { return h.clock.pending() == 1 })
	d.setFW(func(d *fwDriver) { d.block = make(chan struct{}) })
	if err := h.fleet.Refresh("x", TierFirmware); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "running", func() bool { s := h.state(t, "x"); return s.FirmwareRunning })
	d.block <- struct{}{}
	waitFor(t, "rescanned", func() bool { return sink.count() == 2 })
	waitFor(t, "request consumed", func() bool { s := h.state(t, "x"); return !s.FirmwareRequested && !s.FirmwareRunning })
	if n, _, _ := d.counts(); n != 2 {
		t.Fatalf("a refresh runs one cycle (snapshot first): %d snapshots", n)
	}
}

func TestRefreshRefusals(t *testing.T) {
	sink := &fakeSink{}
	pf := &postureFunc{}
	h := start(t, Config{Firmware: sink, Targets: []Target{{ID: "fw", Driver: newFWDriver(), Posture: pf.run},
		{ID: "plain", Driver: &tierDriver{}}}})
	waitFor(t, "polled", func() bool { return h.state(t, "fw").HasInventory && h.state(t, "plain").HasInventory })
	if err := h.fleet.Refresh("nope", TierFirmware); !errors.Is(err, ErrUnknownServer) {
		t.Fatalf("unknown: %v", err)
	}
	if err := h.fleet.Refresh("plain", TierFirmware); !errors.Is(err, ErrNoTier) {
		t.Fatalf("a driver without a firmware scanner: %v", err)
	}
	if h.state(t, "plain").FirmwareEnabled {
		t.Fatal("plain has no firmware tier")
	}
	if err := h.fleet.Refresh("fw", Tier("bogus")); !errors.Is(err, ErrNoTier) {
		t.Fatalf("unknown tier: %v", err)
	}
	if err := h.fleet.Refresh("fw", TierPosture); err != nil {
		t.Fatalf("posture through Refresh: %v", err)
	}
	if err := h.fleet.Refresh("plain", TierPosture); !errors.Is(err, ErrNoPosture) {
		t.Fatalf("posture without the tier: %v", err)
	}
}

func TestFirmwareTierOffWithoutSink(t *testing.T) {
	d := newFWDriver(bios("1"))
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d}}})
	waitFor(t, "inventory", func() bool { return h.state(t, "x").HasInventory })
	if s := h.state(t, "x"); s.FirmwareEnabled || d.scanCount() != 0 {
		t.Fatalf("no sink, no tier: %+v scans %d", s, d.scanCount())
	}
	if err := h.fleet.Refresh("x", TierFirmware); !errors.Is(err, ErrNoTier) {
		t.Fatalf("refresh without a sink: %v", err)
	}
}

func TestInventoryChangeTriggersAFirmwareScan(t *testing.T) {
	d, sink := newFWDriver(bios("2.19.0")), &fakeSink{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d}}, Interval: time.Minute, Firmware: sink,
		InventoryEvery: 2 * time.Minute, FirmwareEvery: 24 * time.Hour})
	waitFor(t, "first scan", func() bool { return sink.count() == 1 })
	h.tick(t, 1, time.Minute)
	h.tick(t, 1, time.Minute) // inventory at t0+2m, same list: no scan
	waitFor(t, "second inventory", func() bool { _, _, inv := d.counts(); return inv == 2 })
	waitFor(t, "parked", func() bool { return h.clock.pending() == 1 })
	if sink.count() != 1 {
		t.Fatalf("an unchanged list rescanned: %d", sink.count())
	}
	d.setFW(func(d *fwDriver) { d.invItems = []bmc.FirmwareItem{bios("2.20.0")}; d.items = d.invItems })
	h.tick(t, 1, time.Minute)
	h.tick(t, 1, time.Minute) // inventory at t0+4m lists a new version: scan in the same cycle
	waitFor(t, "triggered scan", func() bool { return sink.count() == 2 })
	if at := sink.at[1]; !at.Equal(t0.Add(4 * time.Minute)) {
		t.Fatalf("scan at %v", at)
	}
}

func TestFirmwareScanRunsRightAfterABMCRestart(t *testing.T) {
	d, sink := newFWDriver(bios("1")), &fakeSink{}
	h := start(t, Config{Targets: []Target{{ID: "a", Driver: d}}, Interval: time.Minute, Firmware: sink,
		FirmwareEvery: 24 * time.Hour, RestartQuiet: time.Minute, RestartRetry: 30 * time.Second})
	waitFor(t, "first scan", func() bool { return sink.count() == 1 })
	waitFor(t, "idle", func() bool { return h.clock.pending() == 1 })
	since := h.clock.Now()
	done := make(chan RestartEnd, 1)
	if err := h.fleet.ExpectRestart("a", RestartWindow{Since: since, Until: since.Add(5 * time.Minute)},
		func(e RestartEnd) { done <- e }); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "quiet cycle", func() bool { return h.clock.pending() == 2 })
	if err := h.fleet.Refresh("a", TierFirmware); err != nil { // waits for the BMC: no scan in the window
		t.Fatal(err)
	}
	waitFor(t, "second quiet cycle", func() bool { return h.clock.pending() == 3 })
	if n := sink.count(); n != 1 {
		t.Fatalf("scanned inside the restart window: %d", n)
	}
	h.tick(t, 3, time.Minute)
	select {
	case e := <-done:
		if e.Outcome != RestartBack {
			t.Fatalf("end %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the window did not end")
	}
	// One scan right after the BMC is back, once the window has ended (review C-L7); the
	// request made during the window is folded into it.
	waitFor(t, "the scan after the restart", func() bool { return sink.count() == 2 })
	waitFor(t, "parked", func() bool { return h.clock.pending() >= 1 })
	if n := sink.count(); n != 2 {
		t.Fatalf("scans %d", n)
	}
}

// TestRestartEndsBeforeTheFirmwareScan (review C-L7): the BMC-reset window ends as soon as
// the BMC answers (and its inventory is read); the slower firmware scan follows.
func TestRestartEndsBeforeTheFirmwareScan(t *testing.T) {
	d, sink := newFWDriver(bios("1")), &fakeSink{}
	h := start(t, Config{Targets: []Target{{ID: "a", Driver: d}}, Interval: time.Minute, Firmware: sink,
		FirmwareEvery: 24 * time.Hour, RestartQuiet: time.Minute, RestartRetry: 30 * time.Second})
	waitFor(t, "first scan", func() bool { return sink.count() == 1 })
	waitFor(t, "idle", func() bool { return h.clock.pending() == 1 })
	d.setFW(func(d *fwDriver) { d.block = make(chan struct{}) })
	since := h.clock.Now()
	done := make(chan RestartEnd, 1)
	if err := h.fleet.ExpectRestart("a", RestartWindow{Since: since, Until: since.Add(5 * time.Minute)},
		func(e RestartEnd) { done <- e }); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "quiet cycle", func() bool { return h.clock.pending() == 2 })
	h.tick(t, 2, time.Minute)
	select {
	case e := <-done:
		if e.Outcome != RestartBack || !e.State.HasInventory {
			t.Fatalf("end %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the window waited for the firmware scan")
	}
	waitFor(t, "scan running after the window", func() bool { return h.state(t, "a").FirmwareRunning })
	d.block <- struct{}{}
	waitFor(t, "scan after the restart", func() bool { return sink.count() == 2 })
}
