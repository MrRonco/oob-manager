package fleet

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

type harness struct {
	clock *fakeClock
	fleet *Fleet
	stop  func()
}

func start(t *testing.T, cfg Config) harness {
	t.Helper()
	clk := newFakeClock()
	cfg.Clock = clk
	if cfg.Logger == nil {
		cfg.Logger = quietLogger()
	}
	if cfg.Rand == nil {
		cfg.Rand = func() float64 { return 0.5 } // no jitter: exactly Interval
	}
	if cfg.CycleTimeout == 0 {
		cfg.CycleTimeout = 2 * time.Second
	}
	f, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		f.Run(ctx)
		close(done)
	}()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("Run did not return after cancel")
		}
	}
	t.Cleanup(stop)
	return harness{clock: clk, fleet: f, stop: stop}
}

func (h harness) state(t *testing.T, id string) ServerState {
	t.Helper()
	s, ok := h.fleet.Server(id)
	if !ok {
		t.Fatalf("server %s missing", id)
	}
	return s
}

// tick waits until every loop is parked on the clock, then advances it.
func (h harness) tick(t *testing.T, loops int, d time.Duration) {
	t.Helper()
	waitFor(t, "all loops parked", func() bool { return h.clock.pending() == loops })
	h.clock.Advance(d)
}

func requestsTo(s *redfishmock.Server) int { return len(s.Requests()) }

// TestDeadAndHangingBMCsDoNotStallHealthyOne is the task 1.4 acceptance test: one
// healthy mock, one answering 5xx, one hanging past the cycle timeout.
func TestDeadAndHangingBMCsDoNotStallHealthyOne(t *testing.T) {
	healthy, _ := dellTarget(t, "r240", "idrac9-r240")
	dead, deadMock := dellTarget(t, "dead", "idrac8-r730xd", redfishmock.WithStatus("/redfish/v1/Systems", 500))
	hang, _ := dellTarget(t, "hang", "idrac8-r730xd", redfishmock.WithDelay("*", time.Minute))
	samples := &fakeSamples{}
	h := start(t, Config{Targets: []Target{hang, dead, healthy}, Samples: samples, CycleTimeout: time.Second})

	waitFor(t, "healthy snapshot", func() bool { return h.state(t, "r240").HasSnapshot })
	if s := h.state(t, "hang"); s.ConsecutiveFailures != 0 || s.HasSnapshot {
		t.Fatalf("hanging poll should still be in flight while the healthy one finished: %+v", s)
	}
	for cycle := 1; cycle <= 3; cycle++ {
		waitFor(t, "failures recorded", func() bool {
			return h.state(t, "hang").ConsecutiveFailures == cycle && h.state(t, "dead").ConsecutiveFailures == cycle
		})
		if got := h.state(t, "r240"); !got.Reachable() || !got.LastAttempt.Equal(h.clock.Now()) {
			t.Fatalf("cycle %d: healthy server not polled on time: %+v", cycle, got)
		}
		h.tick(t, 3, time.Minute)
	}
	// Three failures opened both breakers at t0+2m until t0+4m; this tick (t0+3m) skips them.
	waitFor(t, "healthy polled at t0+3m", func() bool { return h.state(t, "r240").LastAttempt.Equal(t0.Add(3 * time.Minute)) })
	dead1 := h.state(t, "dead")
	if dead1.Breaker != BreakerOpen || dead1.LastError != bmc.ClassBMC || !dead1.FailingSince.Equal(t0) {
		t.Fatalf("dead: %+v", dead1)
	}
	if hs := h.state(t, "hang"); hs.Breaker != BreakerOpen || hs.LastError != bmc.ClassTimeout || !hs.Stale {
		t.Fatalf("hang: %+v", hs)
	}
	before := requestsTo(deadMock)
	h.tick(t, 3, 0) // let the skipped cycle park again
	if requestsTo(deadMock) != before {
		t.Fatal("open breaker must not contact the BMC")
	}
	// t0+4m: half-open probe is sent, fails, and re-opens the breaker.
	h.clock.Advance(time.Minute)
	waitFor(t, "half-open probe", func() bool { return h.state(t, "dead").ConsecutiveFailures == 4 })
	if requestsTo(deadMock) == before {
		t.Fatal("half-open breaker must send one probe")
	}
	if n, _ := samples.counts(); n < 4 {
		t.Fatalf("samples inserted %d", n)
	}
}

func TestCadenceAndRecovery(t *testing.T) {
	d := &countingDriver{}
	caps := &fakeCaps{}
	h := start(t, Config{Targets: []Target{{ID: "x", Name: "X", Driver: d}}, Capabilities: caps,
		Interval: time.Minute, EventsEvery: 5 * time.Minute, InventoryEvery: time.Hour})
	waitFor(t, "first cycle", func() bool { return h.state(t, "x").HasSEL })
	s := h.state(t, "x")
	if s.InventoryError != bmc.ClassBMC || s.HasInventory || !s.HasCapabilities || s.HasLifecycle || caps.count() != 1 {
		t.Fatalf("first cycle state %+v", s)
	}
	for i := 0; i < 4; i++ {
		h.tick(t, 1, time.Minute)
	}
	waitFor(t, "five snapshots", func() bool { n, _, _, _ := d.get(); return n == 5 })
	if _, ev, inv, pr := d.get(); ev != 1 || inv != 1 || pr != 1 {
		t.Fatalf("events %d inventory %d probes %d before they are due", ev, inv, pr)
	}
	h.tick(t, 1, time.Minute) // t0+5m: logs due again
	waitFor(t, "second SEL refresh", func() bool { _, ev, _, _ := d.get(); return ev == 2 })

	d.setFail(true)
	h.tick(t, 1, time.Minute)
	waitFor(t, "failure", func() bool { return h.state(t, "x").ConsecutiveFailures == 1 })
	failed := h.state(t, "x")
	if !failed.HasSnapshot || failed.Reachable() || !failed.FailingSince.Equal(t0.Add(6*time.Minute)) || failed.Stale {
		t.Fatalf("after one failure the last snapshot is kept and not yet stale: %+v", failed)
	}
	d.setFail(false)
	h.tick(t, 1, time.Minute)
	waitFor(t, "recovery", func() bool { return h.state(t, "x").Reachable() })
	if r := h.state(t, "x"); !r.FailingSince.IsZero() || r.LastError != bmc.ClassNone {
		t.Fatalf("recovered state %+v", r)
	}
}

func TestStaleAfterFailures(t *testing.T) {
	d := &countingDriver{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d}}, Interval: time.Minute, BreakerThreshold: 100})
	waitFor(t, "first poll", func() bool { return h.state(t, "x").HasSnapshot })
	d.setFail(true)
	for i := 0; i < 4; i++ {
		h.tick(t, 1, time.Minute)
	}
	waitFor(t, "four failures", func() bool { return h.state(t, "x").ConsecutiveFailures == 4 })
	if s := h.state(t, "x"); !s.Stale || s.Breaker != BreakerClosed {
		t.Fatalf("4 min without success (stale after 3) %+v", s)
	}
}

func TestDellExtrasArePublished(t *testing.T) {
	r240, _ := dellTarget(t, "r240", "idrac9-r240")
	r730, _ := dellTarget(t, "r730xd", "idrac8-r730xd")
	samples := &fakeSamples{}
	h := start(t, Config{Targets: []Target{r730, r240}, Samples: samples})
	waitFor(t, "inventory", func() bool { return h.state(t, "r240").HasInventory && h.state(t, "r730xd").HasInventory })
	s := h.state(t, "r240")
	if !s.HasLifecycle || s.Lifecycle.Len() != 15 || !s.HasSEL || s.SEL.Len() != 1 {
		t.Fatalf("logs: lc %d sel %d", s.Lifecycle.Len(), s.SEL.Len())
	}
	if s.Inventory.License().Tier != bmc.LicenseEnterprise || !s.HasCapabilities || s.Capabilities.Flags().BMCFirmware != "7.00.00.182" {
		t.Fatalf("inventory %+v", s.Inventory.License())
	}
	all := h.fleet.Servers()
	if len(all) != 2 || all[0].ID != "r730xd" || all[1].ID != "r240" || all[0].Tags[0] != "critical" {
		t.Fatalf("Servers order %+v", all)
	}
	all[0].Tags[0] = "mutated"
	if h.state(t, "r730xd").Tags[0] != "critical" {
		t.Fatal("Servers must return copies")
	}
	if !h.fleet.Polled() {
		t.Fatal("Polled after a snapshot")
	}
	samples.mu.Lock()
	defer samples.mu.Unlock()
	keys := map[string]bool{}
	for _, p := range samples.polls {
		for _, row := range p.Samples {
			keys[row.Key] = true
		}
	}
	if !keys[KeyPowerWatts] || !hasPrefix(keys, KeyTemperature+":") || !hasPrefix(keys, KeyFan+":") {
		t.Fatalf("sample keys %v", keys)
	}
}

func hasPrefix(keys map[string]bool, p string) bool {
	for k := range keys {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

func TestReaderBeforeRun(t *testing.T) {
	f, err := New(Config{Targets: []Target{{ID: "x", Name: "X", Driver: &countingDriver{}}}})
	if err != nil {
		t.Fatal(err)
	}
	if f.Polled() {
		t.Fatal("not polled yet")
	}
	s, ok := f.Server("x")
	if !ok || !s.Stale || s.Name != "X" || s.Breaker != BreakerClosed {
		t.Fatalf("initial state %+v", s)
	}
	if _, ok := f.Server("nope"); ok {
		t.Fatal("unknown server")
	}
}

func TestNewValidates(t *testing.T) {
	d := &countingDriver{}
	for name, cfg := range map[string]Config{
		"no driver": {Targets: []Target{{ID: "x"}}},
		"no id":     {Targets: []Target{{Driver: d}}},
		"duplicate": {Targets: []Target{{ID: "x", Driver: d}, {ID: "x", Driver: d}}},
		"jitter":    {Targets: []Target{{ID: "x", Driver: d}}, Jitter: 0.9},
		"negative":  {Targets: []Target{{ID: "x", Driver: d}}, Interval: -time.Second},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestJitterBounds(t *testing.T) {
	for _, c := range []struct {
		r    float64
		want time.Duration
	}{{0, 54 * time.Second}, {0.5, 60 * time.Second}, {1, 66 * time.Second}} {
		cfg := Config{Targets: []Target{{ID: "x", Driver: &countingDriver{}}}, Rand: func() float64 { return c.r }}.withDefaults()
		if got := newPoller(cfg, cfg.Targets[0]).nextDelay(); got != c.want {
			t.Errorf("rand %.1f: delay %s want %s", c.r, got, c.want)
		}
	}
}

func TestShutdownDuringHangingPollRecordsNoFailure(t *testing.T) {
	hang, _ := dellTarget(t, "hang", "idrac8-r730xd", redfishmock.WithDelay("*", time.Minute))
	h := start(t, Config{Targets: []Target{hang}, CycleTimeout: time.Minute})
	time.Sleep(50 * time.Millisecond)
	h.stop()
	if s := h.state(t, "hang"); s.ConsecutiveFailures != 0 || !s.LastAttempt.IsZero() {
		t.Fatalf("cancelled poll counted as a failure: %+v", s)
	}
}

func TestRealClock(t *testing.T) {
	var c Clock = RealClock{}
	if c.Now().IsZero() {
		t.Fatal("zero time")
	}
	select {
	case <-c.After(time.Millisecond):
	case <-time.After(time.Second):
		t.Fatal("After did not fire")
	}
}

// TestLiveStaleMultiplier: Config.StaleMultiplier is read on every view, so a Settings
// change applies to the stale flag without restarting the pollers.
func TestLiveStaleMultiplier(t *testing.T) {
	var mult atomic.Int64
	mult.Store(3)
	d := &countingDriver{}
	h := start(t, Config{Targets: []Target{{ID: "x", Driver: d}}, Interval: time.Minute, BreakerThreshold: 100,
		StaleMultiplier: func() int { return int(mult.Load()) }})
	waitFor(t, "first poll", func() bool { return h.state(t, "x").HasSnapshot })
	d.setFail(true)
	for i := 0; i < 4; i++ {
		h.tick(t, 1, time.Minute)
	}
	waitFor(t, "four failures", func() bool { return h.state(t, "x").ConsecutiveFailures == 4 })
	if s := h.state(t, "x"); !s.Stale || s.StaleAfter != 3*time.Minute {
		t.Fatalf("x3: %+v", s)
	}
	mult.Store(5)
	if s := h.state(t, "x"); s.Stale || s.StaleAfter != 5*time.Minute {
		t.Fatalf("x5: stale=%v after=%v", s.Stale, s.StaleAfter)
	}
}
