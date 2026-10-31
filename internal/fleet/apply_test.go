package fleet

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

// pinDriver fails every snapshot with a pin mismatch while mismatch is set.
type pinDriver struct {
	tierDriver
	mu       sync.Mutex
	mismatch bool
}

func (d *pinDriver) Snapshot(ctx context.Context) (bmc.Snapshot, error) {
	d.mu.Lock()
	bad := d.mismatch
	d.mu.Unlock()
	if bad {
		d.tierDriver.mu.Lock()
		d.snaps++
		d.tierDriver.mu.Unlock()
		return bmc.Snapshot{}, fmt.Errorf("redfish: %w", bmc.ErrPinMismatch)
	}
	return d.tierDriver.Snapshot(ctx)
}

func target(id, fp string, d bmc.Driver) Target {
	return Target{ID: id, Name: id + " name", Driver: d, Fingerprint: fp}
}

func TestApplyAddsKeepsAndRemoves(t *testing.T) {
	x := &tierDriver{}
	h := start(t, Config{Targets: []Target{target("x", "fx", x)}, Interval: time.Minute})
	waitFor(t, "x polled", func() bool { return h.state(t, "x").HasSnapshot })
	before := h.state(t, "x")

	// Add y, keep x (same fingerprint, new name and tags: no restart, state kept).
	y := &tierDriver{}
	unusedX := &tierDriver{}
	kept := target("x", "fx", unusedX)
	kept.Name, kept.Tags = "Renamed", []string{"new"}
	if err := h.fleet.Apply([]Target{target("y", "fy", y), kept}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "y polled", func() bool { s, ok := h.fleet.Server("y"); return ok && s.HasSnapshot })
	after := h.state(t, "x")
	if !after.LastSuccess.Equal(before.LastSuccess) || after.Name != "Renamed" || after.Tags[0] != "new" {
		t.Fatalf("x restarted or meta not updated: %+v", after)
	}
	if snaps, _, _ := unusedX.counts(); snaps != 0 || unusedX.closes != 1 {
		t.Fatalf("unused replacement driver: snaps %d closes %d", snaps, unusedX.closes)
	}
	if ids := idsOf(h.fleet.Servers()); fmt.Sprint(ids) != "[y x]" {
		t.Fatalf("order = %v", ids)
	}

	// Change x (new fingerprint): the old poller stops and its driver closes first.
	x2 := &tierDriver{}
	if err := h.fleet.Apply([]Target{target("y", "fy", &tierDriver{}), target("x", "fx2", x2)}); err != nil {
		t.Fatal(err)
	}
	if x.closes != 1 {
		t.Fatalf("old x driver closed %d times", x.closes)
	}
	waitFor(t, "x2 polled", func() bool { n, _, _ := x2.counts(); return n >= 1 })

	// Remove y.
	if err := h.fleet.Apply([]Target{target("x", "fx2", &tierDriver{})}); err != nil {
		t.Fatal(err)
	}
	if _, ok := h.fleet.Server("y"); ok || y.closes != 1 {
		t.Fatalf("y still present or not closed (%d)", y.closes)
	}
	h.stop()
	if x2.closes != 1 {
		t.Fatalf("x2 closed %d times at shutdown", x2.closes)
	}
}

func idsOf(states []ServerState) []string {
	out := make([]string, 0, len(states))
	for _, s := range states {
		out = append(out, s.ID)
	}
	return out
}

func TestApplyBeforeRunAndAfterStop(t *testing.T) {
	f, err := New(Config{Logger: quietLogger(), Clock: newFakeClock()})
	if err != nil {
		t.Fatalf("empty fleet: %v", err)
	}
	if !f.Polled() || len(f.Servers()) != 0 {
		t.Fatal("an empty fleet is ready (nothing to wait for)")
	}
	d := &tierDriver{}
	if err = f.Apply([]Target{target("x", "f", d)}); err != nil {
		t.Fatal(err)
	}
	if f.Polled() {
		t.Fatal("not polled before Run")
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()
	waitFor(t, "polled after Run", func() bool { s, _ := f.Server("x"); return s.HasSnapshot })
	cancel()
	<-done
	if err = f.Apply(nil); !errors.Is(err, ErrStopped) {
		t.Fatalf("apply after stop: %v", err)
	}
}

func TestApplyValidates(t *testing.T) {
	h := start(t, Config{Targets: []Target{target("x", "f", &tierDriver{})}})
	for name, ts := range map[string][]Target{
		"duplicate": {target("a", "1", &tierDriver{}), target("a", "2", &tierDriver{})},
		"no driver": {{ID: "a"}},
		"no id":     {{Driver: &tierDriver{}}},
	} {
		if err := h.fleet.Apply(ts); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, ok := h.fleet.Server("x"); !ok {
		t.Fatal("a refused Apply changed the roster")
	}
}

// TestPinMismatchPausesPolling: a certificate that no longer matches the pin stops the
// server's polling (no retries against a possibly different host) until a new target
// (a confirmed new fingerprint) is applied.
func TestPinMismatchPausesPolling(t *testing.T) {
	d := &pinDriver{}
	d.mismatch = true
	h := start(t, Config{Targets: []Target{target("x", "old-pin", d)}, Interval: time.Minute})
	waitFor(t, "paused", func() bool { return h.state(t, "x").PinMismatch })
	s := h.state(t, "x")
	if !s.Paused || s.LastError != bmc.ClassTLS || s.Breaker != BreakerClosed {
		t.Fatalf("state = %+v", s)
	}
	time.Sleep(20 * time.Millisecond)
	if h.clock.pending() != 0 {
		t.Fatal("a paused poller is still scheduling polls")
	}
	if n, _, _ := d.counts(); n != 1 {
		t.Fatalf("snapshots after the mismatch: %d", n)
	}
	fixed := &tierDriver{}
	if err := h.fleet.Apply([]Target{target("x", "new-pin", fixed)}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "resumed", func() bool { s := h.state(t, "x"); return s.HasSnapshot && !s.PinMismatch && !s.Paused })
}

// TestApplyRaceWithReaders runs Apply in a loop while readers load the roster; run
// with -race. Afterwards no poller goroutine is left behind.
func TestApplyRaceWithReaders(t *testing.T) {
	base := runtime.NumGoroutine()
	f, err := New(Config{Logger: quietLogger(), Interval: time.Hour, EventsEvery: time.Hour, InventoryEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.Run(ctx); close(done) }()
	stopReaders := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stopReaders:
					return
				default:
				}
				for _, s := range f.Servers() {
					_, _ = f.Server(s.ID)
				}
				_ = f.Polled()
			}
		})
	}
	var applies sync.WaitGroup
	for w := range 3 {
		applies.Go(func() {
			for i := range 30 {
				ts := []Target{target("a", "fa", &tierDriver{})}
				if (i+w)%2 == 0 {
					ts = append(ts, target(fmt.Sprintf("b%d", i%3), fmt.Sprint(i), &tierDriver{}))
				}
				if aerr := f.Apply(ts); aerr != nil {
					t.Error(aerr)
				}
			}
		})
	}
	applies.Wait()
	close(stopReaders)
	wg.Wait()
	cancel()
	<-done
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > base+2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > base+2 {
		t.Fatalf("goroutines: %d at start, %d after stop", base, n)
	}
}
