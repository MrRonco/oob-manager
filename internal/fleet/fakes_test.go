package fleet

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/dellredfish"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/store"
)

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// fakeClock fires After channels only when Advance moves time past them.
type fakeClock struct {
	mu      sync.Mutex
	now     time.Time
	waiters []waiter
}

type waiter struct {
	at time.Time
	ch chan time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{now: t0} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) After(d time.Duration) <-chan time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	ch := make(chan time.Time, 1)
	c.waiters = append(c.waiters, waiter{at: c.now.Add(d), ch: ch})
	return ch
}

func (c *fakeClock) pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.waiters)
}

// Advance moves time forward and fires every waiter that is due.
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
	kept := c.waiters[:0:0]
	for _, w := range c.waiters {
		if w.at.After(c.now) {
			kept = append(kept, w)
			continue
		}
		w.ch <- c.now
	}
	c.waiters = kept
}

// waitFor polls cond in real time (goroutines run asynchronously to the fake clock).
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func dellTarget(t *testing.T, id, fixture string, opts ...redfishmock.Option) (Target, *redfishmock.Server) {
	t.Helper()
	s := redfishmock.New(t, redfishmock.FixtureDir(t, fixture), opts...)
	d, err := dellredfish.New(redfish.Config{
		Endpoint: s.URL(), Username: redfishmock.User, Password: redfishmock.Password,
		PinSHA256: s.PinSHA256(), Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	return Target{ID: id, Name: id + " name", Tags: []string{"critical"}, Driver: d}, s
}

// fakeSamples records polls and clock jumps; behind and fail script the answers.
type fakeSamples struct {
	mu      sync.Mutex
	polls   []store.SensorPoll
	jumps   []time.Time
	behind  bool
	fail    error
	dropped int
}

func (f *fakeSamples) Insert(_ context.Context, p store.SensorPoll) (store.InsertResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return store.InsertResult{}, f.fail
	}
	p.Samples = append([]store.SensorSample(nil), p.Samples...)
	f.polls = append(f.polls, p)
	return store.InsertResult{Inserted: len(p.Samples), Behind: f.behind, Dropped: f.dropped}, nil
}

func (f *fakeSamples) NoteClockJump(_ context.Context, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jumps = append(f.jumps, at)
	return nil
}

func (f *fakeSamples) set(behind bool, fail error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.behind, f.fail = behind, fail
}

func (f *fakeSamples) counts() (polls, jumps int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.polls), len(f.jumps)
}

// countingDriver is a scripted driver for cadence tests.
type countingDriver struct {
	mu                          sync.Mutex
	snaps, events, invs, probes int
	fail                        bool
}

func (d *countingDriver) Probe(context.Context) (bmc.Capabilities, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.probes++
	return bmc.NewCapabilities(bmc.CapabilityParams{Flags: bmc.CapabilityFlags{SEL: true, ProbedAt: t0}}), nil
}

func (d *countingDriver) Snapshot(context.Context) (bmc.Snapshot, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.snaps++
	if d.fail {
		return bmc.Snapshot{}, bmc.ErrUnreachable
	}
	return bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: t0, Health: bmc.HealthOK,
		Temperatures: []bmc.Temperature{{ID: "t1", Celsius: bmc.ReadingOf(40)}, {ID: "t1", Celsius: bmc.ReadingOf(41)}},
		Fans:         []bmc.Fan{{Name: "Fan 1", Speed: bmc.ReadingOf(7000)}, {ID: "f2"}},
		Power:        bmc.PowerDraw{ConsumedWatts: bmc.ReadingOf(250)},
	}), nil
}

func (d *countingDriver) EventLog(context.Context, time.Time) (bmc.EventLog, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.events++
	return bmc.NewEventLog("/sel", []bmc.Event{{ID: "1"}}, true), nil
}

func (d *countingDriver) Inventory(context.Context) (bmc.Inventory, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.invs++
	return bmc.Inventory{}, bmc.ErrBMC
}

func (d *countingDriver) get() (int, int, int, int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.snaps, d.events, d.invs, d.probes
}

func (d *countingDriver) setFail(v bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.fail = v
}

// fakeCaps records capability writes.
type fakeCaps struct {
	mu   sync.Mutex
	puts []store.Capability
}

func (f *fakeCaps) Put(_ context.Context, c store.Capability) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.puts = append(f.puts, c)
	return nil
}

func (f *fakeCaps) Get(context.Context, string) (store.Capability, error) {
	return store.Capability{}, store.ErrNotFound
}

func (f *fakeCaps) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.puts)
}
