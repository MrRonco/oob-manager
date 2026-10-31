package power

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/store"
)

var allResets = []string{"On", "GracefulShutdown", "GracefulRestart", "ForceOff", "PowerCycle", "ForceRestart", "Nmi"}

// fakeCtl is a scripted BMC: PowerState returns states[i] for the i-th read after the
// reset (the last one repeats); before a reset it returns initial.
type fakeCtl struct {
	mu       sync.Mutex
	allowed  []string
	initial  bmc.PowerState
	states   []bmc.PowerState
	reads    int
	reset    bool
	resets   []string
	resetErr error
	stateErr error
	closed   int
}

func (f *fakeCtl) Allowed() []string { return append([]string(nil), f.allowed...) }

func (f *fakeCtl) PowerState(context.Context) (bmc.PowerState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stateErr != nil {
		return bmc.PowerUnknown, f.stateErr
	}
	if !f.reset || len(f.states) == 0 {
		return f.initial, nil
	}
	i := min(f.reads, len(f.states)-1)
	f.reads++
	return f.states[i], nil
}

func (f *fakeCtl) Reset(_ context.Context, rt string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.resetErr != nil {
		return f.resetErr
	}
	f.reset = true
	f.resets = append(f.resets, rt)
	return nil
}

func (f *fakeCtl) Close(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

func (f *fakeCtl) snapshot() (resets []string, closed int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.resets...), f.closed
}

type fakeAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
	fail    bool
}

func (a *fakeAudit) Record(_ context.Context, e audit.Entry) (store.AuditRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return store.AuditRecord{}, errors.New("disk full")
	}
	a.entries = append(a.entries, e)
	return store.AuditRecord{}, nil
}

func (a *fakeAudit) all() []audit.Entry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]audit.Entry(nil), a.entries...)
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

type harness struct {
	svc   *Service
	ctl   *fakeCtl
	aud   *fakeAudit
	clock *clock
	opens int
	mu    sync.Mutex
}

var actor = Actor{Username: "alice", Role: "admin", SrcIP: "192.0.2.70", AuthMethod: "local"}

func newHarness(t *testing.T, ctl *fakeCtl, mod ...func(*Config)) *harness {
	t.Helper()
	h := &harness{ctl: ctl, aud: &fakeAudit{}, clock: &clock{now: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}}
	cfg := Config{
		Targets: []Target{
			{ServerID: "srv", Open: func(context.Context) (Controller, error) {
				h.mu.Lock()
				h.opens++
				h.mu.Unlock()
				return h.ctl, nil
			}},
			{ServerID: "noop", SelfHost: true, Impact: []string{"Gateway"}},
		},
		Audit: h.aud, Now: h.clock.Now,
		PollEvery: time.Millisecond, GracefulTimeout: 200 * time.Millisecond, ForcedTimeout: 100 * time.Millisecond,
	}
	for _, m := range mod {
		m(&cfg)
	}
	svc, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(svc.Shutdown)
	h.svc = svc
	return h
}

func (h *harness) openCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.opens
}

// waitFinal waits until the server's operation leaves PhasePending.
func waitFinal(t *testing.T, s *Service, id string) Operation {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if op, ok := s.Last(id); ok && op.Final() {
			return op
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("operation still pending")
	return Operation{}
}

// waitAudits waits for n audit entries.
func waitAudits(t *testing.T, a *fakeAudit, n int) []audit.Entry {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e := a.all(); len(e) >= n {
			return e
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("want %d audit entries, have %+v", n, a.all())
	return nil
}
