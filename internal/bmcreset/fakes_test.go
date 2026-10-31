package bmcreset

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/fleet"
	"oob-manager/internal/power"
	"oob-manager/internal/store"
)

var t0 = time.Date(2026, 10, 23, 1, 12, 0, 0, time.UTC)

// events records the order of side effects across fakes.
type events struct {
	mu  sync.Mutex
	log []string
}

func (e *events) add(s string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.log = append(e.log, s)
}

func (e *events) all() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string(nil), e.log...)
}

type fakeResetter struct {
	ev       *events
	resetErr error
	mu       sync.Mutex
	resets   int
	closed   int
}

func (f *fakeResetter) Reset(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ev.add("post")
	f.resets++
	return f.resetErr
}

func (f *fakeResetter) Close(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed++
	return nil
}

func (f *fakeResetter) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resets, f.closed
}

type fakeFleet struct {
	ev        *events
	mu        sync.Mutex
	err       error
	errOnce   error // returned by the next ExpectRestart only
	windows   map[string]fleet.RestartWindow
	done      map[string]func(fleet.RestartEnd)
	cancelled int
}

func newFakeFleet(ev *events) *fakeFleet {
	return &fakeFleet{ev: ev, windows: map[string]fleet.RestartWindow{}, done: map[string]func(fleet.RestartEnd){}}
}

func (f *fakeFleet) ExpectRestart(id string, w fleet.RestartWindow, done func(fleet.RestartEnd)) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.errOnce != nil {
		err := f.errOnce
		f.errOnce = nil
		return err
	}
	if f.err != nil {
		return f.err
	}
	if _, open := f.windows[id]; open {
		return fleet.ErrRestarting
	}
	f.ev.add("window")
	f.windows[id], f.done[id] = w, done
	return nil
}

func (f *fakeFleet) CancelRestart(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.windows[id]
	delete(f.windows, id)
	delete(f.done, id)
	f.cancelled++
	return ok
}

// end finishes server id's window like the poller would.
func (f *fakeFleet) end(t *testing.T, id string, e fleet.RestartEnd) {
	t.Helper()
	f.mu.Lock()
	done, ok := f.done[id]
	delete(f.windows, id)
	delete(f.done, id)
	f.mu.Unlock()
	if !ok {
		t.Fatalf("no window open on %s", id)
	}
	done(e)
}

func (f *fakeFleet) window(id string) (fleet.RestartWindow, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w, ok := f.windows[id]
	return w, ok
}

type fakePower struct {
	mu sync.Mutex
	op *power.Operation
	// pendingFrom makes Last report a pending operation from that call on (1-based):
	// a power request that starts between two checks.
	pendingFrom int
	calls       int
}

func (p *fakePower) Last(string) (power.Operation, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.pendingFrom > 0 && p.calls >= p.pendingFrom {
		return power.Operation{Action: power.ForceOff, Phase: power.PhasePending}, true
	}
	if p.op == nil {
		return power.Operation{}, false
	}
	return *p.op, true
}

type fakeConsole struct {
	ev     *events
	name   string
	active bool
}

func (c *fakeConsole) EndForBMCReset(string) bool {
	c.ev.add("end " + c.name)
	was := c.active
	c.active = false
	return was
}

type fakeAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
	fail    bool
	// failNext fails that many writes of result failResult (transient errors).
	failNext   int
	failResult string
}

func (a *fakeAudit) Record(_ context.Context, e audit.Entry) (store.AuditRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail || (a.failNext > 0 && e.Result == a.failResult) {
		if a.failNext > 0 {
			a.failNext--
		}
		return store.AuditRecord{}, errors.New("disk full")
	}
	a.entries = append(a.entries, e)
	return store.AuditRecord{}, nil
}

func (a *fakeAudit) find(action, result string) (audit.Entry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := len(a.entries) - 1; i >= 0; i-- {
		if e := a.entries[i]; e.Action == action && e.Result == result {
			return e, true
		}
	}
	return audit.Entry{}, false
}

func (a *fakeAudit) waitFor(t *testing.T, action, result string) audit.Entry {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if e, ok := a.find(action, result); ok {
			return e
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("no %s %s audit row", action, result)
	return audit.Entry{}
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

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// rig is a service over a real SQLite store with scripted collaborators.
type rig struct {
	ev       *events
	db       *store.DB
	fleet    *fakeFleet
	audit    *fakeAudit
	clock    *clock
	resetter *fakeResetter
	openErr  error
	opens    int
	// openHook runs inside Open (block it, move the clock).
	openHook func()
	timeouts chan string
	power    *fakePower
	vnc      *fakeConsole
	serial   *fakeConsole
	back     chan string
	svc      *Service
}

func openDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "oob.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newRig(t *testing.T) *rig {
	t.Helper()
	ev := &events{}
	r := &rig{ev: ev, db: openDB(t), fleet: newFakeFleet(ev), audit: &fakeAudit{}, clock: &clock{now: t0},
		resetter: &fakeResetter{ev: ev}, power: &fakePower{}, vnc: &fakeConsole{ev: ev, name: "vnc"},
		serial: &fakeConsole{ev: ev, name: "serial"}, back: make(chan string, 4), timeouts: make(chan string, 4)}
	r.svc = r.service(t)
	t.Cleanup(r.svc.Shutdown)
	return r
}

func (r *rig) service(t *testing.T) *Service {
	t.Helper()
	svc, err := New(Config{Targets: r.targets(), Audit: r.audit, Store: r.db.BMCResets(), Fleet: r.fleet,
		Power: r.power, Consoles: []Console{r.vnc, r.serial}, Now: r.clock.Now,
		AfterBack:    func(_ context.Context, id string) { r.back <- id },
		AfterTimeout: func(id string) { r.timeouts <- id }})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func (r *rig) targets() []Target {
	open := func(context.Context) (Resetter, error) {
		r.ev.add("login")
		r.opens++
		if r.openHook != nil {
			r.openHook()
		}
		if r.openErr != nil {
			return nil, r.openErr
		}
		return r.resetter, nil
	}
	return []Target{
		{ServerID: "node-a", Open: open, Deadline: 3 * time.Minute},
		{ServerID: "node-b", Open: nil, Deadline: 5 * time.Minute},
	}
}

var admin = Actor{Username: "alice", Role: "admin", SrcIP: "192.0.2.70", AuthMethod: "local"}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
