package fan

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/store"
)

type fakeApplier struct {
	mu         sync.Mutex
	immediate  bool
	plan       *Plan // nil: Plan{Pct: requested}
	prepareErr error
	applyErr   error
	releaseErr error
	sweepErr   error
	obs        Observation
	applied    []store.FanLease
	released   []store.FanLease
	sweeps     int
}

func (f *fakeApplier) Prepare(_ context.Context, pct, _ int) (Plan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.prepareErr != nil {
		return Plan{}, f.prepareErr
	}
	if f.plan != nil {
		return *f.plan, nil
	}
	return Plan{Pct: pct}, nil
}

func (f *fakeApplier) Apply(_ context.Context, l store.FanLease) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, l)
	return f.immediate, f.applyErr
}

func (f *fakeApplier) Release(_ context.Context, l store.FanLease) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, l)
	return f.releaseErr
}

func (f *fakeApplier) Observe(store.FanLease, bool) Observation {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.obs
}

func (f *fakeApplier) Sweep(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sweeps++
	return f.sweepErr
}

func (f *fakeApplier) set(fn func(*fakeApplier)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeApplier) counts() (applied, released int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applied), len(f.released)
}

type fakeAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
	fail    bool // every Record fails (the audit store is down)
}

func (a *fakeAudit) Record(_ context.Context, e audit.Entry) (store.AuditRecord, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail {
		return store.AuditRecord{}, errAuditDown
	}
	a.entries = append(a.entries, e)
	return store.AuditRecord{}, nil
}

var errAuditDown = errors.New("audit store down")

func (a *fakeAudit) setFail(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fail = v
}

func (a *fakeAudit) find(action, result string) (audit.Entry, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if e.Action == action && e.Result == result {
			return e, true
		}
	}
	return audit.Entry{}, false
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// rig is a service over a real SQLite store with fake appliers for two servers.
type rig struct {
	db     *store.DB
	svc    *Service
	host   *fakeApplier
	floor  *fakeApplier
	audit  *fakeAudit
	clock  *clock
	dbPath string
}

var testActor = Actor{Username: "op", Role: "operator", IP: "192.0.2.70", Method: "local"}

func policies() []Policy {
	return []Policy{
		{ServerID: "node-a", Mode: config.FanHostLease, SafeMin: 30, MaxLease: 2 * time.Hour},
		{ServerID: "node-b", Mode: config.FanRedfishFloor, SafeMin: 41, MaxLease: 2 * time.Hour},
		{ServerID: "node-c", Mode: config.FanNone},
	}
}

func openDB(t *testing.T, path string) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newRig(t *testing.T) *rig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fan.db")
	r := &rig{db: openDB(t, path), host: &fakeApplier{}, floor: &fakeApplier{immediate: true},
		audit: &fakeAudit{}, clock: &clock{t: time.Unix(1_800_000_000, 0).UTC()}, dbPath: path}
	r.svc = r.service(t, r.db)
	return r
}

func (r *rig) service(t *testing.T, db *store.DB) *Service {
	t.Helper()
	svc, err := New(Config{
		Policies: policies(),
		Appliers: map[string]Applier{"node-a": r.host, "node-b": r.floor},
		Leases:   db.Leases(),
		Audit:    r.audit,
		Now:      r.clock.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func ctxT(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
