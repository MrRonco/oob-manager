package fan

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/store"
)

// failingLeases wraps a real lease repository and fails the chosen calls.
type failingLeases struct {
	store.LeaseRepository
	createErr, transitionErr error
}

func (f failingLeases) Create(ctx context.Context, l store.FanLease) error {
	if f.createErr != nil {
		return f.createErr
	}
	return f.LeaseRepository.Create(ctx, l)
}

func (f failingLeases) Transition(ctx context.Context, id string, from, to store.LeaseState, at time.Time) error {
	if f.transitionErr != nil && to == store.LeaseApplied {
		return f.transitionErr
	}
	return f.LeaseRepository.Transition(ctx, id, from, to, at)
}

func (r *rig) serviceWith(t *testing.T, leases store.LeaseRepository, aud Auditor, timeout time.Duration) *Service {
	t.Helper()
	svc, err := New(Config{Policies: policies(), Appliers: map[string]Applier{"node-a": r.host, "node-b": r.floor},
		Leases: leases, Audit: aud, Now: r.clock.now, AuditTimeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// TestStartFailureAfterStartedRowIsClosed: once a "started" row is written, every way
// Start can fail afterwards writes a closing error row, so no started row is left open.
func TestStartFailureAfterStartedRowIsClosed(t *testing.T) {
	boom := errors.New("disk full")
	for name, c := range map[string]struct {
		id     string
		leases func(store.LeaseRepository) store.LeaseRepository
	}{
		"lease row not stored": {"node-a", func(l store.LeaseRepository) store.LeaseRepository {
			return failingLeases{LeaseRepository: l, createErr: boom}
		}},
		"applied state not stored": {"node-b", func(l store.LeaseRepository) store.LeaseRepository {
			return failingLeases{LeaseRepository: l, transitionErr: boom}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			svc := r.serviceWith(t, c.leases(r.db.Leases()), r.audit, 0)
			if _, err := svc.Start(ctxT(t), testActor, c.id, Request{Pct: 55, Duration: 30 * time.Minute}); !errors.Is(err, boom) {
				t.Fatalf("err = %v, want the store error", err)
			}
			if _, ok := r.audit.find("fan.lease.create", audit.ResultStarted); !ok {
				t.Fatal("no started row")
			}
			if _, ok := r.audit.find("fan.lease.create", audit.ResultError); !ok {
				t.Fatal("the started row was left without a closing error row")
			}
			if _, ok := r.audit.find("fan.lease.create", audit.ResultOK); ok {
				t.Fatal("an ok row for a failed start")
			}
		})
	}
}

// blockingAudit never returns until its context ends (a hung audit store).
type blockingAudit struct {
	mu    sync.Mutex
	calls int
}

func (b *blockingAudit) Record(ctx context.Context, _ audit.Entry) (store.AuditRecord, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	<-ctx.Done()
	return store.AuditRecord{}, ctx.Err()
}

// TestAuditWriteIsBounded: the audit write runs under the server's mutex, so a hung audit
// store must not hold it forever: Start gives up after AuditTimeout with ErrAudit, and
// the next call on the same server is not blocked behind it.
func TestAuditWriteIsBounded(t *testing.T) {
	r := newRig(t)
	svc := r.serviceWith(t, r.db.Leases(), &blockingAudit{}, 50*time.Millisecond)
	for range 2 {
		done := make(chan error, 1)
		go func() {
			_, err := svc.Start(context.Background(), testActor, "node-a", Request{Pct: 55, Duration: 30 * time.Minute})
			done <- err
		}()
		select {
		case err := <-done:
			if !errors.Is(err, ErrAudit) {
				t.Fatalf("err = %v, want ErrAudit", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Start blocked on a hung audit store")
		}
	}
	if a, _ := r.host.counts(); a != 0 {
		t.Fatalf("applier called %d times without an audit row", a)
	}
}

func TestAuditTimeoutDefault(t *testing.T) {
	r := newRig(t)
	if got := r.serviceWith(t, r.db.Leases(), r.audit, 0).cfg.AuditTimeout; got != DefaultAuditTimeout || got <= 0 {
		t.Fatalf("AuditTimeout = %v, want DefaultAuditTimeout", got)
	}
}
