package fan

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/config"
	"oob-manager/internal/store"
)

func TestReconcileExpiresAndRestores(t *testing.T) {
	r := newRig(t)
	r.floor.set(func(f *fakeApplier) { f.plan = &Plan{Pct: 60, Original: 255, HasOriginal: true} })
	l, err := r.svc.Start(ctxT(t), testActor, "node-b", Request{Pct: 60, Duration: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	r.clock.add(29 * time.Minute)
	r.svc.Reconcile(ctxT(t), false)
	if _, rel := r.floor.counts(); rel != 0 {
		t.Fatal("released before expiry")
	}
	r.clock.add(time.Minute)
	r.floor.set(func(f *fakeApplier) { f.releaseErr = errors.New("bmc down") })
	r.svc.Reconcile(ctxT(t), false)
	if got, _ := r.db.Leases().Get(ctxT(t), l.LeaseID); !got.State.Active() {
		t.Fatal("a lease whose restore failed must stay active")
	}
	r.floor.set(func(f *fakeApplier) { f.releaseErr = nil })
	r.svc.Reconcile(ctxT(t), false)
	got, _ := r.db.Leases().Get(ctxT(t), l.LeaseID)
	if got.State != store.LeaseExpired {
		t.Fatalf("state = %s", got.State)
	}
	r.floor.mu.Lock()
	last := r.floor.released[len(r.floor.released)-1]
	r.floor.mu.Unlock()
	if !last.HasOriginal || last.OriginalValue != 255 {
		t.Fatalf("release did not carry the original: %+v", last)
	}
	if e, ok := r.audit.find(ActionExpire, audit.ResultOK); !ok || e.Principal != "system" || e.Params["restored"] != 255 {
		t.Fatalf("audit = %+v", e)
	}
}

func TestReconcileConfirmsPending(t *testing.T) {
	r := newRig(t)
	l, _ := r.svc.Start(ctxT(t), testActor, "node-a", Request{Pct: 55, Duration: time.Hour})
	r.svc.Reconcile(ctxT(t), false)
	if got, _ := r.db.Leases().Get(ctxT(t), l.LeaseID); got.State != store.LeasePending {
		t.Fatal("applied without an ack")
	}
	r.host.set(func(f *fakeApplier) {
		f.obs = Observation{Applied: true, Owner: OwnerLease, AppliedPct: 55, HasPct: true}
	})
	r.svc.Reconcile(ctxT(t), false)
	if got, _ := r.db.Leases().Get(ctxT(t), l.LeaseID); got.State != store.LeaseApplied {
		t.Fatalf("state = %s", got.State)
	}
	if e, ok := r.audit.find(ActionApplied, audit.ResultOK); !ok || e.Params["applied_pct"] != 55 {
		t.Fatalf("audit = %+v", e)
	}
}

// A crash leaves rows behind; the next process reconciles them from the database alone.
func TestCrashRestart(t *testing.T) {
	r := newRig(t)
	r.floor.set(func(f *fakeApplier) { f.plan = &Plan{Pct: 60, Original: 70, HasOriginal: true} })
	expired, _ := r.svc.Start(ctxT(t), testActor, "node-b", Request{Pct: 60, Duration: 10 * time.Minute})
	live, _ := r.svc.Start(ctxT(t), testActor, "node-a", Request{Pct: 40, Duration: time.Hour})

	// "Restart": a new service and fresh appliers over the same database, 15 minutes later.
	r.clock.add(15 * time.Minute)
	host2, floor2 := &fakeApplier{}, &fakeApplier{immediate: true}
	svc2, err := New(Config{Policies: policies(), Appliers: map[string]Applier{"node-a": host2, "node-b": floor2},
		Leases: r.db.Leases(), Audit: r.audit, Now: r.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	svc2.Reconcile(ctxT(t), true)
	if got, _ := r.db.Leases().Get(ctxT(t), expired.LeaseID); got.State != store.LeaseExpired {
		t.Fatalf("expired lease state = %s", got.State)
	}
	if len(floor2.released) != 1 || floor2.released[0].OriginalValue != 70 {
		t.Fatalf("restore after restart: %+v", floor2.released)
	}
	if len(host2.applied) != 1 || host2.applied[0].LeaseID != live.LeaseID {
		t.Fatalf("live lease not re-applied: %+v", host2.applied)
	}
	if e, ok := r.audit.find(ActionReapply, audit.ResultOK); !ok || e.ServerID != "node-a" {
		t.Fatalf("audit = %+v", e)
	}
	if host2.sweeps != 0 || floor2.sweeps != 1 {
		t.Fatalf("sweeps host %d floor %d (only servers without a lease are swept)", host2.sweeps, floor2.sweeps)
	}
}

func TestReconcileStartupEdgeCases(t *testing.T) {
	r := newRig(t)
	// A pending redfish lease (crash after the row, before the PATCH) becomes applied.
	now := r.clock.now()
	pending := store.FanLease{LeaseID: "aa", ServerID: "node-b", Mode: store.LeaseBoost, Pct: 50, IssuedAt: now,
		ExpiresAt: now.Add(time.Hour), RequestedBy: "op", State: store.LeasePending, UpdatedAt: now}
	orphan := pending
	orphan.LeaseID, orphan.ServerID = "bb", "gone"
	for _, l := range []store.FanLease{pending, orphan} {
		if err := r.db.Leases().Create(ctxT(t), l); err != nil {
			t.Fatal(err)
		}
	}
	r.host.set(func(f *fakeApplier) { f.sweepErr = errors.New("ro fs") })
	r.svc.Reconcile(ctxT(t), true)
	if got, _ := r.db.Leases().Get(ctxT(t), "aa"); got.State != store.LeaseApplied {
		t.Fatalf("pending → %s", got.State)
	}
	if got, _ := r.db.Leases().Get(ctxT(t), "bb"); got.State != store.LeaseExpired {
		t.Fatalf("orphan → %s", got.State)
	}
	if e, ok := r.audit.find(ActionExpire, audit.ResultError); !ok || e.ErrorClass != "not_configured" {
		t.Fatalf("orphan audit = %+v", e)
	}
	r.floor.set(func(f *fakeApplier) { f.applyErr = bmc.ErrTimeout })
	if err := r.db.Leases().Transition(ctxT(t), "aa", store.LeaseApplied, store.LeaseEnded, now); err != nil {
		t.Fatal(err)
	}
	l2 := pending
	l2.LeaseID = "cc"
	_ = r.db.Leases().Create(ctxT(t), l2)
	r.svc.Reconcile(ctxT(t), true)
	if e, ok := r.audit.find(ActionReapply, audit.ResultError); !ok || e.ErrorClass != "timeout" {
		t.Fatalf("reapply failure audit = %+v", e)
	}
}

func TestRunTicks(t *testing.T) {
	r := newRig(t)
	svc, _ := New(Config{Policies: policies(), Appliers: map[string]Applier{"node-a": r.host, "node-b": r.floor},
		Leases: r.db.Leases(), Audit: r.audit, Now: r.clock.now, Tick: 5 * time.Millisecond,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	l, _ := svc.Start(ctxT(t), testActor, "node-a", Request{Pct: 55, Duration: 5 * time.Minute})
	r.clock.add(6 * time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, _ := r.db.Leases().Get(ctxT(t), l.LeaseID)
		if got.State == store.LeaseExpired {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run did not expire the lease")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestErrorClass(t *testing.T) {
	cases := map[error]string{bmc.ErrAuth: "auth", context.DeadlineExceeded: "timeout", errors.New("x"): "apply"}
	for err, want := range cases {
		if got := errorClass(err); got != want {
			t.Errorf("errorClass(%v) = %q", err, got)
		}
	}
	if PolicyFor(config.Server{ID: "x", Fan: config.FanConfig{Mode: config.FanHostLease, SafeMinPct: 30, MaxLease: time.Hour}}).SafeMin != 30 {
		t.Error("PolicyFor")
	}
}
