package fan

import (
	"errors"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/store"
)

func targets(host, floor Applier, fp string) []Target {
	ps := policies()
	return []Target{{Policy: ps[0], Applier: host, Fingerprint: "a" + fp}, {Policy: ps[1], Applier: floor, Fingerprint: "b" + fp},
		{Policy: ps[2]}}
}

// TestSetTargetsKeepsUnchangedLease: same fingerprint and policy → the running applier
// is kept (the replacement is unused) and the active lease is untouched.
func TestSetTargetsKeepsUnchangedLease(t *testing.T) {
	r := newRig(t)
	floor := &fakeApplier{immediate: true}
	if err := r.svc.SetTargets(ctxT(t), targets(&fakeApplier{}, floor, "1")); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Start(ctxT(t), testActor, "node-b", Request{Pct: 50, Duration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	spare := &fakeApplier{immediate: true}
	if err := r.svc.SetTargets(ctxT(t), targets(&fakeApplier{}, spare, "1")); err != nil {
		t.Fatal(err)
	}
	if _, rel := floor.counts(); rel != 0 {
		t.Fatalf("lease released on an unchanged server (%d)", rel)
	}
	st, err := r.svc.Status(ctxT(t), "node-b")
	if err != nil || !st.HasLease {
		t.Fatalf("status = %+v %v", st, err)
	}
	if err := r.svc.End(ctxT(t), testActor, "node-b"); err != nil {
		t.Fatal(err)
	}
	if _, rel := floor.counts(); rel != 1 {
		t.Fatal("the kept applier was not the one used")
	}
	if n, _ := spare.counts(); n != 0 {
		t.Fatal("the unused replacement applier was used")
	}
}

// TestSetTargetsRestoresLeaseFirst: a server whose fan setup changes or that is
// removed has its active lease released through the OLD applier (fans restored to the
// BMC's own curve) and closed before the new setup takes over; audited as config_changed.
func TestSetTargetsRestoresLeaseFirst(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Start(ctxT(t), testActor, "node-b", Request{Pct: 50, Duration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Start(ctxT(t), testActor, "node-a", Request{Pct: 40, Duration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	ps := policies()
	newFloor := &fakeApplier{immediate: true}
	// node-a removed, node-b changed (new fingerprint).
	if err := r.svc.SetTargets(ctxT(t), []Target{{Policy: ps[1], Applier: newFloor, Fingerprint: "b2"}}); err != nil {
		t.Fatal(err)
	}
	if _, rel := r.floor.counts(); rel != 1 {
		t.Fatalf("old floor applier released %d", rel)
	}
	if _, rel := r.host.counts(); rel != 1 {
		t.Fatalf("host lease released %d", rel)
	}
	for _, id := range []string{"node-a", "node-b"} {
		if _, err := r.db.Leases().Active(ctxT(t), id); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s lease still active: %v", id, err)
		}
	}
	if e, ok := r.audit.find("fan.lease.end", audit.ResultOK); !ok || e.Principal != "system" || e.Params["reason"] != "config_changed" {
		t.Fatalf("audit = %+v", e)
	}
	if _, ok := r.svc.Policy("node-a"); ok {
		t.Fatal("removed server still has fan control")
	}
	if _, err := r.svc.Start(ctxT(t), testActor, "node-b", Request{Pct: 60, Duration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if n, _ := newFloor.counts(); n != 1 {
		t.Fatalf("new applier used %d times", n)
	}
}

func TestSetTargetsReleaseFailureClosesLease(t *testing.T) {
	r := newRig(t)
	if _, err := r.svc.Start(ctxT(t), testActor, "node-b", Request{Pct: 50, Duration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	r.floor.set(func(f *fakeApplier) { f.releaseErr = errors.New("bmc down") })
	if err := r.svc.SetTargets(ctxT(t), nil); err != nil {
		t.Fatal(err)
	}
	if _, err := r.db.Leases().Active(ctxT(t), "node-b"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("lease left active: %v", err)
	}
	if e, ok := r.audit.find("fan.lease.end", audit.ResultError); !ok || e.Params["reason"] != "config_changed" {
		t.Fatalf("failed release not audited as an error: %+v", e)
	}
}

func TestSetTargetsValidates(t *testing.T) {
	r := newRig(t)
	bad := [][]Target{
		{{Policy: Policy{ServerID: "x", Mode: config.FanHostLease, SafeMin: 30, MaxLease: time.Hour}}},
		{{Policy: Policy{ServerID: "x", Mode: config.FanNone}, Applier: &fakeApplier{}}},
		{{Policy: Policy{ServerID: "x", Mode: config.FanNone}}, {Policy: Policy{ServerID: "x", Mode: config.FanNone}}},
	}
	for i, ts := range bad {
		if err := r.svc.SetTargets(ctxT(t), ts); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, ok := r.svc.Policy("node-a"); !ok {
		t.Fatal("a refused SetTargets changed the policies")
	}
}

// TestSetTargetsRace: Start and End race with SetTargets; run with -race. A Start that
// loses the race against a removal is refused, never applied through a dropped applier.
func TestSetTargetsRace(t *testing.T) {
	r := newRig(t)
	var wg sync.WaitGroup
	for i := range 20 {
		wg.Go(func() {
			_, _ = r.svc.Start(ctxT(t), testActor, "node-b", Request{Pct: 50, Duration: time.Hour})
			_ = r.svc.End(ctxT(t), testActor, "node-b")
			_, _ = r.svc.Status(ctxT(t), "node-b")
		})
		wg.Go(func() {
			fp := "x"
			if i%2 == 0 {
				fp = "y"
			}
			_ = r.svc.SetTargets(ctxT(t), targets(&fakeApplier{}, &fakeApplier{immediate: true}, fp))
		})
	}
	wg.Wait()
	_ = r.svc.SetTargets(ctxT(t), nil)
	if _, err := r.db.Leases().Active(ctxT(t), "node-b"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("lease left active after removal: %v", err)
	}
}
