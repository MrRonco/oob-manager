package fan

import (
	"errors"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/store"
)

func TestStartHostLeaseIsPending(t *testing.T) {
	r := newRig(t)
	l, err := r.svc.Start(ctxT(t), testActor, "node-a", Request{Pct: 55, Duration: 30 * time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if l.State != store.LeasePending || l.Pct != 55 || l.RequestedBy != "op" || l.Mode != store.LeaseBoost ||
		!l.ExpiresAt.Equal(r.clock.now().Add(30*time.Minute)) || len(l.LeaseID) != 32 {
		t.Fatalf("lease = %+v", l)
	}
	got, err := r.db.Leases().Active(ctxT(t), "node-a")
	if err != nil || got.LeaseID != l.LeaseID {
		t.Fatalf("active = %+v %v", got, err)
	}
	if n, _ := r.host.counts(); n != 1 {
		t.Fatalf("applied %d", n)
	}
	e, ok := r.audit.find("fan.lease.create", audit.ResultOK)
	if !ok || e.ServerID != "node-a" || e.Principal != "op" || e.SrcIP != "192.0.2.70" || e.Params["pct"] != 55 ||
		e.Params["minutes"] != 30 || e.Params["mode"] != "host-lease" || e.Params["lease_id"] != l.LeaseID {
		t.Fatalf("audit = %+v", e)
	}
}

func TestStartRedfishFloorIsAppliedWithOriginal(t *testing.T) {
	r := newRig(t)
	r.floor.set(func(f *fakeApplier) { f.plan = &Plan{Pct: 60, Original: 255, HasOriginal: true} })
	l, err := r.svc.Start(ctxT(t), testActor, "node-b", Request{Pct: 50, Duration: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if l.State != store.LeaseApplied || l.Pct != 60 || !l.HasOriginal || l.OriginalValue != 255 {
		t.Fatalf("lease = %+v", l)
	}
	row, _ := r.db.Leases().Get(ctxT(t), l.LeaseID)
	if row.State != store.LeaseApplied || row.OriginalValue != 255 {
		t.Fatalf("row = %+v", row)
	}
}

func TestStartRefusals(t *testing.T) {
	r := newRig(t)
	req := Request{Pct: 55, Duration: 30 * time.Minute}
	for _, id := range []string{"node-c", "nope", ""} {
		if _, err := r.svc.Start(ctxT(t), testActor, id, req); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("%q: %v", id, err)
		}
	}
	if _, err := r.svc.Start(ctxT(t), testActor, "node-a", req); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Start(ctxT(t), testActor, "node-a", req); !errors.Is(err, ErrActive) {
		t.Fatalf("second lease: %v", err)
	}
	if _, ok := r.audit.find("fan.lease.create", audit.ResultDenied); !ok {
		t.Error("refusal not audited")
	}
	for _, bad := range []Request{{Pct: 29, Duration: time.Hour}, {Pct: 101, Duration: time.Hour},
		{Pct: 50, Duration: time.Minute}, {Pct: 50, Duration: 3 * time.Hour}} {
		if _, err := r.svc.Start(ctxT(t), testActor, "node-b", bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("hand-built request %+v: %v", bad, err)
		}
	}
}

func TestStartApplierFailures(t *testing.T) {
	r := newRig(t)
	req := Request{Pct: 50, Duration: time.Hour}
	r.floor.set(func(f *fakeApplier) { f.prepareErr = errors.New("bmc down") })
	if _, err := r.svc.Start(ctxT(t), testActor, "node-b", req); !errors.Is(err, ErrApply) {
		t.Fatalf("prepare: %v", err)
	}
	if rows, _ := r.db.Leases().ListByServer(ctxT(t), "node-b", 10); len(rows) != 0 {
		t.Fatal("a lease was stored although Prepare failed")
	}
	// A plan below the safe minimum (BMC maximum lower than the floor) is refused.
	r.floor.set(func(f *fakeApplier) { f.prepareErr, f.plan = nil, &Plan{Pct: 40} })
	if _, err := r.svc.Start(ctxT(t), testActor, "node-b", req); !errors.Is(err, ErrApply) {
		t.Fatalf("plan below floor: %v", err)
	}
	r.floor.set(func(f *fakeApplier) {
		f.plan, f.applyErr = &Plan{Pct: 50, Original: 255, HasOriginal: true}, errors.New("patch failed")
	})
	if _, err := r.svc.Start(ctxT(t), testActor, "node-b", req); !errors.Is(err, ErrApply) {
		t.Fatalf("apply: %v", err)
	}
	rows, _ := r.db.Leases().ListByServer(ctxT(t), "node-b", 10)
	if len(rows) != 1 || rows[0].State != store.LeaseRejected {
		t.Fatalf("rows = %+v", rows)
	}
	if _, n := r.floor.counts(); n != 1 {
		t.Fatal("a failed apply must restore the original value")
	}
	if e, ok := r.audit.find("fan.lease.create", audit.ResultError); !ok || e.ErrorClass == "" {
		t.Fatalf("audit = %+v", e)
	}
}

func TestEndNow(t *testing.T) {
	r := newRig(t)
	if err := r.svc.End(ctxT(t), testActor, "node-a"); !errors.Is(err, ErrNoLease) {
		t.Fatalf("no lease: %v", err)
	}
	l, _ := r.svc.Start(ctxT(t), testActor, "node-a", Request{Pct: 55, Duration: time.Hour})
	r.host.set(func(f *fakeApplier) { f.releaseErr = errors.New("disk full") })
	if err := r.svc.End(ctxT(t), testActor, "node-a"); !errors.Is(err, ErrRelease) {
		t.Fatalf("release failure: %v", err)
	}
	if got, _ := r.db.Leases().Get(ctxT(t), l.LeaseID); !got.State.Active() {
		t.Fatal("a lease whose release failed must stay active (retried)")
	}
	r.host.set(func(f *fakeApplier) { f.releaseErr = nil })
	if err := r.svc.End(ctxT(t), testActor, "node-a"); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.db.Leases().Get(ctxT(t), l.LeaseID); got.State != store.LeaseEnded {
		t.Fatalf("state = %s", got.State)
	}
	if e, ok := r.audit.find("fan.lease.end", audit.ResultOK); !ok || e.Params["lease_id"] != l.LeaseID {
		t.Fatalf("audit = %+v", e)
	}
	if err := r.svc.End(ctxT(t), testActor, "node-c"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("mode none: %v", err)
	}
}

func TestStatus(t *testing.T) {
	r := newRig(t)
	r.host.set(func(f *fakeApplier) { f.obs = Observation{Owner: OwnerCurve, AppliedPct: 35, HasPct: true} })
	st, err := r.svc.Status(ctxT(t), "node-a")
	if err != nil || st.HasLease || st.Owner != OwnerCurve || st.AppliedPct != 35 || st.Policy.SafeMin != 30 {
		t.Fatalf("status = %+v %v", st, err)
	}
	l, _ := r.svc.Start(ctxT(t), testActor, "node-a", Request{Pct: 55, Duration: time.Hour})
	r.clock.add(20 * time.Minute)
	st, _ = r.svc.Status(ctxT(t), "node-a")
	if !st.HasLease || st.Lease.LeaseID != l.LeaseID || st.Remaining != 40*time.Minute {
		t.Fatalf("status = %+v", st)
	}
	if _, err := r.svc.Status(ctxT(t), "node-c"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("mode none: %v", err)
	}
	if _, ok := r.svc.Policy("node-c"); ok {
		t.Error("mode none has no policy")
	}
	if p, ok := r.svc.Policy("node-b"); !ok || p.SafeMin != 41 {
		t.Errorf("policy = %+v", p)
	}
}

func TestNewValidates(t *testing.T) {
	r := newRig(t)
	cases := map[string]Config{
		"no leases":  {Audit: r.audit},
		"no audit":   {Leases: r.db.Leases()},
		"no applier": {Leases: r.db.Leases(), Audit: r.audit, Policies: policies()[:1]},
		"stray":      {Leases: r.db.Leases(), Audit: r.audit, Appliers: map[string]Applier{"x": r.host}},
		"dup":        {Leases: r.db.Leases(), Audit: r.audit, Policies: []Policy{policies()[2], policies()[2]}},
	}
	for name, c := range cases {
		if _, err := New(c); err == nil || !strings.Contains(err.Error(), "fan:") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

// TestStartAuditFailsClosed: a fan lease is a dangerous action (CLAUDE.md rule 9), so
// like power, BMC restart and the consoles it is refused when its "started" audit row
// cannot be written: no lease row, no BMC read and no applier call.
func TestStartAuditFailsClosed(t *testing.T) {
	for _, id := range []string{"node-a", "node-b"} {
		t.Run(id, func(t *testing.T) {
			r := newRig(t)
			r.audit.setFail(true)
			if _, err := r.svc.Start(ctxT(t), testActor, id, Request{Pct: 55, Duration: 30 * time.Minute}); !errors.Is(err, ErrAudit) {
				t.Fatalf("err = %v, want ErrAudit", err)
			}
			if a, _ := r.host.counts(); a != 0 {
				t.Fatalf("host applier called %d times without an audit row", a)
			}
			if a, _ := r.floor.counts(); a != 0 {
				t.Fatalf("floor applier called %d times without an audit row", a)
			}
			if _, err := r.db.Leases().Active(ctxT(t), id); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("a lease row exists without an audit row: %v", err)
			}
			r.audit.setFail(false)
			if _, err := r.svc.Start(ctxT(t), testActor, id, Request{Pct: 55, Duration: 30 * time.Minute}); err != nil {
				t.Fatalf("after the audit store is back: %v", err)
			}
			if _, ok := r.audit.find("fan.lease.create", audit.ResultStarted); !ok {
				t.Error("no started row before the lease")
			}
		})
	}
}
