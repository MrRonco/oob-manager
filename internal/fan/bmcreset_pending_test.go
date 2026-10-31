package fan

import (
	"errors"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
)

func (s *Service) pendingOf(id string) (reapplyState, bool) {
	s.reMu.Lock()
	defer s.reMu.Unlock()
	st, ok := s.pending[id]
	return st, ok
}

func (a *fakeAudit) count(action, result string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.entries {
		if e.Action == action && e.Result == result {
			n++
		}
	}
	return n
}

func floorLease(t *testing.T, r *rig) {
	t.Helper()
	if _, err := r.svc.Start(ctxT(t), testActor, "node-b", Request{Pct: 60, Duration: time.Hour}); err != nil {
		t.Fatal(err)
	}
}

// TestReapplyBackoffDoublesToTheCap: due now, then 1, 2, 4, 8, 15, 15 minutes.
func TestReapplyBackoffDoublesToTheCap(t *testing.T) {
	r := newRig(t)
	floorLease(t, r)
	r.floor.set(func(f *fakeApplier) { f.applyErr = errors.New("bmc away") })
	r.svc.RequestReapply("node-b")
	if st, ok := r.svc.pendingOf("node-b"); !ok || !st.next.Equal(r.clock.now()) || st.wait != reapplyFirstWait {
		t.Fatalf("first state %+v %v", st, ok)
	}
	for _, want := range []time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute,
		reapplyMaxWait, reapplyMaxWait} {
		before, _ := r.floor.counts()
		r.svc.Reconcile(ctxT(t), false)
		if n, _ := r.floor.counts(); n != before+1 {
			t.Fatalf("not attempted when due (wait %v)", want)
		}
		st, _ := r.svc.pendingOf("node-b")
		if !st.next.Equal(r.clock.now().Add(want)) {
			t.Fatalf("next in %v, want %v", st.next.Sub(r.clock.now()), want)
		}
		r.svc.Reconcile(ctxT(t), false) // not due yet: no attempt
		if n, _ := r.floor.counts(); n != before+1 {
			t.Fatal("attempted before it was due")
		}
		r.clock.add(want)
	}
	if n := r.audit.count(ActionReapply, audit.ResultError); n != 0 {
		t.Fatalf("%d quiet failures audited", n)
	}
}

// TestReapplyRequestedTwiceAppliesOnceAndAuditsOnce.
func TestReapplyRequestedTwiceAppliesOnceAndAuditsOnce(t *testing.T) {
	r := newRig(t)
	floorLease(t, r)
	r.svc.RequestReapply("node-b")
	r.svc.RequestReapply("node-b")
	before, _ := r.floor.counts()
	for range 3 {
		r.svc.Reconcile(ctxT(t), false)
		r.clock.add(reapplyMaxWait)
	}
	if n, _ := r.floor.counts(); n != before+1 {
		t.Fatalf("%d applies, want 1", n-before)
	}
	if n := r.audit.count(ActionReapply, audit.ResultOK); n != 1 {
		t.Fatalf("success audited %d times", n)
	}
	if _, ok := r.svc.pendingOf("node-b"); ok {
		t.Fatal("entry kept after the success")
	}
}

// TestReapplyEntryDroppedWhenNothingIsLeftToApply: the lease ended or expired, the mode
// changed, the server is gone, or it never was a redfish-floor server.
func TestReapplyEntryDroppedWhenNothingIsLeftToApply(t *testing.T) {
	cases := map[string]func(t *testing.T, r *rig){
		"lease ended": func(t *testing.T, r *rig) {
			if err := r.svc.End(ctxT(t), testActor, "node-b"); err != nil {
				t.Fatal(err)
			}
		},
		"lease expired": func(_ *testing.T, r *rig) { r.clock.add(2 * time.Hour) },
		"mode changed": func(t *testing.T, r *rig) {
			ps := policies()
			ps[1].Mode = config.FanHostLease
			if err := r.svc.SetTargets(ctxT(t), []Target{{Policy: ps[0], Applier: r.host, Fingerprint: "a"},
				{Policy: ps[1], Applier: &fakeApplier{}, Fingerprint: "b2"}, {Policy: ps[2]}}); err != nil {
				t.Fatal(err)
			}
		},
		"server gone": func(t *testing.T, r *rig) {
			ps := policies()
			if err := r.svc.SetTargets(ctxT(t), []Target{{Policy: ps[0], Applier: r.host, Fingerprint: "a"}}); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			floorLease(t, r)
			r.svc.RequestReapply("node-b")
			change(t, r)
			before, _ := r.floor.counts()
			r.svc.Reconcile(ctxT(t), false)
			if _, ok := r.svc.pendingOf("node-b"); ok {
				t.Fatal("entry kept")
			}
			if n, _ := r.floor.counts(); n != before {
				t.Fatal("applied although nothing was left to apply")
			}
		})
	}
	r := newRig(t)
	r.svc.RequestReapply("node-a") // host-lease
	r.svc.RequestReapply("node-c") // none
	r.svc.RequestReapply("nope")
	for _, id := range []string{"node-a", "node-c", "nope"} {
		if _, ok := r.svc.pendingOf(id); ok {
			t.Fatalf("%s: a server without a redfish floor was queued", id)
		}
	}
}
