package power

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"oob-manager/internal/bmc"
)

// TestVerifiedTransitionIsObserved (audit R2-08): a verified end state is handed to
// Config.OnVerified at once, with the action and the user; a verification that failed
// or stayed unconfirmed reports nothing.
func TestVerifiedTransitionIsObserved(t *testing.T) {
	var mu sync.Mutex
	var seen []Observation
	record := func(cfg *Config) {
		cfg.OnVerified = func(id string, o Observation) {
			mu.Lock()
			defer mu.Unlock()
			if id == "srv" {
				seen = append(seen, o)
			}
		}
	}
	ctl := &fakeCtl{allowed: allResets, initial: bmc.PowerOn, states: []bmc.PowerState{bmc.PowerPoweringOff, bmc.PowerOff}}
	h := newHarness(t, ctl, record)
	if err := h.svc.Request(context.Background(), "srv", ForceOff, actor); err != nil {
		t.Fatal(err)
	}
	op := waitFinal(t, h.svc, "srv")
	mu.Lock()
	got := append([]Observation(nil), seen...)
	mu.Unlock()
	if len(got) != 1 || got[0].State != bmc.PowerOff || got[0].Action != ForceOff || got[0].By != "alice" ||
		!got[0].At.Equal(op.FinishedAt) {
		t.Fatalf("observations %+v (op %+v)", got, op)
	}

	// Unconfirmed (a restart never seen leaving On) and failed verifications say nothing.
	for _, c := range []struct {
		action Action
		states []bmc.PowerState
	}{{ForceRestart, []bmc.PowerState{bmc.PowerOn}}, {GracefulShutdown, []bmc.PowerState{bmc.PowerOn}}} {
		seen = nil
		ctl := &fakeCtl{allowed: allResets, initial: bmc.PowerOn, states: c.states}
		h := newHarness(t, ctl, record)
		if err := h.svc.Request(context.Background(), "srv", c.action, actor); err != nil {
			t.Fatal(err)
		}
		if op := waitFinal(t, h.svc, "srv"); op.Phase == PhaseDone {
			t.Fatalf("%s: unexpectedly verified", c.action)
		}
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n != 0 {
			t.Fatalf("%s reported %d observations", c.action, n)
		}
	}
}

// TestOnVerifiedRunsBeforeTheOperationIsFinal (review C-L8): a reader that sees the
// operation done also sees the fleet's published state, because OnVerified runs while
// the operation is still pending.
func TestOnVerifiedRunsBeforeTheOperationIsFinal(t *testing.T) {
	var svc atomic.Pointer[Service]
	finalAtCallback := make(chan bool, 1)
	ctl := &fakeCtl{allowed: allResets, initial: bmc.PowerOn, states: []bmc.PowerState{bmc.PowerOff}}
	h := newHarness(t, ctl, func(cfg *Config) {
		cfg.OnVerified = func(id string, _ Observation) {
			op, _ := svc.Load().Last(id)
			finalAtCallback <- op.Final()
		}
	})
	svc.Store(h.svc)
	if err := h.svc.Request(context.Background(), "srv", ForceOff, actor); err != nil {
		t.Fatal(err)
	}
	if final := <-finalAtCallback; final {
		t.Fatal("the operation was final before OnVerified ran")
	}
	if op := waitFinal(t, h.svc, "srv"); op.Phase != PhaseDone {
		t.Fatalf("op %+v", op)
	}
}
