package power

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/store"
)

// TestRefusedWhileTheBMCRestarts (tech_doc §37): the operator login and the
// verification reads would both fail while the BMC restarts, so a power request is
// refused before the cooldown is taken or the BMC contacted.
func TestRefusedWhileTheBMCRestarts(t *testing.T) {
	var restarting atomic.Bool
	restarting.Store(true)
	h := newHarness(t, &fakeCtl{allowed: allResets, initial: bmc.PowerOn}, func(c *Config) {
		c.Restarting = func(id string) bool { return id == "srv" && restarting.Load() }
	})
	if err := h.svc.Request(context.Background(), "srv", ForceRestart, actor); !errors.Is(err, ErrBMCRestarting) {
		t.Fatalf("err = %v", err)
	}
	if h.openCount() != 0 || h.svc.CooldownLeft("srv") != 0 {
		t.Fatalf("opens %d cooldown %v", h.openCount(), h.svc.CooldownLeft("srv"))
	}
	e := h.aud.all()
	if len(e) != 1 || e[0].Result != audit.ResultDenied || e[0].ErrorClass != "bmc_restarting" {
		t.Fatalf("audit %+v", e)
	}
	restarting.Store(false)
	if err := h.svc.Request(context.Background(), "srv", ForceRestart, actor); err != nil {
		t.Fatalf("after the restart: %v", err)
	}
}

// TestBMCResetStartingDuringTheReservation (review N2): a BMC reset that became busy
// between the first check and the power reservation is caught by the re-check.
func TestBMCResetStartingDuringTheReservation(t *testing.T) {
	var calls atomic.Int32
	h := newHarness(t, &fakeCtl{allowed: allResets, initial: bmc.PowerOn}, func(c *Config) {
		c.Restarting = func(string) bool { return calls.Add(1) >= 2 }
	})
	if err := h.svc.Request(context.Background(), "srv", ForceRestart, actor); !errors.Is(err, ErrBMCRestarting) {
		t.Fatalf("err = %v", err)
	}
	if h.openCount() != 0 || h.svc.CooldownLeft("srv") != 0 {
		t.Fatalf("opens %d cooldown %v", h.openCount(), h.svc.CooldownLeft("srv"))
	}
	if _, ok := h.svc.Last("srv"); ok {
		t.Fatal("a refused request left an operation")
	}
	e := h.aud.all()
	if len(e) != 1 || e[0].ErrorClass != "bmc_restarting" || e[0].Result != audit.ResultDenied {
		t.Fatalf("audit %+v", e)
	}
}

// hookAudit runs onStarted inside the "started" write (between reserve and the audit
// row being stored), then behaves like fakeAudit.
type hookAudit struct {
	*fakeAudit
	onStarted func()
}

func (a hookAudit) Record(ctx context.Context, e audit.Entry) (store.AuditRecord, error) {
	if e.Result == audit.ResultStarted && a.onStarted != nil {
		a.onStarted()
	}
	return a.fakeAudit.Record(ctx, e)
}

// TestPendingFromTheReservation (review N2 residual): a BMC reset that checks for a
// pending power operation while power writes its "started" row sees it pending; if that
// write fails, the operation is rolled back.
func TestPendingFromTheReservation(t *testing.T) {
	var svc *Service
	var seen Operation
	var seenOK bool
	aud := hookAudit{fakeAudit: &fakeAudit{}}
	aud.onStarted = func() { seen, seenOK = svc.Last("srv") } // a reset's powerPending check
	h := newHarness(t, &fakeCtl{allowed: allResets, initial: bmc.PowerOn}, func(c *Config) { c.Audit = aud })
	svc = h.svc
	if err := h.svc.Request(context.Background(), "srv", ForceOff, actor); err != nil {
		t.Fatal(err)
	}
	if !seenOK || seen.Final() || seen.Phase != PhaseSending {
		t.Fatalf("during the started write the operation was %+v (%v)", seen, seenOK)
	}

	// The started write fails: no operation is left behind, the cooldown is given back.
	aud2 := hookAudit{fakeAudit: &fakeAudit{fail: true}}
	h2 := newHarness(t, &fakeCtl{allowed: allResets, initial: bmc.PowerOn}, func(c *Config) { c.Audit = aud2 })
	if err := h2.svc.Request(context.Background(), "srv", ForceOff, actor); !errors.Is(err, ErrAudit) {
		t.Fatalf("err = %v", err)
	}
	if op, ok := h2.svc.Last("srv"); ok {
		t.Fatalf("a failed started write left %+v", op)
	}
	if h2.svc.CooldownLeft("srv") != 0 {
		t.Fatal("cooldown kept")
	}

	// With an earlier operation, the failed write puts it back.
	done := waitFinal(t, h.svc, "srv")
	h.clock.advance(time.Hour)
	aud.mu.Lock()
	aud.fail = true
	aud.mu.Unlock()
	if err := h.svc.Request(context.Background(), "srv", On, actor); !errors.Is(err, ErrAudit) {
		t.Fatalf("err = %v", err)
	}
	if op, ok := h.svc.Last("srv"); !ok || op != done {
		t.Fatalf("previous operation not restored: %+v, want %+v", op, done)
	}
}
