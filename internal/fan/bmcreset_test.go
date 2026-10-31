package fan

import (
	"errors"
	"testing"
	"time"

	"oob-manager/internal/audit"
)

func TestReapplyAfterBMCReset(t *testing.T) {
	r := newRig(t)
	if ok, err := r.svc.ReapplyAfterBMCReset(ctxT(t), "node-b"); ok || err != nil {
		t.Fatalf("no lease: %v %v", ok, err)
	}
	if _, err := r.svc.Start(ctxT(t), testActor, "node-b", Request{Pct: 60, Duration: 30 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.svc.Start(ctxT(t), testActor, "node-a", Request{Pct: 40, Duration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	floorBefore, _ := r.floor.counts()
	hostBefore, _ := r.host.counts()
	if ok, err := r.svc.ReapplyAfterBMCReset(ctxT(t), "node-b"); !ok || err != nil {
		t.Fatalf("redfish floor: %v %v", ok, err)
	}
	if ok, err := r.svc.ReapplyAfterBMCReset(ctxT(t), "node-a"); ok || err != nil {
		t.Fatalf("host lease must be left alone: %v %v", ok, err)
	}
	if ok, _ := r.svc.ReapplyAfterBMCReset(ctxT(t), "nope"); ok {
		t.Fatal("unknown server")
	}
	if f, _ := r.floor.counts(); f != floorBefore+1 {
		t.Fatalf("floor applies %d -> %d", floorBefore, f)
	}
	if h, _ := r.host.counts(); h != hostBefore {
		t.Fatal("the host lease file was rewritten")
	}
	e, ok := r.audit.find(ActionReapply, audit.ResultOK)
	if !ok || e.ServerID != "node-b" || e.Params["reason"] != "bmc_reset" || e.Principal != "system" {
		t.Fatalf("audit %+v", e)
	}
	r.floor.set(func(f *fakeApplier) { f.applyErr = errors.New("bmc away") })
	if ok, err := r.svc.ReapplyAfterBMCReset(ctxT(t), "node-b"); ok || err == nil {
		t.Fatalf("failure: %v %v", ok, err)
	}
	if _, ok := r.audit.find(ActionReapply, audit.ResultError); !ok {
		t.Fatal("failure not audited")
	}
	r.clock.add(time.Hour)
	r.floor.set(func(f *fakeApplier) { f.applyErr = nil })
	if ok, _ := r.svc.ReapplyAfterBMCReset(ctxT(t), "node-b"); ok {
		t.Fatal("an expired lease was applied again")
	}
}
