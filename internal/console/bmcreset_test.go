package console

import (
	"testing"
	"time"

	"oob-manager/internal/bmc/bmcssh/sshtest"
	"oob-manager/internal/config"
)

func TestEndForBMCResetEndsTheGraphicalConsole(t *testing.T) {
	h := newHarness(t, config.KindIDRAC9, nil)
	if h.svc.EndForBMCReset("r1") {
		t.Fatal("no console was running")
	}
	b := h.open(false, nil)
	waitUntil(t, func() bool { return h.svc.Status("r1").InUse })
	if !h.svc.EndForBMCReset("r1") {
		t.Fatal("the running console was not reported")
	}
	<-b.done
	if r := h.audit.waitFor(t, "console.vnc.stop", 1)[0].Params["reason"]; r != "bmc_reset" {
		t.Errorf("reason = %v", r)
	}
	h.svc.recordProbe("r1", Probe{State: ProbeOK, CheckedAt: time.Now()})
	h.svc.ForgetProbe("r1")
	if p := h.svc.Status("r1").Probe; !p.CheckedAt.IsZero() {
		t.Fatalf("probe kept: %+v", p)
	}
}

func TestEndForBMCResetEndsTheSerialConsole(t *testing.T) {
	h := newSerialHarness(t, sshtest.Options{}, nil)
	if h.svc.EndForBMCReset("r1") {
		t.Fatal("no console was running")
	}
	r := h.open(false, nil)
	r.waitOutput(t, "Serial Device 2")
	if !h.svc.EndForBMCReset("r1") {
		t.Fatal("the running console was not reported")
	}
	if got := r.endReason(t); got != "bmc_reset" {
		t.Errorf("reason %q", got)
	}
	_ = r.wait(t)
	if h.svc.Status("r1").Last.At.IsZero() {
		t.Fatal("the session left no last attempt to forget")
	}
	h.svc.ForgetAttempt("r1")
	if last := h.svc.Status("r1").Last; !last.At.IsZero() {
		t.Fatalf("last attempt kept: %+v", last)
	}
}
