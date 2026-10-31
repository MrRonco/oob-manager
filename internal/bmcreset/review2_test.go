package bmcreset

import (
	"errors"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/fleet"
	"oob-manager/internal/store"
)

// TestIdleClearsOnlyItsOwnBusyMark (review N1): a request whose refusal released the
// reservation must not clear the busy mark of the request that reserved after it.
func TestIdleClearsOnlyItsOwnBusyMark(t *testing.T) {
	r := newRig(t)
	a := request{id: "node-a", corr: "a", at: t0}
	prev, err := r.svc.reserve(a)
	if err != nil {
		t.Fatal(err)
	}
	r.svc.release(a, prev) // A was refused before the POST
	b := request{id: "node-a", corr: "b", at: t0}
	if _, err := r.svc.reserve(b); err != nil {
		t.Fatal(err)
	}
	r.svc.idle(a) // A's deferred idle runs late
	if !r.svc.Busy("node-a") {
		t.Fatal("A's idle cleared B's busy mark")
	}
	r.svc.release(a, prev) // and so does a stale release
	if !r.svc.Busy("node-a") {
		t.Fatal("A's release cleared B's busy mark")
	}
	r.svc.idle(b)
	if r.svc.Busy("node-a") {
		t.Fatal("B's own idle did not clear it")
	}
}

// TestPowerActionStartingDuringTheReservation (review N2): a power action that started
// between the first check and the reservation is caught by the re-check after it.
func TestPowerActionStartingDuringTheReservation(t *testing.T) {
	r := newRig(t)
	r.power.pendingFrom = 2 // the first check sees nothing, the re-check sees it pending
	if err := r.svc.Request(ctxT(t), "node-a", admin); !errors.Is(err, ErrPowerPending) {
		t.Fatalf("err = %v", err)
	}
	if r.opens != 0 || r.svc.Busy("node-a") || r.svc.CooldownLeft("node-a") != 0 {
		t.Fatalf("opens %d busy %v cooldown %v", r.opens, r.svc.Busy("node-a"), r.svc.CooldownLeft("node-a"))
	}
	if e, _ := r.audit.find(ActionReset, audit.ResultDenied); e.ErrorClass != "power_pending" {
		t.Fatalf("denied %+v", e)
	}
}

// TestRebuiltServerIsRetriedOnce (review code LOW): ExpectRestart losing a race with a
// hot apply of the same server is tried once more.
func TestRebuiltServerIsRetriedOnce(t *testing.T) {
	r := newRig(t)
	r.fleet.errOnce = fleet.ErrUnknownServer
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatalf("the retry did not open the window: %v", err)
	}
	if resets, _ := r.resetter.counts(); resets != 1 {
		t.Fatalf("resets %d", resets)
	}
	r2 := newRig(t)
	r2.fleet.err = fleet.ErrUnknownServer // gone for good
	if err := r2.svc.Request(ctxT(t), "node-a", admin); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v", err)
	}
}

// TestUnconfirmedReturnIsNotARestart (review N3): a return that does not confirm the
// restart is not the server's last restart.
func TestUnconfirmedReturnIsNotARestart(t *testing.T) {
	r := newRig(t)
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatal(err)
	}
	r.fleet.end(t, "node-a", fleet.RestartEnd{Outcome: fleet.RestartBack, At: t0.Add(time.Minute),
		State: backState(t0.Add(-time.Hour))}) // LastResetTime did not move
	e := r.audit.waitFor(t, ActionVerified, audit.ResultOK)
	if e.Params["restart_confirmed"] != false {
		t.Fatalf("params %+v", e.Params)
	}
	st := waitState(t, r, func(st State) bool { return st.Last.Result == store.BMCResetVerified })
	if st.HasVerified {
		t.Fatalf("an unconfirmed return counts as a restart: %+v", st.LastVerified)
	}
	// After a restart of the app, too.
	svc := r.service(t)
	t.Cleanup(svc.Shutdown)
	if err := svc.Start(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if svc.State("node-a").HasVerified {
		t.Fatal("Start loaded an unconfirmed return as the last restart")
	}
}

func TestConfirmedReturnIsMarked(t *testing.T) {
	r := newRig(t)
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatal(err)
	}
	r.fleet.end(t, "node-a", fleet.RestartEnd{Outcome: fleet.RestartBack, At: t0.Add(time.Minute), State: backState(t0.Add(time.Second))})
	if e := r.audit.waitFor(t, ActionVerified, audit.ResultOK); e.Params["restart_confirmed"] != true {
		t.Fatalf("params %+v", e.Params)
	}
}
