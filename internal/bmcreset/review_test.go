package bmcreset

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
	"oob-manager/internal/store"
)

// TestBusyFromReservationToWindowEnd (review S-M1): the server is busy for the power
// interlock while the login and discovery run, not only once the window is open.
func TestBusyFromReservationToWindowEnd(t *testing.T) {
	r := newRig(t)
	inOpen, unblock := make(chan struct{}), make(chan struct{})
	r.openHook = func() { close(inOpen); <-unblock }
	done := make(chan error, 1)
	go func() { done <- r.svc.Request(ctxT(t), "node-a", admin) }()
	<-inOpen
	if !r.svc.Busy("node-a") || !r.svc.State("node-a").InFlight || r.svc.Busy("node-b") {
		t.Fatal("not busy during the login")
	}
	if err := r.svc.Request(ctxT(t), "node-a", admin); !errors.Is(err, ErrRestarting) {
		t.Fatalf("a second request during the login: %v", err)
	}
	close(unblock)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !r.svc.Busy("node-a") || r.svc.State("node-a").InFlight {
		t.Fatal("the open window keeps the server busy; the request is no longer in flight")
	}
	r.fleet.end(t, "node-a", fleet.RestartEnd{Outcome: fleet.RestartBack, At: t0.Add(time.Minute), State: backState(time.Time{})})
	waitState(t, r, func(st State) bool { return !st.Restarting })
	if r.svc.Busy("node-a") {
		t.Fatal("still busy after the window closed")
	}
}

func TestNotBusyAfterARefusalBeforeThePost(t *testing.T) {
	r := newRig(t)
	r.openErr = fmt.Errorf("x: %w", bmc.ErrAuth)
	if err := r.svc.Request(ctxT(t), "node-a", admin); !errors.Is(err, ErrBMC) {
		t.Fatalf("err = %v", err)
	}
	if r.svc.Busy("node-a") {
		t.Fatal("busy after a failed login")
	}
	if e, _ := r.audit.find(ActionReset, audit.ResultError); e.Params["after_started"] != true {
		t.Fatalf("the refusal does not close the requested alert: %+v", e)
	}
}

// TestWindowStampedAtThePost (review S-L1, S-L5): a slow login moves the window, the
// deadline and the downtime to the POST; requested_at stays the request.
func TestWindowStampedAtThePost(t *testing.T) {
	r := newRig(t)
	r.openHook = func() { r.clock.add(50 * time.Second) }
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatal(err)
	}
	sent := t0.Add(50 * time.Second)
	w, _ := r.fleet.window("node-a")
	if !w.Since.Equal(sent) || !w.Until.Equal(sent.Add(3*time.Minute)) {
		t.Fatalf("window %+v", w)
	}
	rows, _ := r.db.BMCResets().Open(ctxT(t))
	if len(rows) != 1 || !rows[0].RequestedAt.Equal(t0) || !rows[0].SentAt.Equal(sent) {
		t.Fatalf("row %+v", rows)
	}
	if r.svc.CooldownLeft("node-a") != DefaultCooldown-50*time.Second {
		t.Fatalf("cooldown counts from the request: %v", r.svc.CooldownLeft("node-a"))
	}
	r.fleet.end(t, "node-a", fleet.RestartEnd{Outcome: fleet.RestartBack, At: sent.Add(100 * time.Second),
		State: backState(time.Time{})})
	if e := r.audit.waitFor(t, ActionVerified, audit.ResultOK); e.Params["downtime_s"] != int64(100) {
		t.Fatalf("downtime from the POST: %+v", e.Params)
	}
}

// TestPostWithoutAnAnswer (review C-M2): a connection lost after the request was
// written is sent_unconfirmed; the window stays open; a later return is confirmed only
// by a newer LastResetTime.
func TestPostWithoutAnAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		last   time.Time
		detail string
	}{
		{"no LastResetTime (iDRAC8)", time.Time{}, store.BMCResetUnconfirmed},
		{"LastResetTime moved (iDRAC9)", t0.Add(30 * time.Second), ""},
		{"LastResetTime unchanged", t0.Add(-time.Hour), store.BMCResetUnchanged},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			r.resetter.resetErr = fmt.Errorf("POST: EOF: %w", bmc.ErrUnreachable)
			if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
				t.Fatalf("no answer is treated as sent: %v", err)
			}
			if e, _ := r.audit.find(ActionReset, audit.ResultOK); e.Params["outcome"] != "sent_unconfirmed" ||
				e.Params["bmc_status"] != "unreachable" {
				t.Fatalf("ok row %+v", e.Params)
			}
			rows, _ := r.db.BMCResets().Open(ctxT(t))
			if len(rows) != 1 || !rows[0].Unconfirmed || !r.svc.State("node-a").Restarting {
				t.Fatalf("rows %+v", rows)
			}
			r.fleet.end(t, "node-a", fleet.RestartEnd{Outcome: fleet.RestartBack, At: t0.Add(time.Minute), State: backState(tc.last)})
			st := waitState(t, r, func(st State) bool { return st.Last.Result == store.BMCResetVerified })
			if st.Last.Detail != tc.detail || st.HasVerified != (tc.detail == "") {
				t.Fatalf("detail %q, want %q", st.Last.Detail, tc.detail)
			}
		})
	}
}

// TestLastResetTimeJudgedOnlyOnAFreshProbe (review C-M4).
func TestLastResetTimeJudgedOnlyOnAFreshProbe(t *testing.T) {
	r := newRig(t)
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatal(err)
	}
	stale := backState(t0.Add(-time.Hour)) // an old LastResetTime from a probe before the POST
	stale.Capabilities = bmc.NewCapabilities(bmc.CapabilityParams{Flags: bmc.CapabilityFlags{
		BMCLastReset: t0.Add(-time.Hour), ProbedAt: t0.Add(-time.Minute)}})
	r.fleet.end(t, "node-a", fleet.RestartEnd{Outcome: fleet.RestartBack, At: t0.Add(time.Minute), State: stale})
	e := r.audit.waitFor(t, ActionVerified, audit.ResultOK)
	if e.Params["last_reset_time_check"] != "not_done" || e.Params["last_reset_time_unchanged"] != nil {
		t.Fatalf("params %+v", e.Params)
	}
	if st := waitState(t, r, func(st State) bool { return st.HasVerified }); st.Last.Detail != "" {
		t.Fatalf("detail %q", st.Last.Detail)
	}
}

// TestFinalAuditRowsAreRetried (review S-L4).
func TestFinalAuditRowsAreRetried(t *testing.T) {
	r := newRig(t)
	r.audit.failNext, r.audit.failResult = 2, audit.ResultOK
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.audit.find(ActionReset, audit.ResultOK); !ok {
		t.Fatal("the ok row was lost to a transient failure")
	}
}

// TestRearmedWindowIsNoted (review S-L5): part of a re-armed window was not watched.
func TestRearmedWindowIsNoted(t *testing.T) {
	r := newRig(t)
	if _, err := r.db.BMCResets().Insert(ctxT(t), store.BMCResetRow{ServerID: "node-a", CorrelationID: "c",
		RequestedAt: t0.Add(-time.Minute), SentAt: t0.Add(-50 * time.Second), RequestedBy: "bob", ResetType: ResetType,
		Result: store.BMCResetSent, DeadlineAt: t0.Add(2 * time.Minute), Unconfirmed: true}); err != nil {
		t.Fatal(err)
	}
	svc := r.service(t)
	t.Cleanup(svc.Shutdown)
	if err := svc.Start(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	if w, _ := r.fleet.window("node-a"); !w.Since.Equal(t0.Add(-50 * time.Second)) {
		t.Fatalf("re-armed from the POST time: %+v", w)
	}
	r.fleet.end(t, "node-a", fleet.RestartEnd{Outcome: fleet.RestartBack, At: t0.Add(time.Minute), State: backState(time.Time{})})
	if e := r.audit.waitFor(t, ActionVerified, audit.ResultOK); e.Params["rearmed"] != true || e.Params["post_unconfirmed"] != true {
		t.Fatalf("params %+v", e.Params)
	}
}

// TestWindowEndingDuringShutdownKeepsTheRowOpen (review C-L2, C-L8).
func TestWindowEndingDuringShutdownKeepsTheRowOpen(t *testing.T) {
	r := newRig(t)
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatal(err)
	}
	r.svc.Shutdown()
	r.fleet.end(t, "node-a", fleet.RestartEnd{Outcome: fleet.RestartBack, At: t0.Add(time.Minute), State: backState(time.Time{})})
	if open, _ := r.db.BMCResets().Open(ctxT(t)); len(open) != 1 {
		t.Fatalf("the row was closed after Shutdown: %+v", open)
	}
	select {
	case <-r.back:
		t.Fatal("AfterBack ran after Shutdown")
	default:
	}
}

// TestTimeoutRunsAfterTimeout (review C-M3): the fan service learns of a late return.
func TestTimeoutRunsAfterTimeout(t *testing.T) {
	r := newRig(t)
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatal(err)
	}
	r.fleet.end(t, "node-a", fleet.RestartEnd{Outcome: fleet.RestartTimeout, At: t0.Add(3 * time.Minute)})
	select {
	case id := <-r.timeouts:
		if id != "node-a" {
			t.Fatalf("timeout for %s", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AfterTimeout did not run")
	}
}

// TestConcurrentRequestsReserveOnce (review C-L8): under -race, exactly one of many
// simultaneous requests reaches the BMC.
func TestConcurrentRequestsReserveOnce(t *testing.T) {
	r := newRig(t)
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for range 16 {
		wg.Go(func() { errs <- r.svc.Request(ctxT(t), "node-a", admin) })
	}
	wg.Wait()
	close(errs)
	ok := 0
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrRestarting) && !errors.Is(err, ErrCoolingDown):
			t.Fatalf("unexpected %v", err)
		}
	}
	if resets, _ := r.resetter.counts(); ok != 1 || resets != 1 {
		t.Fatalf("%d accepted, %d POSTs", ok, resets)
	}
}
