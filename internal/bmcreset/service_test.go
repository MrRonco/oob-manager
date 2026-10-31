package bmcreset

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/config"
	"oob-manager/internal/fleet"
	"oob-manager/internal/power"
	"oob-manager/internal/store"
)

func backState(lastReset time.Time) fleet.ServerState {
	caps := bmc.NewCapabilities(bmc.CapabilityParams{Flags: bmc.CapabilityFlags{
		BMCFirmware: "7.00.00.182", BMCLastReset: lastReset, ManagerReset: true, ProbedAt: t0.Add(time.Minute)}})
	return fleet.ServerState{ID: "node-a", HasSnapshot: true, Capabilities: caps, HasCapabilities: true}
}

func TestRequestEndsConsolesThenPostsOnceAndOpensTheWindow(t *testing.T) {
	r := newRig(t)
	r.vnc.active = true
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatal(err)
	}
	if got, want := r.ev.all(), []string{"login", "window", "end vnc", "end serial", "post"}; !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
	if resets, closed := r.resetter.counts(); resets != 1 || closed != 1 {
		t.Fatalf("resets %d closed %d", resets, closed)
	}
	w, ok := r.fleet.window("node-a")
	if !ok || !w.Since.Equal(t0) || !w.Until.Equal(t0.Add(3*time.Minute)) || w.By != "alice" {
		t.Fatalf("window %+v %v", w, ok)
	}
	started, ok := r.audit.find(ActionReset, audit.ResultStarted)
	if !ok || started.Params["deadline_after"] != "3m0s" || started.ServerID != "node-a" ||
		started.Principal != "alice" || started.SrcIP != "192.0.2.70" {
		t.Fatalf("started %+v", started)
	}
	okRow, _ := r.audit.find(ActionReset, audit.ResultOK)
	if okRow.Params["outcome"] != "sent" || okRow.Params["consoles_ended"] != 1 || okRow.CorrelationID != started.CorrelationID ||
		okRow.Params["deadline"] != t0.Add(3*time.Minute).Format(time.RFC3339) {
		t.Fatalf("ok row %+v", okRow)
	}
	st := r.svc.State("node-a")
	if !st.Restarting || st.CooldownLeft != DefaultCooldown || !st.Window.Deadline.Equal(t0.Add(3*time.Minute)) ||
		!st.HasLast || st.Last.Result != store.BMCResetSent {
		t.Fatalf("state %+v", st)
	}
	rows, _ := r.db.BMCResets().Open(ctxT(t))
	if len(rows) != 1 || rows[0].RequestedBy != "alice" || rows[0].ResetType != "GracefulRestart" {
		t.Fatalf("rows %+v", rows)
	}
	if err := r.svc.Request(ctxT(t), "node-a", admin); !errors.Is(err, ErrRestarting) {
		t.Fatalf("second request: %v", err)
	}
	if e, _ := r.audit.find(ActionReset, audit.ResultDenied); e.ErrorClass != "restarting" {
		t.Fatalf("denied %+v", e)
	}
}

func TestVerifiedWhenTheBMCIsBack(t *testing.T) {
	r := newRig(t)
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatal(err)
	}
	back := t0.Add(130 * time.Second)
	r.fleet.end(t, "node-a", fleet.RestartEnd{Outcome: fleet.RestartBack, At: back, State: backState(t0.Add(5 * time.Second))})
	e := r.audit.waitFor(t, ActionVerified, audit.ResultOK)
	if e.Principal != "system" || e.Params["downtime_s"] != int64(130) || e.Params["firmware_version"] != "7.00.00.182" ||
		e.Params["last_reset_time"] != t0.Add(5*time.Second).Format(time.RFC3339) {
		t.Fatalf("verified %+v", e)
	}
	select {
	case id := <-r.back:
		if id != "node-a" {
			t.Fatalf("after back for %s", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("AfterBack did not run")
	}
	st := r.svc.State("node-a")
	if st.Restarting || !st.HasVerified || !st.LastVerified.BackAt.Equal(back) || st.Last.Result != store.BMCResetVerified {
		t.Fatalf("state %+v", st)
	}
	latest, _ := r.db.BMCResets().Latest(ctxT(t))
	if len(latest) != 1 || latest[0].Result != store.BMCResetVerified || !latest[0].BackAt.Equal(back) {
		t.Fatalf("row %+v", latest)
	}
	if c := r.svc.Counts()["node-a"]; c[store.BMCResetSent] != 1 || c[store.BMCResetVerified] != 1 {
		t.Fatalf("counts %+v", c)
	}
}

func TestVerifiedButLastResetTimeUnchanged(t *testing.T) {
	r := newRig(t)
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatal(err)
	}
	r.fleet.end(t, "node-a", fleet.RestartEnd{Outcome: fleet.RestartBack, At: t0.Add(time.Minute),
		State: backState(t0.Add(-24 * time.Hour))})
	e := r.audit.waitFor(t, ActionVerified, audit.ResultOK)
	if e.Params["last_reset_time_unchanged"] != true {
		t.Fatalf("verified %+v", e)
	}
	waitState(t, r, func(st State) bool { return st.Last.Detail == store.BMCResetUnchanged })
}

func waitState(t *testing.T, r *rig, cond func(State) bool) State {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		st := r.svc.State("node-a")
		if cond(st) {
			return st
		}
		if time.Now().After(deadline) {
			t.Fatalf("state never matched: %+v", st)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func TestWindowEndsWithoutTheBMC(t *testing.T) {
	cases := map[string]struct {
		end   fleet.RestartEnd
		class string
	}{
		"timeout":        {fleet.RestartEnd{Outcome: fleet.RestartTimeout, At: t0.Add(3 * time.Minute)}, "timeout"},
		"config changed": {fleet.RestartEnd{Outcome: fleet.RestartConfigChanged, At: t0.Add(time.Minute)}, "config_changed"},
		"pin mismatch": {fleet.RestartEnd{Outcome: fleet.RestartTimeout, At: t0.Add(time.Minute),
			State: fleet.ServerState{PinMismatch: true}}, "tls"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
				t.Fatal(err)
			}
			r.fleet.end(t, "node-a", tc.end)
			if e := r.audit.waitFor(t, ActionVerified, audit.ResultError); e.ErrorClass != tc.class {
				t.Fatalf("verified error %+v", e)
			}
			st := waitState(t, r, func(st State) bool { return st.Last.Result == store.BMCResetTimeout })
			if st.Restarting || st.Last.Class != tc.class || st.CooldownLeft == 0 {
				t.Fatalf("state %+v", st)
			}
			select {
			case <-r.back:
				t.Fatal("AfterBack ran for a BMC that did not come back")
			default:
			}
		})
	}
}

func TestAuditFailureFailsClosed(t *testing.T) {
	r := newRig(t)
	r.vnc.active = true
	r.audit.fail = true
	if err := r.svc.Request(ctxT(t), "node-a", admin); !errors.Is(err, ErrAudit) {
		t.Fatalf("err = %v", err)
	}
	if len(r.ev.all()) != 0 || r.opens != 0 {
		t.Fatalf("something happened without an audit row: %v", r.ev.all())
	}
	r.audit.fail = false
	if r.svc.CooldownLeft("node-a") != 0 {
		t.Fatal("the cooldown was not given back")
	}
}

func TestRefusalsBeforeAnyWork(t *testing.T) {
	r := newRig(t)
	pending := power.Operation{Action: power.ForceRestart, Phase: power.PhasePending}
	r.power.op = &pending
	if err := r.svc.Request(ctxT(t), "node-a", admin); !errors.Is(err, ErrPowerPending) {
		t.Fatalf("power pending: %v", err)
	}
	if e, _ := r.audit.find(ActionReset, audit.ResultDenied); e.ErrorClass != "power_pending" {
		t.Fatalf("denied %+v", e)
	}
	done := power.Operation{Action: power.ForceRestart, Phase: power.PhaseDone}
	r.power.op = &done
	if err := r.svc.Request(ctxT(t), "node-b", admin); !errors.Is(err, ErrNoOperator) {
		t.Fatalf("no operator: %v", err)
	}
	if err := r.svc.Request(ctxT(t), "nope", admin); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("unknown: %v", err)
	}
	if r.opens != 0 || r.svc.CooldownLeft("node-a") != 0 {
		t.Fatalf("opens %d cooldown %v", r.opens, r.svc.CooldownLeft("node-a"))
	}
}

func TestCooldownAfterAReset(t *testing.T) {
	r := newRig(t)
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatal(err)
	}
	r.fleet.end(t, "node-a", fleet.RestartEnd{Outcome: fleet.RestartBack, At: t0.Add(time.Minute), State: backState(time.Time{})})
	waitState(t, r, func(st State) bool { return !st.Restarting && st.HasVerified })
	r.clock.add(4 * time.Minute)
	var cd *CooldownError
	if err := r.svc.Request(ctxT(t), "node-a", admin); !errors.As(err, &cd) || cd.Left != 6*time.Minute {
		t.Fatalf("cooldown: %v", err)
	}
	if e, _ := r.audit.find(ActionReset, audit.ResultDenied); e.ErrorClass != "cooldown" {
		t.Fatalf("denied %+v", e)
	}
	r.clock.add(6 * time.Minute)
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatalf("after the cooldown: %v", err)
	}
}

func TestFailuresBeforeThePostGiveTheCooldownBack(t *testing.T) {
	cases := map[string]struct {
		openErr, fleetErr error
		want              error
		result, class     string
	}{
		"not offered": {openErr: fmt.Errorf("x: %w", bmc.ErrUnsupported), want: ErrUnsupported,
			result: audit.ResultDenied, class: "not_offered"},
		"login refused": {openErr: fmt.Errorf("x: %w", bmc.ErrAuth), want: ErrBMC, result: audit.ResultError, class: "auth"},
		"paused":        {fleetErr: fleet.ErrPaused, want: ErrBMC, result: audit.ResultError, class: "tls"},
		"gone":          {fleetErr: fleet.ErrUnknownServer, want: ErrNotConfigured, result: audit.ResultDenied, class: "not_configured"},
		"window open":   {fleetErr: fleet.ErrRestarting, want: ErrRestarting, result: audit.ResultDenied, class: "restarting"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.openErr, r.fleet.err = tc.openErr, tc.fleetErr
			if err := r.svc.Request(ctxT(t), "node-a", admin); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v", err)
			}
			if e, ok := r.audit.find(ActionReset, tc.result); !ok || e.ErrorClass != tc.class {
				t.Fatalf("audit %+v", e)
			}
			if resets, _ := r.resetter.counts(); resets != 0 || r.svc.CooldownLeft("node-a") != 0 {
				t.Fatalf("resets %d cooldown %v", resets, r.svc.CooldownLeft("node-a"))
			}
		})
	}
}

func TestPrivilegeRefusalIsStickyAndKeepsTheCooldown(t *testing.T) {
	r := newRig(t)
	r.resetter.resetErr = fmt.Errorf("%w: %w", bmc.ErrPrivilege, bmc.ErrAuth)
	if err := r.svc.Request(ctxT(t), "node-a", admin); !errors.Is(err, ErrPrivilege) {
		t.Fatalf("err = %v", err)
	}
	st := r.svc.State("node-a")
	if !st.PrivilegeRefused || st.Restarting || st.CooldownLeft != DefaultCooldown || st.Last.Result != store.BMCResetRefused {
		t.Fatalf("state %+v", st)
	}
	if _, open := r.fleet.window("node-a"); open {
		t.Fatal("the window stayed open for a refused reset")
	}
	if e, _ := r.audit.find(ActionReset, audit.ResultError); e.ErrorClass != "auth" {
		t.Fatalf("audit %+v", e)
	}
	latest, _ := r.db.BMCResets().Latest(ctxT(t))
	if len(latest) != 1 || latest[0].Result != store.BMCResetRefused || latest[0].ErrorClass != "auth" {
		t.Fatalf("row %+v", latest)
	}
	if err := r.svc.SetTargets(r.targets()); err != nil {
		t.Fatal(err)
	}
	if r.svc.State("node-a").PrivilegeRefused {
		t.Fatal("a hot apply must clear the sticky refusal")
	}
}

func TestPostOutcomes(t *testing.T) {
	r := newRig(t)
	r.resetter.resetErr = fmt.Errorf("x: %w", bmc.ErrTimeout)
	if err := r.svc.Request(ctxT(t), "node-a", admin); err != nil {
		t.Fatalf("a timed-out POST is treated as sent: %v", err)
	}
	if e, _ := r.audit.find(ActionReset, audit.ResultOK); e.Params["outcome"] != "sent_unconfirmed" {
		t.Fatalf("audit %+v", e)
	}
	if !r.svc.State("node-a").Restarting {
		t.Fatal("the window must stay open")
	}

	r2 := newRig(t)
	r2.resetter.resetErr = fmt.Errorf("x: %w", bmc.ErrBMC)
	if err := r2.svc.Request(ctxT(t), "node-a", admin); !errors.Is(err, ErrBMC) {
		t.Fatalf("err = %v", err)
	}
	if st := r2.svc.State("node-a"); st.Restarting || st.PrivilegeRefused || st.CooldownLeft == 0 {
		t.Fatalf("state %+v", st)
	}
}

func TestStartRearmsOpenWindowsAndClosesExpiredOnes(t *testing.T) {
	r := newRig(t)
	repo := r.db.BMCResets()
	row := func(id string, at time.Time, deadline time.Duration) store.BMCResetRow {
		return store.BMCResetRow{ServerID: id, CorrelationID: "c", RequestedAt: at, SentAt: at, RequestedBy: "bob",
			ResetType: ResetType, Result: store.BMCResetSent, DeadlineAt: at.Add(deadline)}
	}
	if _, err := repo.Insert(ctxT(t), row("node-a", t0.Add(-time.Minute), 3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Insert(ctxT(t), row("node-b", t0.Add(-time.Hour), 5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Insert(ctxT(t), row("gone", t0.Add(-time.Minute), 5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	r.fleet.err = nil
	svc := r.service(t)
	t.Cleanup(svc.Shutdown)
	r.fleet.windows["gone"] = fleet.RestartWindow{} // ExpectRestart refuses it (already open)
	if err := svc.Start(ctxT(t)); err != nil {
		t.Fatal(err)
	}
	w, ok := r.fleet.window("node-a")
	if !ok || !w.Since.Equal(t0.Add(-time.Minute)) || w.By != "bob" {
		t.Fatalf("not re-armed: %+v %v", w, ok)
	}
	st := svc.State("node-a")
	if !st.Restarting || st.CooldownLeft != 9*time.Minute {
		t.Fatalf("state %+v", st)
	}
	if st := svc.State("node-b"); st.Restarting || st.Last.Result != store.BMCResetTimeout || st.Last.Class != classUnobserved {
		t.Fatalf("expired row: %+v", st)
	}
	if st := svc.State("gone"); st.Last.Class != classConfigChanged {
		t.Fatalf("unwatchable row: %+v", st)
	}
	open, _ := repo.Open(ctxT(t))
	if len(open) != 1 || open[0].ServerID != "node-a" {
		t.Fatalf("open rows %+v", open)
	}
	r.fleet.end(t, "node-a", fleet.RestartEnd{Outcome: fleet.RestartBack, At: t0.Add(time.Minute), State: backState(time.Time{})})
	if e := r.audit.waitFor(t, ActionVerified, audit.ResultOK); e.Principal != "system" {
		t.Fatalf("verified %+v", e)
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("missing collaborators accepted")
	}
	r := newRig(t)
	dup := []Target{{ServerID: "a"}, {ServerID: "a"}}
	if _, err := New(Config{Targets: dup, Audit: r.audit, Store: r.db.BMCResets(), Fleet: r.fleet}); err == nil {
		t.Fatal("duplicate target accepted")
	}
	if err := r.svc.SetTargets(dup); err == nil {
		t.Fatal("duplicate target accepted by SetTargets")
	}
	svc, err := New(Config{Targets: []Target{{ServerID: "a"}}, Audit: r.audit, Store: r.db.BMCResets(), Fleet: r.fleet})
	if err != nil {
		t.Fatal(err)
	}
	if info := svc.Info("a"); !info.Configured || info.Operator || info.Deadline != 5*time.Minute {
		t.Fatalf("info %+v", info)
	}
	if svc.Info("zz").Configured {
		t.Fatal("unknown server configured")
	}
	if Deadline(config.KindIDRAC9) != 3*time.Minute || Deadline(config.KindIDRAC8) != 5*time.Minute ||
		Deadline(config.KindRedfish) != 5*time.Minute {
		t.Fatal("deadlines per kind")
	}
	svc.Shutdown()
	if err := svc.Request(ctxT(t), "a", admin); !errors.Is(err, ErrNoOperator) && !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("after shutdown: %v", err)
	}
}

func TestShutdownRefusesNewRequests(t *testing.T) {
	r := newRig(t)
	r.svc.Shutdown()
	if err := r.svc.Request(ctxT(t), "node-a", admin); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v", err)
	}
	if r.opens != 0 {
		t.Fatal("a stopped service logged in")
	}
}
