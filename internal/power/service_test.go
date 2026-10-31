package power

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
)

func TestActionTable(t *testing.T) {
	want := map[Action]struct {
		rt     string
		az     authz.Action
		forced bool
	}{
		On:               {"On", authz.PowerOn, false},
		GracefulShutdown: {"GracefulShutdown", authz.PowerGracefulStop, false},
		GracefulRestart:  {"GracefulRestart", authz.PowerGracefulRestart, false},
		ForceOff:         {"ForceOff", authz.PowerForceOff, true},
		PowerCycle:       {"PowerCycle", authz.PowerCycle, true},
		ForceRestart:     {"ForceRestart", authz.PowerForceRestart, true},
	}
	if len(Actions()) != len(want) {
		t.Fatalf("actions %v", Actions())
	}
	for _, a := range Actions() {
		w := want[a]
		if a.ResetType() != w.rt || a.Authz() != w.az || a.Forced() != w.forced || a.Label() == "" || a.Effect() == "" {
			t.Errorf("%s: %q %q %v", a, a.ResetType(), a.Authz(), a.Forced())
		}
		if p, ok := ParseAction(string(a)); !ok || p != a {
			t.Errorf("parse %s", a)
		}
		// Forced actions need the admin role; safe ones the operator role.
		op := authz.Principal{Kind: authz.KindSession, Role: authz.RoleOperator}
		if authz.Allowed(op, a.Authz()) == a.Forced() || !authz.RequiresStepUp(a.Authz()) {
			t.Errorf("%s: authz rule mismatch", a)
		}
	}
	for _, bad := range []string{"", "On", "force_off", "nmi", "push-power-button", "on "} {
		if _, ok := ParseAction(bad); ok {
			t.Errorf("parsed %q", bad)
		}
	}
	if Action("x").ResetType() != "" || Action("x").Label() != "" {
		t.Error("unknown action has a spec")
	}
	if On.TakesDown() || !ForceOff.TakesDown() || !PowerCycle.Restarts() || ForceOff.Restarts() {
		t.Error("TakesDown/Restarts")
	}
}

func TestApplies(t *testing.T) {
	cases := []struct {
		a    Action
		s    bmc.PowerState
		want bool
	}{
		{On, bmc.PowerOff, true}, {On, bmc.PowerOn, false}, {On, bmc.PowerPoweringOn, false}, {On, bmc.PowerUnknown, true},
		{ForceOff, bmc.PowerOn, true}, {ForceOff, bmc.PowerOff, false}, {GracefulRestart, bmc.PowerPoweringOff, false},
		{PowerCycle, bmc.PowerUnknown, true},
	}
	for _, c := range cases {
		if got := c.a.Applies(c.s); got != c.want {
			t.Errorf("%s in %s: %v", c.a, c.s, got)
		}
	}
}

func TestForceOffVerifiedAndAudited(t *testing.T) {
	ctl := &fakeCtl{allowed: allResets, initial: bmc.PowerOn, states: []bmc.PowerState{bmc.PowerPoweringOff, bmc.PowerOff}}
	h := newHarness(t, ctl)
	if err := h.svc.Request(context.Background(), "srv", ForceOff, actor); err != nil {
		t.Fatal(err)
	}
	op := waitFinal(t, h.svc, "srv")
	if op.Phase != PhaseDone || op.State != bmc.PowerOff || op.By != "alice" || op.Action != ForceOff || op.FinishedAt.IsZero() {
		t.Fatalf("op %+v", op)
	}
	resets, closed := ctl.snapshot()
	if !slices.Equal(resets, []string{"ForceOff"}) || closed != 1 {
		t.Fatalf("resets %v closed %d", resets, closed)
	}
	e := waitAudits(t, h.aud, 2)
	if e[0].Result != audit.ResultStarted || e[1].Result != audit.ResultOK || e[0].CorrelationID == "" ||
		e[0].CorrelationID != e[1].CorrelationID {
		t.Fatalf("audit %+v", e)
	}
	for _, x := range e {
		if x.Action != "power.force_off" || x.ServerID != "srv" || x.Principal != "alice" || x.SrcIP != "192.0.2.70" ||
			x.Params["reset_type"] != "ForceOff" {
			t.Errorf("entry %+v", x)
		}
	}
	if e[1].Params["outcome"] != "verified" || e[1].Params["power_state"] != "Off" {
		t.Errorf("final params %+v", e[1].Params)
	}
}

func TestCooldown(t *testing.T) {
	ctl := &fakeCtl{allowed: allResets, initial: bmc.PowerOff, states: []bmc.PowerState{bmc.PowerOn}}
	h := newHarness(t, ctl)
	if err := h.svc.Request(context.Background(), "srv", On, actor); err != nil {
		t.Fatal(err)
	}
	waitFinal(t, h.svc, "srv")
	h.clock.advance(20 * time.Second)
	err := h.svc.Request(context.Background(), "srv", ForceOff, actor)
	var cd *CooldownError
	if !errors.As(err, &cd) || !errors.Is(err, ErrCoolingDown) || cd.Left != 40*time.Second || err.Error() == "" {
		t.Fatalf("err = %v", err)
	}
	if left := h.svc.CooldownLeft("srv"); left != 40*time.Second {
		t.Fatalf("CooldownLeft %v", left)
	}
	e := waitAudits(t, h.aud, 3)
	if last := e[len(e)-1]; last.Result != audit.ResultDenied || last.ErrorClass != "cooldown" || last.Action != "power.force_off" {
		t.Fatalf("cooldown not audited: %+v", last)
	}
	if h.openCount() != 1 {
		t.Fatal("the BMC was contacted during the cooldown")
	}
	h.clock.advance(41 * time.Second)
	if h.svc.CooldownLeft("srv") != 0 || h.svc.CooldownLeft("other") != 0 {
		t.Fatal("cooldown did not end")
	}
	if err := h.svc.Request(context.Background(), "srv", ForceOff, actor); err != nil {
		t.Fatalf("after cooldown: %v", err)
	}
}

func TestRefusalsBeforeTheBMC(t *testing.T) {
	ctl := &fakeCtl{allowed: []string{"On", "ForceOff"}, initial: bmc.PowerOn}
	h := newHarness(t, ctl)
	cases := []struct {
		id    string
		a     Action
		err   error
		class string
	}{
		{"nope", ForceOff, ErrNotConfigured, "not_configured"},
		{"noop", ForceOff, ErrNoOperator, "no_operator"},
		{"srv", PowerCycle, ErrUnsupported, "unsupported"},
		{"srv", On, ErrState, "state"},
		{"srv", Action("bogus"), ErrUnsupported, "unsupported"},
	}
	for _, c := range cases {
		if err := h.svc.Request(context.Background(), c.id, c.a, actor); !errors.Is(err, c.err) {
			t.Errorf("%s %s: err = %v", c.id, c.a, err)
		}
		e := h.aud.all()
		if last := e[len(e)-1]; last.ErrorClass != c.class || (last.Result != audit.ResultDenied && last.Result != audit.ResultError) {
			t.Errorf("%s %s: audit %+v", c.id, c.a, last)
		}
		// A refusal before anything was sent does not start the cooldown.
		if h.svc.CooldownLeft("srv") != 0 {
			t.Errorf("%s %s: cooldown started", c.id, c.a)
		}
	}
	if resets, closed := ctl.snapshot(); len(resets) != 0 || closed != h.openCount() {
		t.Fatalf("resets %v, closed %d of %d", resets, closed, h.openCount())
	}
	if i := h.svc.Info("srv"); !i.Configured || !i.Operator {
		t.Errorf("srv info %+v", i)
	}
	if i := h.svc.Info("noop"); !i.Configured || i.Operator || !i.SelfHost || i.Impact[0] != "Gateway" {
		t.Errorf("noop info %+v", i)
	}
	if i := h.svc.Info("nope"); i.Configured {
		t.Errorf("unknown info %+v", i)
	}
}

func TestAuditFailsClosed(t *testing.T) {
	ctl := &fakeCtl{allowed: allResets, initial: bmc.PowerOn}
	h := newHarness(t, ctl)
	h.aud.fail = true
	if err := h.svc.Request(context.Background(), "srv", ForceOff, actor); !errors.Is(err, ErrAudit) {
		t.Fatalf("err = %v", err)
	}
	if h.openCount() != 0 || h.svc.CooldownLeft("srv") != 0 {
		t.Fatal("the BMC was contacted without an audit record")
	}
}

func TestBMCFailures(t *testing.T) {
	for _, c := range []struct {
		name  string
		ctl   *fakeCtl
		open  error
		class string
	}{
		{"reset refused", &fakeCtl{allowed: allResets, initial: bmc.PowerOn, resetErr: fmt.Errorf("x: %w", bmc.ErrBMC)}, nil, "bmc"},
		{"state unreadable", &fakeCtl{allowed: allResets, stateErr: fmt.Errorf("x: %w", bmc.ErrTimeout)}, nil, "timeout"},
		{"login refused", nil, fmt.Errorf("x: %w", bmc.ErrAuth), "auth"},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, c.ctl, func(cfg *Config) {
				if c.open != nil {
					cfg.Targets[0].Open = func(context.Context) (Controller, error) { return nil, c.open }
				}
			})
			err := h.svc.Request(context.Background(), "srv", ForceOff, actor)
			if !errors.Is(err, ErrBMC) {
				t.Fatalf("err = %v", err)
			}
			e := h.aud.all()
			last := e[len(e)-1]
			if last.Result != audit.ResultError || last.ErrorClass != c.class {
				t.Fatalf("audit %+v", last)
			}
			op, ok := h.svc.Last("srv")
			if !ok || op.Phase != PhaseFailed || op.Class != c.class {
				t.Fatalf("op %+v", op)
			}
			// The reset may have reached the BMC only in the first case: that one keeps the cooldown.
			if cool := h.svc.CooldownLeft("srv") > 0; cool != (c.name == "reset refused") {
				t.Fatalf("cooldown %v", h.svc.CooldownLeft("srv"))
			}
		})
	}
}

func TestVerificationOutcomes(t *testing.T) {
	for _, c := range []struct {
		name    string
		a       Action
		initial bmc.PowerState
		states  []bmc.PowerState
		phase   Phase
		outcome string
		class   string
	}{
		{"restart seen", PowerCycle, bmc.PowerOn, []bmc.PowerState{bmc.PowerOn, bmc.PowerOff, bmc.PowerPoweringOn, bmc.PowerOn}, PhaseDone, "verified", ""},
		{"restart not seen", ForceRestart, bmc.PowerOn, []bmc.PowerState{bmc.PowerOn}, PhaseUnconfirmed, "unconfirmed", ""},
		{"restart stuck off", GracefulRestart, bmc.PowerOn, []bmc.PowerState{bmc.PowerOff}, PhaseFailed, "", "not_confirmed"},
		{"shutdown ignored", GracefulShutdown, bmc.PowerOn, []bmc.PowerState{bmc.PowerOn}, PhaseFailed, "", "not_confirmed"},
		{"on", On, bmc.PowerOff, []bmc.PowerState{bmc.PowerPoweringOn, bmc.PowerOn}, PhaseDone, "verified", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, &fakeCtl{allowed: allResets, initial: c.initial, states: c.states})
			if err := h.svc.Request(context.Background(), "srv", c.a, actor); err != nil {
				t.Fatal(err)
			}
			op := waitFinal(t, h.svc, "srv")
			e := waitAudits(t, h.aud, 2)
			last := e[len(e)-1]
			if op.Phase != c.phase || op.Class != c.class || last.ErrorClass != c.class {
				t.Fatalf("op %+v audit %+v", op, last)
			}
			if c.outcome != "" && (last.Result != audit.ResultOK || last.Params["outcome"] != c.outcome) {
				t.Fatalf("audit %+v", last)
			}
			if c.outcome == "" && last.Result != audit.ResultError {
				t.Fatalf("audit %+v", last)
			}
		})
	}
}

func TestSupersedeAndShutdown(t *testing.T) {
	ctl := &fakeCtl{allowed: allResets, initial: bmc.PowerOn, states: []bmc.PowerState{bmc.PowerOn}}
	h := newHarness(t, ctl, func(c *Config) { c.GracefulTimeout = time.Hour })
	if err := h.svc.Request(context.Background(), "srv", GracefulShutdown, actor); err != nil {
		t.Fatal(err)
	}
	if op, _ := h.svc.Last("srv"); op.Phase != PhasePending {
		t.Fatalf("op %+v", op)
	}
	h.clock.advance(time.Minute)
	if err := h.svc.Request(context.Background(), "srv", ForceOff, actor); err != nil {
		t.Fatal(err)
	}
	e := waitAudits(t, h.aud, 3)
	if e[2].ErrorClass != "superseded" || e[2].Action != "power.graceful_shutdown" {
		// the superseded verification and the new request race; find it
		found := false
		for _, x := range e {
			found = found || x.ErrorClass == "superseded"
		}
		if !found {
			t.Fatalf("no superseded record: %+v", e)
		}
	}
	h.svc.Shutdown()
	all := waitAudits(t, h.aud, 4)
	stopped := false
	for _, x := range all {
		stopped = stopped || x.ErrorClass == "stopped"
	}
	if !stopped {
		t.Fatalf("shutdown did not record the stopped verification: %+v", all)
	}
	if err := h.svc.Request(context.Background(), "srv", On, actor); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("request after shutdown: %v", err)
	}
	if _, closed := ctl.snapshot(); closed != 2 {
		t.Fatalf("closed %d", closed)
	}
}

func TestNewValidates(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("no audit accepted")
	}
	if _, err := New(Config{Audit: &fakeAudit{}, Targets: []Target{{ServerID: "a"}, {ServerID: "a"}}}); err == nil {
		t.Fatal("duplicate target accepted")
	}
	s, err := New(Config{Audit: &fakeAudit{}})
	if err != nil {
		t.Fatal(err)
	}
	if s.cfg.Cooldown != DefaultCooldown || s.cfg.PollEvery != DefaultPollEvery {
		t.Fatalf("defaults %+v", s.cfg)
	}
	s.Shutdown()
	s.Shutdown() // idempotent
}
