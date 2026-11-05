package ui

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/power"
)

// fakePower records requests and answers with err.
type fakePower struct {
	mu       sync.Mutex
	info     map[string]power.Info
	cooldown time.Duration
	last     map[string]power.Operation
	err      error
	calls    []string
	actors   []power.Actor
}

func (f *fakePower) Info(id string) power.Info { return f.info[id] }

func (f *fakePower) CooldownLeft(string) time.Duration { return f.cooldown }

func (f *fakePower) Last(id string) (power.Operation, bool) {
	op, ok := f.last[id]
	return op, ok
}

func (f *fakePower) Request(_ context.Context, id string, a power.Action, actor power.Actor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, id+":"+string(a))
	f.actors = append(f.actors, actor)
	return f.err
}

func (f *fakePower) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

var allResetTypes = []string{"On", "ForceOff", "ForceRestart", "GracefulRestart", "GracefulShutdown", "PushPowerButton", "Nmi", "PowerCycle"}

// powerServer is an iDRAC9-like server: every reset type, powered on, tagged critical.
func powerServer(now time.Time, id, name string, tags []string, resets []string) ServerView {
	return ServerView{ID: id, Name: name, Tags: tags,
		Snapshot:    bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: now, PowerState: bmc.PowerOn, Health: bmc.HealthOK}),
		HasSnapshot: true, LastSuccess: now,
		Capabilities: bmc.NewCapabilities(bmc.CapabilityParams{ResetTypes: resets}), HasCapabilities: true}
}

type powerEnv struct {
	h  *harness
	c  *client
	fp *fakePower
}

// newPowerEnv signs in a user with role; servers: "edge" (critical, impact, every reset
// type), "store" (self_host, no PowerCycle), "plain" (no operator login).
func newPowerEnv(t *testing.T, role authz.Role) *powerEnv {
	t.Helper()
	fp := &fakePower{last: map[string]power.Operation{}, info: map[string]power.Info{
		"edge":  {Configured: true, Operator: true, Impact: []string{"Network gateway: all internet access drops", "<b>VPN</b> ends"}},
		"store": {Configured: true, Operator: true, SelfHost: true},
		"plain": {Configured: true},
	}}
	h := newHarness(t, func(d *Deps) { d.Power = fp })
	now := h.clock.Now().Add(time.Hour) // newer than any login-time clock advance
	h.fleet.servers = []ServerView{
		powerServer(now, "edge", "Edge router", []string{"critical"}, allResetTypes),
		powerServer(now, "store", "Storage node", nil, []string{"On", "ForceOff", "ForceRestart", "GracefulShutdown"}),
		powerServer(now, "plain", "Plain box", nil, allResetTypes),
	}
	secret := h.addUser("pat", role, true)
	c := h.client("192.0.2.40")
	c.login("pat", secret)
	return &powerEnv{h: h, c: c, fp: fp}
}

func (e *powerEnv) post(path string, fields url.Values) *httpResult {
	e.h.t.Helper()
	return result(e.c.submit(path, path, fields))
}

func TestPowerNotWiredKeepsPlaceholders(t *testing.T) {
	t.Parallel()
	_, c := signedInOperator(t)
	result(c.get("/servers/r730xd")).status(t, http.StatusOK).
		contains(t, notSetUp).lacks(t, "Not yet:")
	result(c.get("/servers/r730xd/power/on")).status(t, http.StatusNotFound)
	result(c.get("/servers/r730xd")).contains(t, "Power control: not set up")
}

func TestPowerMenuItems(t *testing.T) {
	t.Parallel()
	e := newPowerEnv(t, authz.RoleOperator)
	body := result(e.c.get("/servers/edge")).status(t, http.StatusOK).
		contains(t, `href="/servers/edge/power/graceful-shutdown"`, `href="/servers/edge/power/graceful-restart"`,
			"The server is already on.", "Needs the admin role.").
		lacks(t, `href="/servers/edge/power/on"`, `href="/servers/edge/power/force-off"`, "Not yet:").rec.Body.String()
	if !strings.Contains(between(body, "<span>Power on</span>", "</li>"), "already on") {
		t.Fatalf("power on reason:\n%s", body)
	}
	result(e.c.get("/servers/plain")).contains(t, "Needs an operator BMC account (credentials.operator in the config).").
		lacks(t, `href="/servers/plain/power/`)
	result(e.c.get("/servers/edge")).contains(t, `class="hmenus"`, `id="now-h"`)
}

func TestPowerMenuItemsAdmin(t *testing.T) {
	t.Parallel()
	e := newPowerEnv(t, authz.RoleAdmin)
	result(e.c.get("/servers/store")).status(t, http.StatusOK).
		contains(t, `href="/servers/store/power/force-off"`, `href="/servers/store/power/force-restart"`,
			"Not offered by this BMC.", "mi mi-danger").
		lacks(t, `href="/servers/store/power/power-cycle"`, `href="/servers/store/power/graceful-restart"`)
	e.fp.cooldown = 42 * time.Second
	result(e.c.get("/servers/store")).contains(t, "Another power action ran a moment ago. Try again in 42 seconds.").
		lacks(t, `href="/servers/store/power/`)
	r := result(e.c.get("/servers/store/power/force-off")).status(t, http.StatusTooManyRequests)
	if r.rec.Header().Get("Retry-After") != "42" {
		t.Fatalf("Retry-After %q", r.rec.Header().Get("Retry-After"))
	}
}

func TestPowerConfirmSafeAction(t *testing.T) {
	t.Parallel()
	e := newPowerEnv(t, authz.RoleOperator)
	result(e.c.get("/servers/store/power/graceful-shutdown")).status(t, http.StatusOK).
		contains(t, "<h1>Graceful shutdown Storage node?</h1>", "Safe action", "What happens",
			"Asks the operating system to shut down", "Storage node stays off until someone powers it on.",
			`href="/servers/store" autofocus>Cancel</a>`, "Graceful shutdown Storage node</button>",
			"This server runs oob-manager; the console will go offline until it boots.",
			"Powering it on again needs another way in", "Type <code>Storage node</code> to confirm",
			"This server runs oob-manager.", "ResetType GracefulShutdown", "Step-up fresh until").
		lacks(t, "What goes down")
	// A forced action is refused to the operator before any form is shown.
	result(e.c.get("/servers/store/power/force-off")).status(t, http.StatusForbidden).contains(t, "Needs the admin role.")
	if !e.h.audit.denied("power.force_off", "forbidden") {
		t.Fatalf("forbidden not audited: %+v", e.h.audit.entries)
	}
	result(e.c.get("/servers/store/power/nmi")).status(t, http.StatusNotFound)
	result(e.c.get("/servers/nope/power/on")).status(t, http.StatusNotFound)
}

func TestPowerConfirmCriticalAndImpact(t *testing.T) {
	t.Parallel()
	e := newPowerEnv(t, authz.RoleAdmin)
	result(e.c.get("/servers/edge/power/power-cycle")).status(t, http.StatusOK).
		contains(t, "Forced action", "Edge router is tagged critical: other systems depend on it.", "What goes down",
			"Network gateway: all internet access drops", "&lt;b&gt;VPN&lt;/b&gt; ends", "Type <code>Edge router</code>",
			"Forced actions skip the operating system.", "Edge router starts again by itself").
		lacks(t, "<b>VPN</b>", "runs oob-manager")
	// Graceful restart of a critical server needs the typed name too.
	result(e.c.get("/servers/edge/power/graceful-restart")).contains(t, "Edge router is a critical server.", `name="typed"`)
}

func TestPowerForcedNeedsTypedName(t *testing.T) {
	t.Parallel()
	e := newPowerEnv(t, authz.RoleAdmin)
	path := "/servers/edge/power/force-off"
	e.post(path, url.Values{"confirm": {"yes"}, "typed": {"edge router"}}).
		status(t, http.StatusUnprocessableEntity).contains(t, "does not match", `aria-invalid="true"`)
	if !e.h.audit.denied("power.force_off", "confirm_mismatch") {
		t.Fatalf("mismatch not audited: %+v", e.h.audit.entries)
	}
	if len(e.fp.requests()) != 0 {
		t.Fatal("forced action ran without the typed name")
	}
	e.post(path, url.Values{"confirm": {"yes"}, "typed": {"Edge router"}}).
		status(t, http.StatusSeeOther).location(t, "/servers/edge#now-h")
	if got := e.fp.requests(); len(got) != 1 || got[0] != "edge:force-off" {
		t.Fatalf("requests %v", got)
	}
	if a := e.fp.actors[0]; a.Username != "pat" || a.Role != "admin" || a.SrcIP != "192.0.2.40" {
		t.Fatalf("actor %+v", a)
	}
}

func TestPowerUnconfirmedAndCSRF(t *testing.T) {
	t.Parallel()
	e := newPowerEnv(t, authz.RoleOperator)
	path := "/servers/store/power/graceful-shutdown"
	e.post(path, url.Values{}).status(t, http.StatusSeeOther).location(t, path)
	if !e.h.audit.denied("power.graceful_shutdown", "unconfirmed") {
		t.Fatalf("unconfirmed not audited: %+v", e.h.audit.entries)
	}
	result(e.c.do(http.MethodPost, path, url.Values{csrfField: {"forged"}, "confirm": {"yes"}, "typed": {"Storage node"}})).
		status(t, http.StatusForbidden)
	if !e.h.audit.denied("power.graceful_shutdown", "csrf") {
		t.Fatalf("csrf not audited: %+v", e.h.audit.entries)
	}
	// A Settings form token is not a power form token.
	result(e.c.do(http.MethodPost, path, url.Values{csrfField: {e.h.csrfToken(e.c)}, "confirm": {"yes"}})).
		status(t, http.StatusForbidden)
	if len(e.fp.requests()) != 0 {
		t.Fatal("request sent")
	}
}

func TestPowerDeniedWithoutStepUp(t *testing.T) {
	t.Parallel()
	e := newPowerEnv(t, authz.RoleOperator)
	path := "/servers/edge/power/graceful-restart"
	e.h.clock.Advance(6 * time.Minute)
	result(e.c.get(path)).status(t, http.StatusOK).
		contains(t, "<strong>Graceful restart · Edge router</strong> needs a fresh code", `autocomplete="one-time-code"`)
	e.post(path, url.Values{"confirm": {"yes"}, "typed": {"Edge router"}}).
		status(t, http.StatusUnauthorized).contains(t, "Enter the 6-digit code")
	if !e.h.audit.denied("power.graceful_restart", "stepup_required") {
		t.Fatalf("missing step-up not audited: %+v", e.h.audit.entries)
	}
	e.post(path, url.Values{"confirm": {"yes"}, "typed": {"Edge router"}, "code": {"000000"}}).
		status(t, http.StatusUnauthorized).contains(t, msgBadCode)
	if len(e.fp.requests()) != 0 {
		t.Fatal("request sent without a step-up")
	}
}

func TestPowerStepUpInlineCode(t *testing.T) {
	t.Parallel()
	fp := &fakePower{last: map[string]power.Operation{}, info: map[string]power.Info{"edge": {Configured: true, Operator: true}}}
	h := newHarness(t, func(d *Deps) { d.Power = fp })
	h.fleet.servers = []ServerView{powerServer(h.clock.Now().Add(time.Hour), "edge", "Edge router", nil, allResetTypes)}
	secret := h.addUser("pat", authz.RoleOperator, true)
	c := h.client("192.0.2.40")
	c.login("pat", secret)
	h.clock.Advance(6 * time.Minute)
	path := "/servers/edge/power/graceful-restart"
	result(c.submit(path, path, url.Values{"confirm": {"yes"}, "code": {h.code(secret)}})).
		status(t, http.StatusSeeOther).location(t, "/servers/edge#now-h")
	if got := fp.requests(); len(got) != 1 {
		t.Fatalf("requests %v", got)
	}
}

func TestPowerServiceErrors(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		err    error
		status int
		msg    string
	}{
		{&power.CooldownError{Left: 30 * time.Second}, http.StatusTooManyRequests, "Try again in 30 seconds."},
		{power.ErrAudit, http.StatusServiceUnavailable, "nothing was sent"},
		{fmt.Errorf("%w: bmc", power.ErrBMC), http.StatusBadGateway, "The BMC did not confirm the request."},
		{power.ErrState, http.StatusConflict, "no longer applies"},
		{power.ErrUnsupported, http.StatusConflict, "does not offer"},
		{power.ErrNoOperator, http.StatusConflict, "not set up"},
	} {
		t.Run(fmt.Sprint(c.status, c.msg), func(t *testing.T) {
			e := newPowerEnv(t, authz.RoleOperator)
			e.fp.err = c.err
			path := "/servers/edge/power/graceful-restart"
			e.post(path, url.Values{"confirm": {"yes"}, "typed": {"Edge router"}}).status(t, c.status).contains(t, c.msg)
		})
	}
}

func TestPowerRateLimit(t *testing.T) {
	t.Parallel()
	fp := &fakePower{last: map[string]power.Operation{}, info: map[string]power.Info{"edge": {Configured: true, Operator: true}}}
	h := newHarness(t, func(d *Deps) {
		d.Power = fp
		d.ChangesPerUser = RateLimit{Events: 1, Per: time.Minute}
	})
	h.fleet.servers = []ServerView{powerServer(h.clock.Now().Add(time.Hour), "edge", "Edge router", nil, allResetTypes)}
	secret := h.addUser("pat", authz.RoleOperator, true)
	c := h.client("192.0.2.40")
	c.login("pat", secret)
	path := "/servers/edge/power/graceful-restart"
	result(c.submit(path, path, url.Values{"confirm": {"yes"}})).status(t, http.StatusSeeOther)
	result(c.submit(path, path, url.Values{"confirm": {"yes"}})).status(t, http.StatusTooManyRequests).
		contains(t, "Too many power requests")
	if !h.audit.denied("power.graceful_restart", "rate_limited") {
		t.Fatalf("rate limit not audited: %+v", h.audit.entries)
	}
}

func TestPowerStatusOnOperations(t *testing.T) {
	t.Parallel()
	e := newPowerEnv(t, authz.RoleOperator)
	at := e.h.clock.Now()
	for _, c := range []struct {
		op   power.Operation
		want string
	}{
		{power.Operation{Action: power.ForceOff, By: "boss", RequestedAt: at, Phase: power.PhaseSending}, "logging in to the BMC"},
		{power.Operation{Action: power.ForceOff, By: "boss", RequestedAt: at, Phase: power.PhasePending}, "Waiting for the server to report Off"},
		{power.Operation{Action: power.On, By: "boss", RequestedAt: at, FinishedAt: at, Phase: power.PhaseDone, State: bmc.PowerOn}, "Power on done: the server reported On"},
		{power.Operation{Action: power.ForceRestart, By: "boss", Phase: power.PhaseUnconfirmed}, "reported On the whole time"},
		{power.Operation{Action: power.GracefulShutdown, By: "boss", Phase: power.PhaseFailed, Class: "not_confirmed"}, "did not report Off in time"},
		{power.Operation{Action: power.GracefulRestart, By: "boss", Phase: power.PhaseFailed, Class: "superseded"}, "a newer power action replaced it"},
		{power.Operation{Action: power.On, By: "boss", Phase: power.PhaseFailed, Class: "stopped"}, "oob-manager stopped"},
		{power.Operation{Action: power.On, By: "boss", Phase: power.PhaseFailed, Class: "unsupported"}, "does not offer it"},
		{power.Operation{Action: power.On, By: "boss", Phase: power.PhaseFailed, Class: "state"}, "did not apply"},
		{power.Operation{Action: power.On, By: "boss", Phase: power.PhaseFailed, Class: "auth"}, "refused the operator login"},
		{power.Operation{Action: power.On, By: "boss", Phase: power.PhaseFailed, Class: "timeout"}, "did not answer in time"},
		{power.Operation{Action: power.On, By: "boss", Phase: power.PhaseFailed, Class: "unreachable"}, "could not be reached"},
		{power.Operation{Action: power.On, By: "boss", Phase: power.PhaseFailed, Class: "bmc"}, "returned an error (bmc)"},
	} {
		e.fp.last["edge"] = c.op
		result(e.c.get("/servers/edge")).contains(t, `id="pw-last" role="status"`, c.want)
	}
}

func TestPowerStateFromFinishedOperation(t *testing.T) {
	t.Parallel()
	e := newPowerEnv(t, authz.RoleOperator)
	// The snapshot (one hour ahead) says On; an operation finished later says Off.
	later := e.h.clock.Now().Add(2 * time.Hour)
	e.fp.last["edge"] = power.Operation{Action: power.ForceOff, Phase: power.PhaseDone, State: bmc.PowerOff, FinishedAt: later}
	result(e.c.get("/servers/edge")).contains(t, `href="/servers/edge/power/on"`, "The server is off.")
}

func TestPowerViewerSeesRoleReason(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t, func(d *Deps) {
		d.Power = &fakePower{info: map[string]power.Info{"r730xd": {Configured: true, Operator: true}}}
	})
	// A viewer is told which role acts and what the BMC supports, without dead buttons.
	result(c.get("/servers/r730xd")).contains(t, "Actions need the operator role.").
		lacks(t, "btn-disabled", "mi-off", "Not offered by this BMC.")
	result(c.get("/servers/r730xd/power/on")).status(t, http.StatusConflict)
	result(c.get("/servers/r730xd/inventory")).status(t, http.StatusOK)
}

// denied reports whether a denied entry for action with class exists (for the server
// named in the path; the UI always sets it).
func (f *fakeAudit) denied(action, class string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.entries {
		if e.Action == action && e.Result == audit.ResultDenied && e.ErrorClass == class {
			return true
		}
	}
	return false
}

func TestStepUpPageNamesPowerAction(t *testing.T) {
	t.Parallel()
	e := newPowerEnv(t, authz.RoleAdmin)
	e.h.clock.Advance(6 * time.Minute)
	result(e.c.get("/stepup?next="+url.QueryEscape("/servers/edge/power/force-off"))).contains(t, "Force off · Edge router")
	result(e.c.get("/stepup?next="+url.QueryEscape("/servers/edge/power/nmi"))).contains(t, "Make changes").lacks(t, "· Edge router")
	result(e.c.get("/stepup?next="+url.QueryEscape("/servers/nope/power/on"))).contains(t, "Make changes")
}
