package ui

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/bmcreset"
	"oob-manager/internal/console"
	"oob-manager/internal/power"
	"oob-manager/internal/store"
)

type fakeBMC struct {
	mu     sync.Mutex
	info   map[string]bmcreset.Info
	state  map[string]bmcreset.State
	err    error
	calls  []string
	actors []bmcreset.Actor
}

func (f *fakeBMC) Info(id string) bmcreset.Info { return f.info[id] }

func (f *fakeBMC) State(id string) bmcreset.State {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state[id]
}

func (f *fakeBMC) Request(_ context.Context, id string, a bmcreset.Actor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, id)
	f.actors = append(f.actors, a)
	return f.err
}

func (f *fakeBMC) set(id string, st bmcreset.State) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state[id] = st
}

func (f *fakeBMC) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// bmcServer is an iDRAC-like server that offers Manager.Reset (lastReset zero: iDRAC8).
func bmcServer(now time.Time, id, name string, offered bool, lastReset time.Time) ServerView {
	v := powerServer(now, id, name, nil, allResetTypes)
	v.Capabilities = bmc.NewCapabilities(bmc.CapabilityParams{ResetTypes: allResetTypes, Flags: bmc.CapabilityFlags{
		BMCModel: "14G Monolithic", BMCFirmware: "7.00.00.182", ManagerReset: offered, BMCLastReset: lastReset}})
	return v
}

type bmcEnv struct {
	h   *harness
	c   *client
	fb  *fakeBMC
	fp  *fakePower
	con *fakeConsoles
	now time.Time
}

// newBMCEnv: "edge" (iDRAC9-like, offered, self host), "old" (not offered), "plain" (no
// operator login), "fresh" (never probed).
func newBMCEnv(t *testing.T, role authz.Role, tweak ...func(*Deps)) *bmcEnv {
	t.Helper()
	fb := &fakeBMC{state: map[string]bmcreset.State{}, info: map[string]bmcreset.Info{
		"edge":  {Configured: true, Operator: true, SelfHost: true, Deadline: 3 * time.Minute},
		"old":   {Configured: true, Operator: true, Deadline: 5 * time.Minute},
		"plain": {Configured: true, Deadline: 5 * time.Minute},
		"fresh": {Configured: true, Operator: true, Deadline: 5 * time.Minute},
	}}
	fp := &fakePower{last: map[string]power.Operation{}, info: map[string]power.Info{"edge": {Configured: true, Operator: true}}}
	con := newFakeConsoles()
	h := newHarness(t, append([]func(*Deps){func(d *Deps) { d.BMCReset, d.Power, d.Consoles = fb, fp, con }}, tweak...)...)
	now := h.clock.Now().Add(time.Hour)
	fresh := bmcServer(now, "fresh", "Fresh box", true, time.Time{})
	fresh.HasCapabilities = false
	h.fleet.servers = []ServerView{
		bmcServer(now, "edge", "Edge router", true, time.Date(2026, 4, 3, 5, 18, 54, 0, time.UTC)),
		bmcServer(now, "old", "Old box", false, time.Time{}),
		bmcServer(now, "plain", "Plain box", true, time.Time{}),
		fresh,
	}
	secret := h.addUser("pat", role, true)
	c := h.client("192.0.2.40")
	c.login("pat", secret)
	return &bmcEnv{h: h, c: c, fb: fb, fp: fp, con: con, now: now}
}

func (e *bmcEnv) post(fields url.Values) *httpResult {
	e.h.t.Helper()
	return result(e.c.submit("/servers/edge/bmc/reset", "/servers/edge/bmc/reset", fields))
}

func TestBMCPanelReasonsAndButton(t *testing.T) {
	t.Parallel()
	e := newBMCEnv(t, authz.RoleAdmin)
	result(e.c.get("/servers/edge")).status(t, http.StatusOK).
		contains(t, "<dt>Last BMC restart</dt>", "14G Monolithic", "7.00.00.182", "(reported by the BMC)",
			`href="/servers/edge/bmc/reset"`, "Restart BMC…")
	result(e.c.get("/servers/old")).contains(t, "Not offered by this BMC.").lacks(t, `href="/servers/old/bmc/reset"`)
	result(e.c.get("/servers/plain")).contains(t, "Needs an operator BMC account.")
	result(e.c.get("/servers/fresh")).contains(t, "Not determined yet")
	for _, c := range []struct {
		st   bmcreset.State
		op   *power.Operation
		want string
	}{
		{st: bmcreset.State{CooldownLeft: 9*time.Minute + time.Second}, want: "Cooling down for 10 min."},
		{st: bmcreset.State{PrivilegeRefused: true}, want: "The operator account lacks the privilege (last attempt)."},
		{st: bmcreset.State{Restarting: true, Window: bmcreset.Record{RequestedAt: e.now, By: "bob", Deadline: e.now.Add(3 * time.Minute)}},
			want: "BMC is restarting (back by"},
		{op: &power.Operation{Action: power.ForceOff, Phase: power.PhasePending}, want: "A power action is still being verified."},
		{st: bmcreset.State{InFlight: true, CooldownLeft: 10 * time.Minute}, want: "The BMC is restarting; power actions wait"},
	} {
		e.fb.set("edge", c.st)
		delete(e.fp.last, "edge")
		if c.op != nil {
			e.fp.last["edge"] = *c.op
		}
		result(e.c.get("/servers/edge")).contains(t, c.want).lacks(t, `href="/servers/edge/bmc/reset"`)
	}
}

func TestBMCPanelRoles(t *testing.T) {
	t.Parallel()
	e := newBMCEnv(t, authz.RoleOperator)
	result(e.c.get("/servers/edge")).contains(t, `class="mi mi-off"`, "Needs the admin role.").
		lacks(t, `href="/servers/edge/bmc/reset"`)
	result(e.c.get("/servers/edge/bmc/reset")).status(t, http.StatusForbidden)
	if !e.h.audit.denied("bmc.reset", "forbidden") {
		t.Fatalf("refusal not audited: %+v", e.h.audit.entries)
	}
	v := newBMCEnv(t, authz.RoleViewer)
	result(v.c.get("/servers/edge")).contains(t, "Actions need the operator role.").
		lacks(t, `class="mi mi-off"`, `href="/servers/edge/bmc/reset"`)
	_, plain := signedIn(t)
	result(plain.get("/servers/r730xd/bmc/reset")).status(t, http.StatusNotFound)
}

func TestBMCPanelStatusLines(t *testing.T) {
	t.Parallel()
	e := newBMCEnv(t, authz.RoleAdmin)
	at := e.now.Add(-time.Hour)
	rec := func(result, class, detail string) bmcreset.Record {
		return bmcreset.Record{RequestedAt: at, By: "bob", Result: result, BackAt: at.Add(130 * time.Second),
			Deadline: at.Add(3 * time.Minute), Class: class, Detail: detail}
	}
	for _, c := range []struct {
		st   bmcreset.State
		want string
	}{
		{bmcreset.State{HasLast: true, Last: rec(store.BMCResetVerified, "", "")}, "BMC back after 2 min 10 s (requested by bob"},
		{bmcreset.State{HasLast: true, Last: rec(store.BMCResetVerified, "", store.BMCResetUnchanged)}, "did not report a restart"},
		{bmcreset.State{HasLast: true, Last: rec(store.BMCResetVerified, "", store.BMCResetUnconfirmed)}, "the restart is not confirmed"},
		{bmcreset.State{HasLast: true, Last: rec(store.BMCResetTimeout, "timeout", "")}, "did not come back by"},
		{bmcreset.State{HasLast: true, Last: rec(store.BMCResetTimeout, "config_changed", "")}, "no longer watched"},
		{bmcreset.State{HasLast: true, Last: rec(store.BMCResetTimeout, "unobserved", "")}, "was not running"},
		{bmcreset.State{HasLast: true, Last: rec(store.BMCResetTimeout, "tls", "")}, "does not match its pin"},
		{bmcreset.State{HasLast: true, Last: rec(store.BMCResetRefused, "bmc", "")}, "The BMC refused the restart"},
		{bmcreset.State{HasLast: true, PrivilegeRefused: true, Last: rec(store.BMCResetRefused, "auth", "")}, "needs Configure iDRAC"},
		{bmcreset.State{Restarting: true, Window: bmcreset.Record{RequestedAt: at, By: "bob", Deadline: at.Add(time.Hour)}},
			"BMC restarting · requested"},
	} {
		e.fb.set("old", c.st)
		result(e.c.get("/servers/old")).contains(t, `id="bmc-last" role="status"`, c.want)
	}
	// iDRAC8: no LastResetTime, so the app's last verified restart is shown.
	e.fb.set("old", bmcreset.State{HasVerified: true, LastVerified: rec(store.BMCResetVerified, "", "")})
	result(e.c.get("/servers/old")).contains(t, "by bob (requested here)")
}

func TestBMCConfirmPage(t *testing.T) {
	t.Parallel()
	e := newBMCEnv(t, authz.RoleAdmin)
	e.con.status["edge"] = console.Status{Configured: true, InUse: true, Active: console.Active{Username: "bob"}}
	result(e.c.get("/servers/edge/bmc/reset")).status(t, http.StatusOK).
		contains(t, "<h1>Restart the BMC of Edge router?</h1>", "Monitoring pauses", "Every console on this server closes now",
			"unavailable for about 2–5 minutes", "Fans may run at full speed", "The host keeps running",
			"The graphical console of bob is open; it ends now.", "This server runs oob-manager. The app is not affected",
			"Manager.Reset, ResetType GracefulRestart", "Type <code>Edge router</code>",
			`href="/servers/edge#now-h" autofocus>Cancel</a>`, "Restart BMC of Edge router</button>")
}

func TestBMCSubmitTypedNameAndSuccess(t *testing.T) {
	t.Parallel()
	e := newBMCEnv(t, authz.RoleAdmin)
	e.post(url.Values{"confirm": {"yes"}, "typed": {"edge router"}}).
		status(t, http.StatusUnprocessableEntity).contains(t, "does not match")
	if !e.h.audit.denied("bmc.reset", "confirm_mismatch") || len(e.fb.requests()) != 0 {
		t.Fatalf("mismatch: %+v %v", e.h.audit.entries, e.fb.requests())
	}
	e.post(url.Values{}).status(t, http.StatusSeeOther).location(t, "/servers/edge/bmc/reset")
	if !e.h.audit.denied("bmc.reset", "unconfirmed") {
		t.Fatal("unconfirmed not audited")
	}
	e.post(url.Values{"confirm": {"yes"}, "typed": {"Edge router"}}).
		status(t, http.StatusSeeOther).location(t, "/servers/edge#now-h")
	if got := e.fb.requests(); len(got) != 1 || got[0] != "edge" {
		t.Fatalf("requests %v", got)
	}
	if a := e.fb.actors[0]; a.Username != "pat" || a.Role != "admin" || a.SrcIP != "192.0.2.40" {
		t.Fatalf("actor %+v", a)
	}
}

func TestBMCSubmitCSRFAndStepUp(t *testing.T) {
	t.Parallel()
	e := newBMCEnv(t, authz.RoleAdmin)
	path := "/servers/edge/bmc/reset"
	result(e.c.do(http.MethodPost, path, url.Values{csrfField: {"forged"}, "confirm": {"yes"}, "typed": {"Edge router"}})).
		status(t, http.StatusForbidden)
	result(e.c.do(http.MethodPost, path, url.Values{csrfField: {e.h.csrfToken(e.c)}, "confirm": {"yes"}, "typed": {"Edge router"}})).
		status(t, http.StatusForbidden) // a Settings token is not a BMC form token
	if !e.h.audit.denied("bmc.reset", "csrf") {
		t.Fatal("csrf not audited")
	}
	e.h.clock.Advance(6 * time.Minute)
	result(e.c.get(path)).contains(t, "<strong>Restart BMC · Edge router</strong> needs a fresh code")
	e.post(url.Values{"confirm": {"yes"}, "typed": {"Edge router"}}).
		status(t, http.StatusUnauthorized).contains(t, "Enter the 6-digit code")
	if !e.h.audit.denied("bmc.reset", "stepup_required") || len(e.fb.requests()) != 0 {
		t.Fatalf("step-up: %+v %v", e.h.audit.entries, e.fb.requests())
	}
	result(e.c.get("/stepup?next="+url.QueryEscape(path))).contains(t, "Restart BMC · Edge router")
	result(e.c.get("/stepup?next="+url.QueryEscape("/servers/nope/bmc/reset"))).lacks(t, "Restart BMC ·")
}

func TestBMCCooldownAnswers429(t *testing.T) {
	t.Parallel()
	e := newBMCEnv(t, authz.RoleAdmin)
	e.fb.set("edge", bmcreset.State{CooldownLeft: 4 * time.Minute})
	r := result(e.c.get("/servers/edge/bmc/reset")).status(t, http.StatusTooManyRequests).contains(t, "Cooling down for 4 min.")
	if r.rec.Header().Get("Retry-After") != "240" {
		t.Fatalf("Retry-After %q", r.rec.Header().Get("Retry-After"))
	}
	if !e.h.audit.denied("bmc.reset", "cooldown") {
		t.Fatal("cooldown not audited")
	}
}

func TestBMCServiceErrors(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		err    error
		status int
		msg    string
	}{
		{&bmcreset.CooldownError{Left: 30 * time.Second}, http.StatusTooManyRequests, "Try again in 30 seconds."},
		{bmcreset.ErrRestarting, http.StatusConflict, "already restarting"},
		{bmcreset.ErrPowerPending, http.StatusConflict, "still being verified"},
		{bmcreset.ErrUnsupported, http.StatusConflict, "does not offer"},
		{bmcreset.ErrNoOperator, http.StatusConflict, "not set up"},
		{bmcreset.ErrAudit, http.StatusServiceUnavailable, "nothing was sent"},
		{bmcreset.ErrPrivilege, http.StatusBadGateway, "Configure iDRAC"},
		{fmt.Errorf("%w: bmc", bmcreset.ErrBMC), http.StatusBadGateway, "did not accept the restart"},
	} {
		t.Run(c.msg, func(t *testing.T) {
			e := newBMCEnv(t, authz.RoleAdmin)
			e.fb.err = c.err
			e.post(url.Values{"confirm": {"yes"}, "typed": {"Edge router"}}).status(t, c.status).contains(t, c.msg)
		})
	}
}

func TestBMCRateLimit(t *testing.T) {
	t.Parallel()
	e := newBMCEnv(t, authz.RoleAdmin, func(d *Deps) { d.ChangesPerUser = RateLimit{Events: 1, Per: time.Minute} })
	ok := url.Values{"confirm": {"yes"}, "typed": {"Edge router"}}
	e.post(ok).status(t, http.StatusSeeOther)
	e.post(ok).status(t, http.StatusTooManyRequests).contains(t, "Too many BMC restart requests")
	if !e.h.audit.denied("bmc.reset", "rate_limited") {
		t.Fatal("rate limit not audited")
	}
}

func TestRestartingStateWording(t *testing.T) {
	t.Parallel()
	e := newBMCEnv(t, authz.RoleAdmin)
	v := e.h.fleet.servers[0]
	v.Restarting, v.Restart = true, RestartWindow{Since: e.now, Until: e.now.Add(3 * time.Minute), By: "alice"}
	e.h.fleet.servers[0] = v
	result(e.c.get("/servers/edge")).status(t, http.StatusOK).
		contains(t, `class="verdict" role="status"`, "BMC restarting · requested", "by alice · expected back by",
			"<strong>BMC restarting.</strong>", "1 restarting").
		lacks(t, "Data stale.")
	result(e.c.get("/servers")).contains(t, "BMC restarting", "r-stale")
	result(e.c.get("/servers/edge")).contains(t, "The BMC is restarting; power actions wait until it is back.",
		"BMC is restarting (back by").lacks(t, `href="/servers/edge/power/`, `href="/servers/edge/bmc/reset"`)
	result(e.c.get("/")).contains(t, "BMC restarting: requested")
}

func TestBMCHelpers(t *testing.T) {
	t.Parallel()
	for d, want := range map[time.Duration]string{45 * time.Second: "45 s", 2 * time.Minute: "2 min",
		130 * time.Second: "2 min 10 s"} {
		if got := downFor(d); got != want {
			t.Errorf("downFor(%v) = %q", d, got)
		}
	}
	if coolMinutes(61*time.Second) != "2 min" || coolMinutes(time.Minute) != "1 min" {
		t.Error("coolMinutes rounds up")
	}
	if joinNonEmpty("", "b") != "b" || joinNonEmpty("a", "") != "a" || joinNonEmpty("a", "b") != "a · b" {
		t.Error("joinNonEmpty")
	}
}
