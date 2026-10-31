package ui

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/config"
	"oob-manager/internal/fan"
	"oob-manager/internal/store"
)

type fakeFans struct {
	mu        sync.Mutex
	status    fan.Status
	statusErr error
	startErr  error
	endErr    error
	starts    []fan.Request
	actors    []fan.Actor
	ends      int
}

func (f *fakeFans) Policy(id string) (fan.Policy, bool) {
	switch id {
	case "r730xd":
		return fan.Policy{ServerID: id, Mode: config.FanHostLease, SafeMin: 30, MaxLease: 2 * time.Hour}, true
	case "r240":
		return fan.Policy{ServerID: id, Mode: config.FanRedfishFloor, SafeMin: 41, MaxLease: time.Hour}, true
	default:
		return fan.Policy{}, false
	}
}

func (f *fakeFans) Status(context.Context, string) (fan.Status, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, f.statusErr
}

func (f *fakeFans) Start(_ context.Context, a fan.Actor, _ string, r fan.Request) (store.FanLease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts, f.actors = append(f.starts, r), append(f.actors, a)
	return store.FanLease{Pct: r.Pct}, f.startErr
}

func (f *fakeFans) End(context.Context, fan.Actor, string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ends++
	return f.endErr
}

func (f *fakeFans) set(fn func(*fakeFans)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// fanSignedIn returns a harness with fake fans and a client signed in with role.
func fanSignedIn(t *testing.T, role authz.Role, tweak ...func(*Deps)) (*harness, *client, *fakeFans) {
	t.Helper()
	ff := &fakeFans{status: fan.Status{Observation: fan.Observation{Owner: fan.OwnerCurve, AppliedPct: 35, HasPct: true}}}
	h := newHarness(t, append([]func(*Deps){func(d *Deps) { d.Fans = ff }}, tweak...)...)
	secret := h.addUser("ops", role, true)
	c := h.client("192.0.2.10")
	c.login("ops", secret)
	return h, c, ff
}

func fanForm(t *testing.T, c *client, extra url.Values) url.Values {
	t.Helper()
	page := c.get("/servers/r730xd/fan").Body.String()
	form := url.Values{csrfField: {csrfFor(t, page, "/servers/r730xd/fan/lease")}, "pct": {"55"}, "minutes": {"30"}}
	for k, v := range extra {
		form[k] = v
	}
	return form
}

func TestFanCardViewerIsReadOnly(t *testing.T) {
	_, c, _ := fanSignedIn(t, authz.RoleViewer)
	result(c.get("/servers/r730xd/fan")).status(t, http.StatusOK).
		contains(t, "Fan lease", "<strong>Owner:</strong> Host fan curve", "35 %", "Fan leases need the operator role",
			"Host fan script with a lease file").
		lacks(t, `action="/servers/r730xd/fan/lease"`, "End now")
	result(c.get("/servers/spare/fan")).contains(t, "Fan control is off for this server")
}

func TestFanStartReviewThenConfirm(t *testing.T) {
	h, c, ff := fanSignedIn(t, authz.RoleOperator)
	result(c.get("/servers/r730xd/fan")).contains(t, `action="/servers/r730xd/fan/lease"`, "Review lease",
		`name="pct"`, `<option value="120">2 hours</option>`, "30 to 100")
	review := c.do(http.MethodPost, "/servers/r730xd/fan/lease", fanForm(t, c, nil))
	result(review).status(t, http.StatusOK).contains(t, "Start a fan lease on Storage node R730XD?",
		"Fans run at least at 55 % until", "(30 minutes)", "host fan script applies it", "Step-up fresh", "Start lease").
		lacks(t, `name="code"`)
	if len(ff.starts) != 0 {
		t.Fatal("the review step must not start a lease")
	}
	form := url.Values{csrfField: {csrfFor(t, review.Body.String(), "/servers/r730xd/fan/lease")},
		"pct": {"55"}, "minutes": {"30"}, "confirm": {"yes"}}
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", form)).status(t, http.StatusSeeOther).
		location(t, "/servers/r730xd/fan?fan=started")
	if len(ff.starts) != 1 || ff.starts[0] != (fan.Request{Pct: 55, Duration: 30 * time.Minute}) ||
		ff.actors[0].Username != "ops" || ff.actors[0].IP != "192.0.2.10" {
		t.Fatalf("starts %+v actors %+v", ff.starts, ff.actors)
	}
	result(c.get("/servers/r730xd/fan?fan=started")).contains(t, "Lease started.")
	if e, ok := h.audit.find(string(authz.FanLeaseCreate), audit.ResultDenied); ok {
		t.Fatalf("unexpected denial %+v", e)
	}
}

func TestFanStartNeedsStepUp(t *testing.T) {
	h, c, ff := fanSignedIn(t, authz.RoleOperator)
	h.clock.Advance(6 * time.Minute) // the login step-up has lapsed
	form := fanForm(t, c, url.Values{"confirm": {"yes"}})
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", form)).status(t, http.StatusUnauthorized).
		contains(t, `name="code"`, "Start fan lease · Storage node R730XD", "Enter the 6-digit code")
	if _, ok := h.audit.find(string(authz.FanLeaseCreate), audit.ResultDenied); !ok || len(ff.starts) != 0 {
		t.Fatalf("stale step-up: starts %v", ff.starts)
	}
	bad := fanForm(t, c, url.Values{"confirm": {"yes"}, "code": {"000000"}})
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", bad)).status(t, http.StatusUnauthorized).contains(t, msgBadCode)
	secret := h.addUser("ops2", authz.RoleOperator, true)
	c2 := h.client("192.0.2.11")
	c2.login("ops2", secret)
	h.clock.Advance(6 * time.Minute)
	good := fanForm(t, c2, url.Values{"confirm": {"yes"}, "code": {h.code(secret)}})
	result(c2.do(http.MethodPost, "/servers/r730xd/fan/lease", good)).status(t, http.StatusSeeOther)
	if len(ff.starts) != 1 {
		t.Fatalf("starts = %v", ff.starts)
	}
}

func TestFanStartHostileInput(t *testing.T) {
	_, c, ff := fanSignedIn(t, authz.RoleOperator)
	for _, v := range []url.Values{{"pct": {"101"}}, {"pct": {"abc"}}, {"pct": {"-5"}}, {"minutes": {"999"}},
		{"minutes": {"1"}}, {"pct": {"55 "}}, {"pct": {""}}} {
		v["confirm"] = []string{"yes"}
		result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", fanForm(t, c, v))).status(t, http.StatusUnprocessableEntity).
			contains(t, "Enter a floor from 30 to 100", `aria-invalid="true"`)
	}
	if len(ff.starts) != 0 {
		t.Fatalf("a hostile request started a lease: %+v", ff.starts)
	}
	// Below the safe minimum is raised, not refused.
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", fanForm(t, c, url.Values{"pct": {"10"}, "confirm": {"yes"}}))).
		status(t, http.StatusSeeOther)
	if ff.starts[0].Pct != 30 {
		t.Fatalf("pct = %d", ff.starts[0].Pct)
	}
}

func TestFanRefusals(t *testing.T) {
	h, c, ff := fanSignedIn(t, authz.RoleOperator)
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", url.Values{"pct": {"55"}, "minutes": {"30"}})).
		status(t, http.StatusForbidden)
	if e, ok := h.audit.find(string(authz.FanLeaseCreate), audit.ResultDenied); !ok || e.ErrorClass != "csrf" {
		t.Fatalf("csrf audit = %+v", e)
	}
	result(c.do(http.MethodPost, "/servers/spare/fan/lease", fanForm(t, c, nil))).status(t, http.StatusNotFound)
	result(c.do(http.MethodPost, "/servers/nope/fan/lease", fanForm(t, c, nil))).status(t, http.StatusNotFound)

	h2, v, ff2 := fanSignedIn(t, authz.RoleViewer)
	vf := url.Values{csrfField: {h2.csrfFanToken(v)}, "pct": {"55"}, "minutes": {"30"}, "confirm": {"yes"}}
	result(v.do(http.MethodPost, "/servers/r730xd/fan/lease", vf)).status(t, http.StatusForbidden)
	result(v.do(http.MethodPost, "/servers/r730xd/fan/lease/end", vf)).status(t, http.StatusForbidden)
	if len(ff.starts) != 0 || len(ff2.starts) != 0 || ff2.ends != 0 {
		t.Fatal("refused requests reached the service")
	}
}

func TestFanStartErrors(t *testing.T) {
	cases := map[error]int{fan.ErrActive: http.StatusConflict, fan.ErrApply: http.StatusBadGateway,
		fan.ErrNotConfigured: http.StatusNotFound, errors.New("db"): http.StatusInternalServerError}
	for err, want := range cases {
		_, c, ff := fanSignedIn(t, authz.RoleOperator)
		ff.set(func(f *fakeFans) { f.startErr = err })
		result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", fanForm(t, c, url.Values{"confirm": {"yes"}}))).status(t, want)
	}
}

// TestFanStartAuditDown: a lease refused because the audit row could not be written says so.
func TestFanStartAuditDown(t *testing.T) {
	_, c, ff := fanSignedIn(t, authz.RoleOperator)
	ff.set(func(f *fakeFans) { f.startErr = fan.ErrAudit })
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", fanForm(t, c, url.Values{"confirm": {"yes"}}))).
		status(t, http.StatusServiceUnavailable).contains(t, "The audit log could not be written, so nothing changed.")
}

func TestFanEndNow(t *testing.T) {
	h, c, ff := fanSignedIn(t, authz.RoleOperator)
	now := h.clock.Now()
	ff.set(func(f *fakeFans) {
		f.status = fan.Status{HasLease: true, Remaining: 28 * time.Minute,
			Lease: store.FanLease{Pct: 55, RequestedBy: "ops", ExpiresAt: now.Add(28 * time.Minute), State: store.LeasePending}}
	})
	page := c.get("/servers/r730xd/fan").Body.String()
	result(c.get("/servers/r730xd/fan")).contains(t, "Pending", "Lease by ops: at least 55 %",
		"waiting for confirmation", "28 minutes left", "End now").lacks(t, "Review lease")
	h.clock.Advance(10 * time.Minute) // End now needs no step-up
	form := url.Values{csrfField: {csrfFor(t, page, "/servers/r730xd/fan/lease/end")}}
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease/end", form)).status(t, http.StatusSeeOther).
		location(t, "/servers/r730xd/fan?fan=ended")
	ff.set(func(f *fakeFans) { f.endErr = fan.ErrNoLease })
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease/end", form)).location(t, "/servers/r730xd/fan?fan=none")
	ff.set(func(f *fakeFans) { f.endErr = fan.ErrRelease })
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease/end", form)).status(t, http.StatusBadGateway).
		contains(t, "could not be ended yet")
	if ff.ends != 3 {
		t.Fatalf("ends = %d", ff.ends)
	}
	result(c.get("/servers/r730xd/fan?fan=ended")).contains(t, "Lease ended.")
	result(c.get("/servers/r730xd/fan?fan=none")).contains(t, "no active lease")
}

func TestFanCardStates(t *testing.T) {
	_, c, ff := fanSignedIn(t, authz.RoleOperator)
	ff.set(func(f *fakeFans) {
		f.status = fan.Status{HasLease: true, Remaining: 30 * time.Second, Lease: store.FanLease{Pct: 50, RequestedBy: "ops"},
			Observation: fan.Observation{Applied: true, Owner: fan.OwnerCurve, AppliedPct: 65, HasPct: true}}
	})
	result(c.get("/servers/r730xd/fan")).contains(t, "Applied", "above the lease floor of 50 %", "65 %", "1 minute left")
	ff.set(func(f *fakeFans) {
		f.status = fan.Status{Observation: fan.Observation{Owner: fan.OwnerGuard, Warning: "A thermal guard is active"}}
	})
	result(c.get("/servers/r730xd/fan")).contains(t, "Thermal guard: BMC automatic", "Check:", "A thermal guard is active")
	ff.set(func(f *fakeFans) { f.status = fan.Status{Observation: fan.Observation{Warning: "stale report"}} })
	result(c.get("/servers/r730xd/fan")).contains(t, "No lease, check", "stale report")
	result(c.get("/servers/r240/fan")).contains(t, "BMC automatic (no minimum set by this app)", "BMC minimum fan speed",
		`<option value="60">1 hour</option>`).lacks(t, `<option value="120">`)
	ff.set(func(f *fakeFans) { f.statusErr = errors.New("db") })
	result(c.get("/servers/r730xd/fan")).status(t, http.StatusOK).contains(t, "could not be read")
}

func TestFanNotSetUp(t *testing.T) {
	_, c := signedIn(t)
	result(c.get("/servers/r730xd/fan")).contains(t, "Fan control is not set up in this installation")
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", url.Values{})).status(t, http.StatusNotFound)
}

func TestFanRateLimit(t *testing.T) {
	_, c, ff := fanSignedIn(t, authz.RoleOperator, func(d *Deps) { d.ChangesPerUser = RateLimit{Events: 1, Per: time.Minute} })
	form := fanForm(t, c, url.Values{"confirm": {"yes"}})
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", form)).status(t, http.StatusSeeOther)
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", form)).status(t, http.StatusTooManyRequests)
	if len(ff.starts) != 1 {
		t.Fatalf("starts = %d", len(ff.starts))
	}
}

func (h *harness) csrfFanToken(c *client) string {
	s := csrfSigner{key: h.deps.CSRFKey, ttl: DefaultCSRFTTL, now: h.clock.Now}
	return s.issue(formFan, sessionBinding(c.jar[auth.SessionCookieName]))
}
