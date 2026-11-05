package ui

import (
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/power"
)

// placeholderTexts are the pre-P2..P4 "not built yet" strings; with power, fans and the
// serial console all built none of them may appear on any page.
var placeholderTexts = []string{"Not yet:", "in this version", "later version", "once it is available",
	"once they are available"}

// allOpsDeps wires fake power, fan and serial services (the integrated build).
func allOpsDeps(fp *fakePower, ff *fakeFans, fs *fakeSerial) func(*Deps) {
	return func(d *Deps) { d.Power, d.Fans, d.Serial = fp, ff, fs }
}

func opsAdmin(t *testing.T) (*harness, *client) {
	t.Helper()
	fp := &fakePower{last: map[string]power.Operation{}, info: map[string]power.Info{
		"r730xd": {Configured: true, Operator: true}}}
	ff := &fakeFans{}
	h := newHarness(t, allOpsDeps(fp, ff, newFakeSerial()))
	c := h.client("192.0.2.30")
	c.login("boss", h.addUser("boss", authz.RoleAdmin, true))
	return h, c
}

func TestServerActionsAllServicesLive(t *testing.T) {
	t.Parallel()
	_, c := opsAdmin(t)
	result(c.get("/servers/r730xd/fan")).status(t, http.StatusOK).
		contains(t, `id="fan-h"`, `action="/servers/r730xd/fan/lease"`).lacks(t, placeholderTexts...)
	result(c.get("/servers/r730xd")).status(t, http.StatusOK).
		contains(t, `href="/servers/r730xd/fan"`, "Open serial console").lacks(t, placeholderTexts...)
	result(c.get("/servers/r730xd/inventory")).status(t, http.StatusOK).
		contains(t, "In the server menus (Console, Power, More).").lacks(t, placeholderTexts...)
	result(c.get("/help")).lacks(t, placeholderTexts...)
}

func TestServerActionsWithoutServicesSayNotSetUp(t *testing.T) {
	t.Parallel()
	_, c := signedInAdmin(t)
	result(c.get("/servers/r730xd/fan")).status(t, http.StatusOK).lacks(t, placeholderTexts...)
	result(c.get("/servers/r730xd")).contains(t, "Power control: not set up", "Fan control: not set up").
		lacks(t, placeholderTexts...)
	result(c.get("/servers/r730xd/inventory")).contains(t, notSetUp).lacks(t, placeholderTexts...)
}

// Server-scoped refusals name the server in the audit row, whichever feature refused.
func TestServerScopedDenialsAuditTheServer(t *testing.T) {
	t.Parallel()
	h, c, _ := fanSignedIn(t, authz.RoleOperator)
	h.clock.Advance(6 * time.Minute)
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", fanForm(t, c, url.Values{"confirm": {"yes"}}))).
		status(t, http.StatusUnauthorized)
	if e, ok := h.audit.find(string(authz.FanLeaseCreate), audit.ResultDenied); !ok || e.ServerID != "r730xd" {
		t.Fatalf("fan step-up denial = %+v, %v", e, ok)
	}
	hs, admin, _ := serialHarness(t, authz.RoleAdmin)
	hs.clock.Advance(6 * time.Minute)
	result(admin.get("/servers/r730xd/serial")).status(t, http.StatusSeeOther)
	if e, ok := hs.audit.find(string(authz.ConsoleSerial), audit.ResultDenied); !ok || e.ServerID != "r730xd" {
		t.Fatalf("serial step-up denial = %+v, %v", e, ok)
	}
}

// The fan lease review is the shared confirm interstitial (same template and inline
// step-up as power and Settings), with the floor and duration fields added.
func TestFanReviewUsesSharedConfirm(t *testing.T) {
	t.Parallel()
	_, c, _ := fanSignedIn(t, authz.RoleOperator)
	result(c.do(http.MethodPost, "/servers/r730xd/fan/lease", fanForm(t, c, nil))).status(t, http.StatusOK).
		contains(t, `<h2 id="w-h">What happens</h2>`, `name="pct"`, `name="minutes"`, "Reversible",
			">Start lease</button>")
	if pageFanLease := "fan_lease"; slices.Contains(pageNames(), pageFanLease) {
		t.Fatal("fan lease must not keep its own confirm template")
	}
}
