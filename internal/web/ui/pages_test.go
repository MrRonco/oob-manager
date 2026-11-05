package ui

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
)

func signedIn(t *testing.T, tweak ...func(*Deps)) (*harness, *client) {
	t.Helper()
	h := newHarness(t, tweak...)
	secret := h.addUser("viewer", authz.RoleViewer, true)
	c := h.client("192.0.2.100")
	c.login("viewer", secret)
	return h, c
}

// signedInOperator is signedIn with the operator role: the one that sees installation
// placeholders ("not set up") on the action bar and the Operations tab (a viewer gets a
// role note instead, audit R2-11).
func signedInOperator(t *testing.T, tweak ...func(*Deps)) (*harness, *client) {
	t.Helper()
	h := newHarness(t, tweak...)
	secret := h.addUser("ops", authz.RoleOperator, true)
	c := h.client("192.0.2.101")
	c.login("ops", secret)
	return h, c
}

func TestPagesRequireSession(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	c := h.client("192.0.2.100")
	for _, p := range []string{"/", "/servers/r730xd", "/servers/r730xd/events", "/servers/r730xd/inventory", "/activity",
		"/servers/r730xd/activity", "/servers/r730xd/sensors", "/servers/r730xd/fan", "/events"} {
		result(c.get(p)).status(t, http.StatusSeeOther).location(t, "/login")
	}
	c.jar[auth.SessionCookieName] = "bogus"
	result(c.get("/")).status(t, http.StatusSeeOther).location(t, "/login")
	if _, ok := c.jar[auth.SessionCookieName]; ok {
		t.Fatal("invalid session cookie not cleared")
	}
}

// fleetTable is the fleet table of the Servers page (round-2 slice C: the Overview draws
// the flight recorder and a compact list; the table with every column is on /servers).
func fleetTable(c *client) string {
	return between(c.get("/servers").Body.String(), `aria-label="Fleet table"`, "</table>")
}

func TestOverview(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	r := result(c.get("/")).status(t, http.StatusOK)
	r.contains(t, "Storage node R730XD", "Edge node R240", "Spare box",
		`href="/servers/r730xd"`, "Stale 10 min", "last error: timed out", "No data", "BMC unreachable", "<span>2 stale</span>",
		"Stale (last: Warning)", "Also needs attention", "Power supply PS2 reports Critical", "viewer", `action="/logout"`,
		`class="gpill gp-stale"`, "2 stale")
	body := fleetTable(c)
	for _, want := range []string{`<span class="mv">23</span>`, `<span class="mv">51</span>`, ">2/2<", ">1/2<", ">241<"} {
		if !strings.Contains(body, want) {
			t.Errorf("fleet table lacks %s", want)
		}
	}
	if strings.Index(body, ">Spare box</a>") < strings.Index(body, ">Edge node R240</a>") ||
		strings.Index(body, ">Storage node R730XD</a>") < strings.Index(body, ">Spare box</a>") {
		t.Fatal("fleet table must list problems first, in config order within a rank")
	}
}

func TestOverviewEmptyFleet(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	h.fleet.servers = nil
	result(c.get("/")).status(t, http.StatusOK).contains(t, "No servers are configured yet.", "First-run checklist")
}

func TestServerPage(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	r := result(c.get("/servers/r730xd")).status(t, http.StatusOK)
	r.contains(t, "Inlet", "b-crit", "390 W", "power: timeout", "PowerEdge R730xd", "SVCTAG1", "Live ")
	r.lacks(t, "<script>alert(1)", "Data stale.")
	sn := result(c.get("/servers/r730xd/sensors")).status(t, http.StatusOK)
	sn.contains(t, `title="System Board Inlet Temp"`, "42 / 47", "Fan1A", "<strong>7440</strong>", "PWR SPLY,750W",
		"120 W", "Peak", "&lt;script&gt;alert(1)&lt;/script&gt;").lacks(t, "<script>alert(1)", "Data stale.")
}

func TestServerPageStaleAndEmpty(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	result(c.get("/servers/r240")).status(t, http.StatusOK).
		contains(t, "Data stale.", "Values below are not current.", "Inventory not read yet.")
	result(c.get("/servers/r240/sensors")).status(t, http.StatusOK).contains(t, "Data stale.", "Stale (last: OK)")
	result(c.get("/servers/spare")).status(t, http.StatusOK).contains(t, "No data.").lacks(t, "Temperatures")
	result(c.get("/servers/spare/sensors")).status(t, http.StatusOK).contains(t, "No data.", "No readings yet").lacks(t, "Temperatures")
}

func TestStaleThresholdIsConfigurable(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t, func(d *Deps) { d.StaleAfter = time.Hour })
	result(c.get("/servers/r240")).status(t, http.StatusOK).lacks(t, "Data stale.")
}

func TestServerNotFound(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	for _, p := range []string{"/servers/nope", "/servers/R730XD", "/servers/a%20b", "/servers/nope/events",
		"/servers/nope/inventory"} {
		result(c.get(p)).status(t, http.StatusNotFound)
	}
}

func TestInventoryPage(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	result(c.get("/servers/r730xd/inventory")).status(t, http.StatusOK).
		contains(t, "Integrated Dell Remote Access Controller", "2.86.86.86", "25227", "Installed", "56 threads",
			"Enterprise", "iDRAC8 Enterprise License", "Redfish version", "<h1>Storage node R730XD: inventory</h1>")
	result(c.get("/servers/r240/inventory")).status(t, http.StatusOK).contains(t, "Inventory not read yet.")
}

func eventLog(n int, complete bool) bmc.EventLog {
	es := make([]bmc.Event, n)
	for i := range es {
		es[i] = bmc.Event{ID: fmt.Sprint(i), Message: fmt.Sprintf("event-%03d", i), Severity: bmc.SeverityWarning,
			Created: time.Date(2026, 10, 1, 0, 0, i, 0, time.UTC), MessageID: "SEL9901", EntryType: "SEL"}
	}
	return bmc.NewEventLog("/redfish/v1/Managers/iDRAC.Embedded.1/LogServices/Sel/Entries", es, complete)
}

func TestLogsPagination(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	h.fleet.logs["r730xd/sel"] = eventLog(120, true)
	r := result(c.get("/servers/r730xd/events")).status(t, http.StatusOK)
	r.contains(t, "event-000", "event-049", "120 entries", "Page 1 of 3",
		`href="/servers/r730xd/events?log=sel&amp;page=2"`, "2026-10-01 00:00:00 UTC").lacks(t, "event-050", `rel="prev"`)
	result(c.get("/servers/r730xd/events?log=sel&page=3")).status(t, http.StatusOK).
		contains(t, "event-119", "Page 3 of 3", `rel="prev"`).lacks(t, "event-099", `rel="next"`)
	result(c.get("/servers/r730xd/events?page=99")).status(t, http.StatusSeeOther).
		location(t, "/servers/r730xd/events?log=sel&page=3")
	for _, q := range []string{"?page=abc", "?page=0", "?page=-1", "?page=100001", "?log=bogus"} {
		result(c.get("/servers/r730xd/events"+q)).status(t, http.StatusBadRequest)
	}
}

func TestLogsStates(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	h.fleet.logs["r730xd/sel"] = eventLog(3, false)
	h.fleet.logs["r240/sel"] = eventLog(0, true)
	result(c.get("/servers/r730xd/events")).contains(t, "only part of this log could be read", "<strong>Warning:</strong>")
	result(c.get("/servers/r240/events")).contains(t, "The log is empty.")
	result(c.get("/servers/r730xd/events?log=lifecycle")).
		contains(t, "This server does not provide this log.", `aria-current="page">Lifecycle log`)
	h.fleet.logErr = fmt.Errorf("wrapped: %w", bmc.ErrTimeout)
	result(c.get("/servers/r730xd/events")).status(t, http.StatusOK).
		contains(t, "could not be read from the BMC (timed out)").lacks(t, "wrapped")
}

func TestAuthzDenyUnknownRole(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addUser("guest", authz.Role("guest"), true)
	c := h.client("192.0.2.100")
	c.login("guest", secret)
	for _, p := range []string{"/", "/servers/r730xd", "/servers/r730xd/events", "/servers/r730xd/inventory", "/activity",
		"/servers/r730xd/activity", "/servers/r730xd/sensors", "/servers/r730xd/fan", "/events"} {
		result(c.get(p)).status(t, http.StatusForbidden).lacks(t, "Storage node R730XD")
	}
	e, ok := h.audit.find(string(authz.ViewFleet), audit.ResultDenied)
	if !ok || e.Principal != "guest" || e.ErrorClass != "forbidden" {
		t.Fatalf("denial not audited: %+v", e)
	}
}

func TestAuthzCalledWithEveryPageAction(t *testing.T) {
	t.Parallel()
	var asked []authz.Action
	deny := func(_ authz.Principal, a authz.Action, _ bool) error {
		asked = append(asked, a)
		if a == authz.ViewLogs {
			return authz.ErrStepUpRequired
		}
		return authz.ErrForbidden
	}
	h, c := signedIn(t, func(d *Deps) { d.Authorize = deny })
	pages := map[string]authz.Action{"/": authz.ViewFleet, "/servers": authz.ViewFleet,
		"/servers/r730xd": authz.ViewServer, "/servers/r730xd/events": authz.ViewLogs,
		"/servers/r730xd/inventory": authz.ViewInventory, "/events": authz.ViewLogs, "/about": authz.AboutView,
		"/firmware": authz.ViewFirmware, "/firmware.csv": authz.ExportFirmware}
	for p, want := range pages {
		asked = nil
		result(c.get(p)).status(t, http.StatusForbidden).lacks(t, "Storage node R730XD")
		if len(asked) == 0 || asked[0] != want {
			t.Fatalf("%s: authz asked %v first, want %s", p, asked, want)
		}
	}
	if e, ok := h.audit.find(string(authz.ViewLogs), audit.ResultDenied); !ok || e.ErrorClass != "stepup_required" {
		t.Fatalf("step-up denial class: %+v", e)
	}
}

func TestUnknownRoutesAndMethods(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	for _, p := range []string{"/admin/users", "/servers/r730xd/power", "/nope", "/settings/nope"} {
		result(c.get(p)).status(t, http.StatusNotFound)
	}
	result(c.do(http.MethodPost, "/servers/r730xd", nil)).status(t, http.StatusNotFound)
	result(c.do(http.MethodPost, "/", nil)).status(t, http.StatusNotFound)
}

func TestStaticCSS(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	rec := h.client("192.0.2.100").get("/static/app.css")
	result(rec).status(t, http.StatusOK).contains(t, ":focus-visible")
	result(h.client("192.0.2.10").get("/static/tokens.css")).status(t, http.StatusOK).contains(t, "prefers-color-scheme")
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/css") {
		t.Fatalf("Content-Type = %q", ct)
	}
	result(h.client("192.0.2.100").get("/static/nope.js")).status(t, http.StatusNotFound)
}

func TestSessionStoreErrorIs500(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	h.deps.Auth = brokenAuth{h.authn}
	app, err := New(h.deps)
	must(t, err)
	h.handler = app
	result(c.get("/")).status(t, http.StatusInternalServerError).lacks(t, "db exploded")
}

type brokenAuth struct{ *auth.Authenticator }

func (brokenAuth) Authenticate(context.Context, string) (auth.Identity, error) {
	return auth.Identity{}, errors.New("db exploded")
}
