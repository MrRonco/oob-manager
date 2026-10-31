package ui

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
)

// Tests for the fixes from docs/reviews/2026-10-21-ui-layout-review.md (F-xx).

func TestF02StaleServersNeverShowOK(t *testing.T) {
	h, c := signedIn(t)
	h.fleet.servers[1] = withHealth(h.fleet.servers[1], bmc.HealthOK) // R240: stale but last said OK
	result(c.get("/")).status(t, http.StatusOK)
	row := between(fleetTable(c), `href="/servers/r240"`, "</tr>")
	if strings.Contains(row, "b-ok") || !strings.Contains(row, "Stale (last: OK)") {
		t.Fatalf("stale row shows OK:\n%s", row)
	}
	srv := result(c.get("/servers/r240")).status(t, http.StatusOK).rec.Body.String()
	if strings.Contains(between(srv, `id="temps-h"`, "</section>"), "b-ok") {
		t.Fatal("stale server's sensor rows show OK")
	}
	result(c.get("/static/app.css")).lacks(t, "opacity: .7")
}

func withHealth(v ServerView, h bmc.Health) ServerView {
	v.Snapshot = snapshotAt(v.LastSuccess, h)
	return v
}

func between(s, from, to string) string {
	i := strings.Index(s, from)
	if i < 0 {
		return ""
	}
	j := strings.Index(s[i:], to)
	if j < 0 {
		return s[i:]
	}
	return s[i : i+j]
}

func TestF03TruthfulTimesAndAutoRefresh(t *testing.T) {
	_, c := signedIn(t)
	r := result(c.get("/")).status(t, http.StatusOK)
	r.contains(t, "Page generated", "Auto-refresh <strong>Off</strong>", "Reload now", "Last successful poll 2026-10-20 11:59:40 UTC").
		lacks(t, `http-equiv="refresh"`)
	result(c.get("/servers/r730xd")).contains(t, `<time datetime="2026-10-20T11:59:40Z">`)
	result(c.submit("/", "/prefs/refresh", url.Values{"refresh": {"on"}, "next": {"/servers"}})).
		status(t, http.StatusSeeOther).location(t, "/servers")
	result(c.get("/")).contains(t, `<meta http-equiv="refresh" content="60">`, "Auto-refresh <strong>On</strong> (every 60 s)")
	result(c.get("/servers/r730xd")).contains(t, `http-equiv="refresh"`)
	result(c.get("/servers/r730xd/events")).lacks(t, `http-equiv="refresh"`)
	result(c.submit("/", "/prefs/refresh", url.Values{"refresh": {"off"}, "next": {"https://evil.test/"}})).
		status(t, http.StatusSeeOther).location(t, "/")
	result(c.get("/")).lacks(t, `http-equiv="refresh"`)
	result(c.do(http.MethodPost, "/prefs/refresh", url.Values{"refresh": {"on"}})).status(t, http.StatusForbidden)
}

func TestF04NavigationCurrentPageAndBreadcrumb(t *testing.T) {
	_, c := signedIn(t)
	result(c.get("/")).contains(t, `<a href="/" aria-current="page">`, `href="/events"`, `href="/about"`,
		`<aside class="side"`, `href="/servers/r240"`).lacks(t, `href="/settings"`)
	srv := result(c.get("/servers/r730xd/events")).status(t, http.StatusOK)
	srv.contains(t, `aria-label="Breadcrumb"`, `<a href="/servers">Servers</a>`, `<span aria-current="page">Events</span>`,
		`<a href="/servers/r730xd/events" aria-current="page">`, `<a href="/servers/r730xd" aria-current="page"><span class="sdot`)
	result(c.get("/servers")).status(t, http.StatusOK).contains(t, "3 configured", "Storage node R730XD", "No data")
}

func TestF05ErrorPagesKeepTheSignedInLayout(t *testing.T) {
	_, c := signedIn(t)
	r := result(c.get("/servers/nope")).status(t, http.StatusNotFound)
	r.contains(t, "Server not found", "Error 404", "Configured servers", `href="/servers/r730xd"`, "Sign out",
		"Go to the overview")
	result(c.get("/nope")).status(t, http.StatusNotFound).contains(t, "Page not found", "Sign out")
	h := newHarness(t)
	result(h.client("192.0.2.1").get("/nope")).status(t, http.StatusNotFound).
		contains(t, "Go to sign in").lacks(t, "Sign out", "Configured servers")
}

func TestF06PagerAndF07LogLayout(t *testing.T) {
	h, c := signedIn(t)
	h.fleet.logs["r730xd/sel"] = eventLog(1, true)
	result(c.get("/servers/r730xd/events")).contains(t, "1 entry in the order the BMC keeps them", "ID SEL9901",
		"newest record first").lacks(t, "1 entries", "Page 1 of 1")
	h.fleet.logs["r730xd/sel"] = eventLog(120, true)
	result(c.get("/servers/r730xd/events?page=2")).contains(t, "Page 2 of 3", ">First<", ">Last<",
		`href="/servers/r730xd/events?log=sel&amp;page=1"`, `href="/servers/r730xd/events?log=sel&amp;page=3"`)
}

func TestF09ScrollRegionsAreFocusableAndHealthIsSecond(t *testing.T) {
	_, c := signedIn(t)
	body := result(c.get("/servers/r730xd/sensors")).rec.Body.String()
	if n := strings.Count(body, `class="tw" role="region"`); n != strings.Count(body, `class="tw"`) || n < 2 {
		t.Fatalf("%d of %d scroll regions are labelled", n, strings.Count(body, `class="tw"`))
	}
	if strings.Count(body, `<table class="stack">`) != strings.Count(body, "<table") {
		t.Fatal("every table must stack on phones (UX-09)")
	}
	if !strings.Contains(body, `aria-label="Temperatures table"`) {
		t.Fatal("scroll region label must differ from its section's (axe landmark-unique)")
	}
	if !strings.Contains(body, `tabindex="0"`) {
		t.Fatal("scroll regions are not focusable")
	}
	head := between(body, `id="temps-h"`, "</thead>")
	if strings.Index(head, "Reading") > strings.Index(head, "Headroom") {
		t.Fatal("the reading must come before the headroom meter")
	}
}

func TestF10OneNoDataVocabulary(t *testing.T) {
	_, c := signedIn(t)
	for _, p := range []string{"/", "/servers/r730xd", "/servers/spare", "/servers/r730xd/inventory"} {
		body := result(c.get(p)).status(t, http.StatusOK).rec.Body.String()
		for _, bad := range []string{">—<", ">unavailable<", ">unknown<"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s renders %q", p, bad)
			}
		}
	}
	result(c.get("/servers")).contains(t, `<span class="nodata">Not reported</span>`)
}

func TestF11PSURatingIsNotLiveInput(t *testing.T) {
	h, c := signedIn(t)
	snap := bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: h.clock.Now(), PowerState: bmc.PowerOn, Health: bmc.HealthOK,
		PSUs: []bmc.PSU{{Name: "PS1", CapacityWatts: bmc.ReadingOf(750), RatedInputWatts: bmc.ReadingOf(900),
			Health: bmc.HealthOK}},
		Power: bmc.PowerDraw{ConsumedWatts: bmc.ReadingOf(263)}})
	h.fleet.servers[0].Snapshot, h.fleet.servers[0].LastSuccess = snap, h.clock.Now()
	body := result(c.get("/servers/r730xd/sensors")).rec.Body.String()
	psu := between(body, `id="psu-h"`, "</section>")
	if !strings.Contains(psu, "750 W out · 900 W in") || strings.Contains(psu, `data-label="In W"`) ||
		strings.Contains(psu, ">900 W</td>") {
		t.Fatalf("PSU table:\n%s", psu)
	}
}

func TestF12OverviewSummaryAttentionAndTable(t *testing.T) {
	_, c := signedIn(t)
	result(c.get("/")).contains(t, "<span class=\"meta\">3 servers</span>", "<span>Draw 241 W</span>",
		"No answer from the BMC for 10 min (last error: timed out)", "No data: never polled successfully",
		`href="/servers/r730xd/sensors#psu-h"`)
	result(c.get("/servers")).contains(t, `aria-label="Fleet table"`)
}

func TestF13LoginKeepsUsernameAndTiesErrors(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("morgan", authz.RoleAdmin, true)
	c := h.client("192.0.2.5")
	page := c.get("/login").Body.String()
	rec := c.do(http.MethodPost, "/login", url.Values{"username": {"morgan"}, "password": {"wrong password here"},
		csrfField: {csrfFor(t, page, "/login")}})
	result(rec).status(t, http.StatusUnauthorized).contains(t, `value="morgan"`, `aria-invalid="true"`,
		`aria-describedby="form-error"`, `id="form-error"`).lacks(t, "wrong password here")
	page = c.get("/login").Body.String()
	result(c.do(http.MethodPost, "/login", url.Values{"username": {"morgan"}, "password": {testPassword},
		csrfField: {csrfFor(t, page, "/login")}})).status(t, http.StatusSeeOther)
	result(c.get("/login/totp")).contains(t, "Signing in as <strong>morgan</strong>", "Lost your authenticator?")
	_ = secret
}

func TestF14BrandingFooterAndStaticCaching(t *testing.T) {
	_, c := signedIn(t)
	result(c.get("/")).contains(t, `<link rel="icon" href="/static/favicon-stale.svg?v=`, `<span class="logo" aria-hidden="true">`,
		`<meta name="robots" content="noindex, nofollow">`, `<footer class="foot">`, "<span>dev</span>")
	for _, f := range []string{"/static/logo.svg", "/static/favicon.svg"} {
		rec := c.get(f)
		result(rec).status(t, http.StatusOK)
		if rec.Header().Get("Cache-Control") != staticCacheControl {
			t.Errorf("%s Cache-Control = %q", f, rec.Header().Get("Cache-Control"))
		}
	}
	if cc := c.get("/").Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("pages must stay no-store, got %q", cc)
	}
}

func TestF15ActionsCardExplainsAvailability(t *testing.T) {
	_, oc := signedInOperator(t)
	result(oc.get("/servers/r730xd")).contains(t, "Power control: not set up", `aria-disabled="true"`,
		"Fan control: not set up").lacks(t, "Actions</h2>")
	_, c := signedIn(t) // viewer: a role note instead of dead buttons (audit R2-11)
	result(c.get("/servers/r730xd")).contains(t, "Actions need the operator role.").lacks(t, `aria-disabled="true"`, "Actions</h2>")
	result(c.get("/servers/r730xd/inventory")).contains(t, "Needs the operator role.", "Power control")
	h, ac := signedInAdmin(t)
	_ = h
	result(ac.get("/servers/r730xd/inventory")).contains(t, "Your role may use it.", notSetUp)
}

func TestF18RoleChipHiddenWhenItRepeatsTheName(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("admin", authz.RoleAdmin, true)
	c := h.client("192.0.2.5")
	c.login("admin", secret)
	result(c.get("/")).lacks(t, `<span class="role">admin</span>`)
	_, vc := signedIn(t)
	result(vc.get("/")).lacks(t, `<span class="role">`)
}

func TestEventsPage(t *testing.T) {
	h, c := signedIn(t)
	h.fleet.logs["r730xd/sel"] = eventLog(3, true)
	crit := bmc.NewEventLog("x", []bmc.Event{{ID: "9", Message: "PSU lost", Severity: bmc.SeverityCritical,
		Created: time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)}}, true)
	h.fleet.logs["r240/lifecycle"] = crit
	r := result(c.get("/events?severity=all&range=all")).status(t, http.StatusOK)
	r.contains(t, "PSU lost", "event-002", "Edge node R240", "Lifecycle", `aria-current="page">Events`)
	body := r.rec.Body.String()
	if strings.Index(body, "PSU lost") > strings.Index(body, "event-002") {
		t.Fatal("events not newest first")
	}
	result(c.get("/events?severity=critical&range=all")).contains(t, "PSU lost").lacks(t, "event-002")
	result(c.get("/events?log=sel&range=all&severity=all")).lacks(t, "PSU lost")
	for _, q := range []string{"?log=x", "?severity=x", "?page=0"} {
		result(c.get("/events"+q)).status(t, http.StatusBadRequest)
	}
	result(c.get("/events?page=9")).status(t, http.StatusSeeOther)
	h.fleet.logErr = fmt.Errorf("x: %w", bmc.ErrTimeout)
	result(c.get("/events")).status(t, http.StatusOK).contains(t, "could not be read (timed out)")
}

func TestStepUpPageWhenAlreadyFresh(t *testing.T) {
	_, c := signedInAdmin(t)
	result(c.get("/stepup?next=/settings/users")).status(t, http.StatusOK).
		contains(t, "already confirmed", `href="/settings/users"`, "Continue")
	result(c.get("/stepup?next=//evil.test")).contains(t, `href="/settings"`).lacks(t, "evil.test")
}

func TestCompareNewest(t *testing.T) {
	a, b := time.Unix(1, 0), time.Unix(2, 0)
	if compareNewest(a, b) <= 0 || compareNewest(b, a) >= 0 || compareNewest(time.Time{}, a) <= 0 ||
		compareNewest(a, time.Time{}) >= 0 || compareNewest(time.Time{}, time.Time{}) != 0 {
		t.Fatal("compareNewest order wrong")
	}
}
