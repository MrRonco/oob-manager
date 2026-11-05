package ui

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

// themeCSRF returns the CSRF token of the theme form on body.
func themeCSRF(t *testing.T, body string) string {
	t.Helper()
	return csrfFor(t, body, "/prefs/theme")
}

func TestThemePreferenceIsAServerRenderedForm(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	page := c.get("/events").Body.String()
	if strings.Contains(page, "data-theme=") {
		t.Fatal("no preference must follow the OS (no data-theme attribute)")
	}
	result(c.get("/events")).contains(t, `action="/prefs/theme"`, "Theme: Auto")
	for _, tc := range []struct{ theme, attr string }{{"dark", `data-theme="dark"`}, {"light", `data-theme="light"`}} {
		rec := c.do(http.MethodPost, "/prefs/theme", url.Values{csrfField: {themeCSRF(t, page)}, "theme": {tc.theme},
			"next": {"/events"}})
		result(rec).status(t, http.StatusSeeOther).location(t, "/events")
		page = c.get("/events").Body.String()
		if !strings.Contains(page, tc.attr) {
			t.Fatalf("after choosing %s the page lacks %s", tc.theme, tc.attr)
		}
	}
	rec := c.do(http.MethodPost, "/prefs/theme", url.Values{csrfField: {themeCSRF(t, page)}, "theme": {"auto"}, "next": {"/"}})
	result(rec).status(t, http.StatusSeeOther)
	if strings.Contains(c.get("/").Body.String(), "data-theme=") {
		t.Fatal("auto must clear the preference")
	}
}

func TestThemePreferenceRejectsBadInput(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	page := c.get("/").Body.String()
	result(c.do(http.MethodPost, "/prefs/theme", url.Values{csrfField: {themeCSRF(t, page)}, "theme": {"neon"}})).
		status(t, http.StatusBadRequest)
	result(c.do(http.MethodPost, "/prefs/theme", url.Values{"theme": {"dark"}})).status(t, http.StatusForbidden)
	rec := c.do(http.MethodPost, "/prefs/theme", url.Values{csrfField: {themeCSRF(t, page)}, "theme": {"dark"},
		"next": {"https://evil.example/"}})
	result(rec).status(t, http.StatusSeeOther).location(t, "/")
	h := newHarness(t)
	result(h.client("192.0.2.9").do(http.MethodPost, "/prefs/theme", url.Values{"theme": {"dark"}})).
		status(t, http.StatusSeeOther).location(t, "/login")
}

func TestThemeCookieAppliesBeforeSignIn(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	c := h.client("192.0.2.9")
	c.jar[themeCookie] = "light"
	result(c.get("/login")).contains(t, `data-theme="light"`)
	c.jar[themeCookie] = "<script>"
	result(c.get("/login")).lacks(t, "data-theme=")
}

func TestShellSidebarPillAndClock(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t)
	h.fleet.logs["r730xd/sel"] = bmc.NewEventLog("", []bmc.Event{
		{ID: "1", Created: h.clock.Now().Add(-2 * time.Hour), Message: "PSU lost input", Severity: bmc.SeverityWarning},
		{ID: "2", Created: h.clock.Now().Add(-3 * 24 * time.Hour), Message: "old", Severity: bmc.SeverityCritical},
		{ID: "3", Created: h.clock.Now().Add(-1 * time.Hour), Message: "info", Severity: bmc.SeverityOK},
	}, true)
	r := result(c.get("/events")).status(t, http.StatusOK)
	r.contains(t,
		`class="side"`, `aria-label="Main"`, // the permanent sidebar
		`class="sdot s-stale"`,              // the stale R240 in the server list
		`class="gpill gp-stale"`, "2 stale", // fleet verdict pill: one stale, one never polled
		`class="clock"`, "data ", // generation time and the age of the oldest current data
		`<span class="cnt">1</span>`,   // one warning event in the last 24 hours
		`<details class="menu sheet">`, // the phone Menu sheet
		"Help",
	)
}

func TestPlainShellBeforeSignIn(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(d *Deps) { d.InstanceName = "Lab OOB" })
	r := result(h.client("192.0.2.9").get("/login")).status(t, http.StatusOK)
	r.contains(t, `class="app plain"`, "Lab OOB", `href="/help"`).lacks(t, `class="side"`, "gpill")
}

func TestFooterShowsVersionAndCommit(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t, func(d *Deps) { d.Build = Build{Version: "1.2.3", Commit: "abc1234def"} })
	result(c.get("/")).contains(t, "v1.2.3 (abc1234)", "About and licenses", `href="/help"`).lacks(t, "licences")
}

func TestHelpPageIsPublicAndExplainsTerms(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	r := result(h.client("192.0.2.9").get("/help")).status(t, http.StatusOK)
	r.contains(t, "<h1>Help</h1>", "Glossary", "System Event Log", "Power-good", "Step-up", "Accessibility",
		"WCAG 2.2", `id="setup"`).lacks(t, `class="side"`)
	_, c := signedIn(t)
	result(c.get("/help")).status(t, http.StatusOK).contains(t, `class="side"`, `aria-current="page"`)
}
