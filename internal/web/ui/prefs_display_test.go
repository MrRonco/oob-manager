package ui

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/config"
	"oob-manager/internal/settings"
)

// signInViewer creates, enrols and signs in a viewer.
func (e *settingsEnv) signInViewer(t *testing.T, name, ip string) *client {
	t.Helper()
	link, err := e.svc.CreateUser(context.Background(), actorFor(t, e, "morgan"), name, authz.RoleViewer)
	must(t, err)
	c := e.client(ip)
	c.login(name, e.enrolViaLink(link.Token, testPassword))
	return c
}

func TestDisplayUserOverrideWins(t *testing.T) {
	e, _ := newGeneralEnv(t, "ui: { time_zone: America/New_York }\n")
	admin := e.adminClient()
	viewer := e.signInViewer(t, "victor", "192.0.2.20")

	result(viewer.get("/preferences")).status(t, http.StatusOK).contains(t, "Display preferences",
		`<option value="" selected>App default (America/New_York)</option>`, `data-palette="solarized"`,
		`id="p-date_format-default" name="date_format" value="" checked`, `App default (ISO (2026-10-21))`,
		`id="p-clock-default" name="clock" value="" checked`, `App default (24-hour (14:05))`,
		`id="p-temp_unit-default" name="temp_unit" value="" checked`, `App default (Celsius (°C))`,
		`id="p-density-default" name="density" value="" checked`, `App default (Compact)`)
	rec := viewer.submit("/preferences", "/preferences", url.Values{"time_zone": {"Asia/Tokyo"}, "theme": {"dracula"},
		"date_format": {"us"}, "clock": {"12h"}, "temp_unit": {"f"}, "density": {"comfortable"}})
	result(rec).status(t, http.StatusSeeOther).location(t, "/preferences?done=saved")

	// The viewer sees Tokyo time, US dates, a 12-hour clock, °F, Dracula and comfortable rows;
	// the admin keeps the app default (New York, Graphite, °C).
	result(viewer.get("/preferences?done=saved")).contains(t, "Preferences saved.", `data-palette="dracula"`,
		`data-density="comfortable"`, ` JST</time>`, `<option value="Asia/Tokyo" selected>Tokyo</option>`)
	server := result(viewer.get("/servers/r730xd/sensors")).status(t, http.StatusOK).contains(t, "°F", "Reading °F", " PM JST")
	if strings.Contains(server.rec.Body.String(), "Reading °C") {
		t.Fatal("viewer page still in °C")
	}
	result(viewer.get("/servers/r730xd")).contains(t, "as of <time datetime=\"2026-10-21T08:59:40Z\">10/21/2026 5:59:40 PM JST</time>")
	result(admin.get("/servers/r730xd/sensors")).contains(t, "Reading °C", ` EDT</time>`, `data-palette="graphite"`).
		lacks(t, "JST")

	rec2, ok := e.findAudit(settings.ActionPrefsUpdate, audit.ResultOK)
	if !ok || rec2.Principal != "victor" || !strings.Contains(rec2.ParamsJSON, `"after":"Asia/Tokyo"`) {
		t.Fatalf("prefs audit = %+v", rec2)
	}
	// Back to the defaults: everything follows the app default again.
	result(viewer.submit("/preferences", "/preferences", url.Values{"time_zone": {""}, "theme": {""},
		"date_format": {""}, "clock": {""}, "temp_unit": {""}, "density": {""}})).status(t, http.StatusSeeOther)
	result(viewer.get("/")).contains(t, ` EDT</time>`, `data-density="compact"`)
	if p, _ := e.db.Prefs().Get(context.Background(), actorFor(t, e, "victor").UserID); p.DateFormat != "" || p.TimeZone != "" {
		t.Fatalf("defaults stored explicitly: %+v", p)
	}
}

func TestDisplayRejectsInvalidAndCSRF(t *testing.T) {
	e, _ := newGeneralEnv(t, "")
	c := e.adminClient()
	result(c.submit("/preferences", "/preferences", url.Values{"time_zone": {"Mars/Olympus"}})).
		status(t, http.StatusUnprocessableEntity).contains(t, "unknown time zone", `aria-invalid="true"`)
	result(c.submit("/preferences", "/preferences", url.Values{"theme": {"pink"}})).
		status(t, http.StatusUnprocessableEntity).contains(t, "Not saved")
	if rec, ok := e.findAudit(settings.ActionPrefsUpdate, audit.ResultDenied); !ok || rec.ErrorClass != "invalid" {
		t.Fatalf("invalid prefs not audited: %+v", rec)
	}
	result(c.do(http.MethodPost, "/preferences", url.Values{"time_zone": {"UTC"}})).status(t, http.StatusForbidden)
	// The settings CSRF token of the same session is not accepted for this form.
	result(c.do(http.MethodPost, "/preferences", url.Values{csrfField: {e.csrfToken(c)}, "time_zone": {"UTC"}})).
		status(t, http.StatusForbidden)
	if p, _ := e.db.Prefs().Get(context.Background(), actorFor(t, e, "morgan").UserID); p.TimeZone != "" {
		t.Fatalf("refused prefs stored: %+v", p)
	}
}

func TestDisplayNoStepUpNeeded(t *testing.T) {
	e, _ := newGeneralEnv(t, "")
	c := e.adminClient()
	e.clock.Advance(20 * 60e9) // 20 minutes: the step-up window is long gone
	result(c.submit("/preferences", "/preferences", url.Values{"time_zone": {"Europe/Paris"}})).
		status(t, http.StatusSeeOther).location(t, "/preferences?done=saved")
}

func TestSignInPageUsesAppDefaults(t *testing.T) {
	e, _ := newGeneralEnv(t, "ui: { theme: high-contrast, time_zone: Europe/Paris }\n")
	anon := e.client("192.0.2.99")
	result(anon.get("/login")).status(t, http.StatusOK).contains(t, `data-palette="high-contrast"`).lacks(t, "/preferences")
}

func TestClockLinksToPreferences(t *testing.T) {
	e, _ := newGeneralEnv(t, "")
	c := e.adminClient()
	result(c.get("/")).contains(t, `<a class="clock-link" href="/preferences" title="Time zone: UTC.`,
		`<a href="/preferences">`, "Display preferences</a>")
	cur := e.deps.Settings.Current()
	if f, _ := cur.Field(config.KeyTimeZone); f.Value != "UTC" {
		t.Fatalf("zone = %q", f.Value)
	}
}

// TestAppDisplayDefaults: the app-wide defaults for clock, date format, temperature
// unit and density (Settings → General) apply to users who chose none and to the
// sign-in page; a file key is locked; a user's own choice still wins.
func TestAppDisplayDefaults(t *testing.T) {
	e, svc := newGeneralEnv(t, "ui: { density: comfortable }\n")
	admin := e.adminClient()
	result(admin.get("/settings/general")).status(t, http.StatusOK).contains(t,
		`name="ui.clock_format"`, `<option value="12h">12-hour (2:05 PM)</option>`, "Set in config.yaml (ui.density)")
	rec := admin.submit("/settings/general", "/settings/general", url.Values{"rev": {"0"},
		config.KeyClockFormat: {"12h"}, config.KeyDateFormat: {"us"}, config.KeyTempUnit: {"f"}})
	result(rec).status(t, http.StatusSeeOther).location(t, "/settings/general?done=general")
	if g := svc.Current().General; g.ClockFormat != "12h" || g.DateFormat != "us" || g.TempUnit != "f" || g.Density != "comfortable" {
		t.Fatalf("general = %+v", g)
	}
	viewer := e.signInViewer(t, "victor", "192.0.2.20")
	result(viewer.get("/servers/r730xd/sensors")).contains(t, "Reading °F", " AM UTC</time>", `data-density="comfortable"`)
	result(viewer.get("/preferences")).contains(t, "App default (12-hour (2:05 PM))", "App default (Fahrenheit (°F))",
		"App default (US (10/21/2026))", "App default (Comfortable)")
	result(viewer.submit("/preferences", "/preferences", url.Values{"clock": {"24h"}, "temp_unit": {"c"}})).
		status(t, http.StatusSeeOther)
	result(viewer.get("/servers/r730xd/sensors")).contains(t, "Reading °C").lacks(t, " AM UTC</time>")
	result(e.client("192.0.2.99").get("/login")).contains(t, `data-density="comfortable"`)
	// Refused: a file-managed key, and a value outside the set.
	result(admin.submit("/settings/general", "/settings/general", url.Values{"rev": {"1"}, config.KeyDensity: {"compact"}})).
		status(t, http.StatusForbidden)
	result(admin.submit("/settings/general", "/settings/general", url.Values{"rev": {"1"}, config.KeyClockFormat: {"25h"}})).
		status(t, http.StatusUnprocessableEntity).contains(t, "ui.clock_format")
}
