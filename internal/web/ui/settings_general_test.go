package ui

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/config"
	"oob-manager/internal/settings"
	"oob-manager/internal/web"
)

const generalBaseYAML = `tls: { cert_file: /c, key_file: /k }
public_url: https://oob.test
servers:
  - id: r730xd
    name: Storage node R730XD
    bmc: { address: 192.0.2.70, kind: idrac8 }
    tls_pin_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    credentials: { readonly: r-ro }
`

// newGeneralEnv is newSettingsEnv plus the settings service over the same database,
// with extraYAML written into config.yaml (file-managed keys).
func newGeneralEnv(t *testing.T, extraYAML string) (*settingsEnv, *settings.Service) {
	t.Helper()
	e := newSettingsEnv(t)
	file, err := config.Parse([]byte(extraYAML + generalBaseYAML))
	must(t, err)
	lg := audit.NewLogger(e.db.Audit(), nil, e.clock.Now, quiet())
	svc, err := settings.New(context.Background(), settings.Config{DB: e.db, Audit: lg, File: file, Now: e.clock.Now, Logger: quiet()})
	must(t, err)
	e.deps.Settings = svc
	app, err := New(e.deps)
	must(t, err)
	e.handler, err = web.NewHandler(app, web.Options{Logger: quiet()})
	must(t, err)
	return e, svc
}

func TestGeneralPageShowsSourcesAndLocks(t *testing.T) {
	e, _ := newGeneralEnv(t, "ratelimit: { login_acct_per_hour: 12 }\n")
	c := e.adminClient()
	r := result(c.get("/settings/general")).status(t, http.StatusOK).contains(t,
		`aria-current="page">General`, "Managed by config.yaml", "Set in config.yaml (ratelimit.login_acct_per_hour)",
		`name="ratelimit.login_acct_per_hour" type="text"`, "Default.",
		`<optgroup label="America">`, `<option value="UTC" selected>`, `name="rev" value="0"`, "Save settings")
	body := r.rec.Body.String()
	if !strings.Contains(body, `id="g-ratelimit-login-acct-per-hour" name="ratelimit.login_acct_per_hour" type="text" inputmode="numeric" min="3" max="20" step="1" required value="12" aria-describedby="g-ratelimit-login-acct-per-hour-hint g-ratelimit-login-acct-per-hour-src" disabled`) {
		t.Fatalf("file-managed field not disabled:\n%s", body)
	}
}

func TestGeneralSaveAppliesLiveAndIsAudited(t *testing.T) {
	e, svc := newGeneralEnv(t, "")
	c := e.adminClient()
	result(c.get("/")).contains(t, `<time datetime="2026-10-21T09:01:02Z">09:01:02 UTC</time>`)
	rec := c.submit("/settings/general", "/settings/general", url.Values{"rev": {"0"},
		config.KeyTimeZone: {"America/New_York"}, config.KeySessionIdle: {"45"}, config.KeyTheme: {"nord"}})
	result(rec).status(t, http.StatusSeeOther).location(t, "/settings/general?done=general")
	if g := svc.Current().General; g.TimeZone != "America/New_York" || g.SessionIdle != 45*time.Minute || g.Theme != "nord" {
		t.Fatalf("not applied: %+v", g)
	}
	// The top bar clock follows the new default at once, with the zone abbreviation, and
	// keeps the UTC instant machine-readable.
	result(c.get("/settings/general?done=general")).status(t, http.StatusOK).contains(t,
		"Settings saved.", `<time datetime="2026-10-21T09:01:02Z">05:01:02 EDT</time>`, `data-palette="nord"`,
		"Saved by morgan on 2026-10-21 05:01:02 EDT.")
	rec2, ok := e.findAudit(settings.ActionGeneralUpdate, audit.ResultOK)
	if !ok || rec2.Principal != "morgan" || !strings.Contains(rec2.ParamsJSON, `"before":"UTC"`) ||
		!strings.Contains(rec2.ParamsJSON, `"after":"America/New_York"`) || !strings.Contains(rec2.ParamsJSON, `"after":"45 min"`) {
		t.Fatalf("audit row = %+v", rec2)
	}
	// Saving the same values again writes nothing.
	rec = c.submit("/settings/general", "/settings/general", url.Values{"rev": {"1"}, config.KeyTimeZone: {"America/New_York"}})
	result(rec).status(t, http.StatusSeeOther).location(t, "/settings/general?done=general-unchanged")
	// Since S3 the poll interval applies live: nothing is flagged as waiting for a restart.
	rec = c.submit("/settings/general", "/settings/general", url.Values{"rev": {"1"}, config.KeyPollInterval: {"120"}})
	result(rec).status(t, http.StatusSeeOther)
	result(c.get("/settings/general")).lacks(t, "applies after a restart", "Applies after a restart")
}

func TestGeneralRefusals(t *testing.T) {
	e, svc := newGeneralEnv(t, "ratelimit: { login_acct_per_hour: 12 }\n")
	c := e.adminClient()
	post := func(fields url.Values) *httpResult {
		return result(c.submit("/settings/general", "/settings/general", fields))
	}
	post(url.Values{"rev": {"0"}, config.KeyTimeZone: {"US/Eastern"}}).status(t, http.StatusUnprocessableEntity).
		contains(t, "Not saved:", "ui.time_zone", `aria-invalid="true"`)
	post(url.Values{"rev": {"0"}, config.KeySessionMax: {"48"}}).status(t, http.StatusUnprocessableEntity).
		contains(t, "auth.session_max")
	post(url.Values{"rev": {"0"}, config.KeyLoginAcctPerHour: {"15"}}).status(t, http.StatusForbidden).
		contains(t, "managed by config.yaml")
	post(url.Values{"rev": {"7"}, config.KeyTheme: {"nord"}}).status(t, http.StatusConflict).
		contains(t, "changed elsewhere")
	post(url.Values{"rev": {"x"}, config.KeyTheme: {"nord"}}).status(t, http.StatusBadRequest)
	if rows, _ := e.db.Settings().All(context.Background()); len(rows) != 0 {
		t.Fatalf("refused changes were written: %+v", rows)
	}
	if svc.Current().General.TimeZone != "UTC" {
		t.Fatal("refused change applied")
	}
	if rec, ok := e.findAudit(settings.ActionGeneralUpdate, audit.ResultDenied); !ok || rec.ErrorClass != "conflict" {
		t.Fatalf("conflict not audited: %+v", rec)
	}
	if !e.auditContains("locked") {
		t.Fatal("file-managed refusal not audited")
	}
}

func TestGeneralLockedSection(t *testing.T) {
	e, _ := newGeneralEnv(t, "settings: { locked: [general] }\n")
	c := e.adminClient()
	result(c.get("/settings/general")).status(t, http.StatusOK).contains(t, "locked by <code>settings.locked</code>").
		lacks(t, "Save settings")
	form := url.Values{csrfField: {e.csrfToken(c)}, "rev": {"0"}, config.KeyTheme: {"nord"}}
	result(c.do(http.MethodPost, "/settings/general", form)).status(t, http.StatusForbidden)
}

func TestGeneralNeedsStepUpAndAdmin(t *testing.T) {
	e, _ := newGeneralEnv(t, "")
	c := e.adminClient()
	e.clock.Advance(6 * time.Minute)
	form := url.Values{csrfField: {e.csrfToken(c)}, "rev": {"0"}, config.KeyTheme: {"nord"}}
	resumeFrom(t, result(c.do(http.MethodPost, "/settings/general", form)), "/settings/general")
	if rec, ok := e.findAudit(string(authz.AdminGeneralManage), audit.ResultDenied); !ok || rec.ErrorClass != "stepup_required" {
		t.Fatalf("stale step-up not audited: %+v", rec)
	}

	link, err := e.svc.CreateUser(context.Background(), actorFor(t, e, "morgan"), "victor", authz.RoleViewer)
	must(t, err)
	vc := e.client("192.0.2.20")
	vc.login("victor", e.enrolViaLink(link.Token, testPassword))
	result(vc.get("/settings/general")).status(t, http.StatusForbidden)
	vform := url.Values{csrfField: {e.csrfToken(vc)}, "rev": {"0"}, config.KeyTheme: {"nord"}}
	result(vc.do(http.MethodPost, "/settings/general", vform)).status(t, http.StatusForbidden)
}

func TestGeneralWithoutSettingsBackend(t *testing.T) {
	e := newSettingsEnv(t)
	c := e.adminClient()
	result(c.get("/settings/general")).status(t, http.StatusNotFound)
	result(c.get("/preferences")).status(t, http.StatusNotFound)
	form := url.Values{csrfField: {e.csrfToken(c)}, "rev": {"0"}}
	result(c.do(http.MethodPost, "/settings/general", form)).status(t, http.StatusNotFound)
}

func TestLoginRateLimitIsLive(t *testing.T) {
	e, svc := newGeneralEnv(t, "")
	c := e.adminClient()
	result(c.submit("/settings/general", "/settings/general", url.Values{"rev": {"0"},
		config.KeyLoginIPPerMin: {"1"}})).status(t, http.StatusSeeOther)
	if svc.Current().General.LoginIPPerMin != 1 {
		t.Fatal("not saved")
	}
	anon := e.client("192.0.2.77")
	try := func() int {
		page := anon.get("/login").Body.String()
		return anon.do(http.MethodPost, "/login", url.Values{"username": {"nobody"}, "password": {"wrong"},
			csrfField: {csrfFor(t, page, "/login")}}).Code
	}
	if code := try(); code != http.StatusUnauthorized {
		t.Fatalf("first attempt %d", code)
	}
	if code := try(); code != http.StatusTooManyRequests {
		t.Fatalf("second attempt within the minute = %d, want 429 (1/min)", code)
	}
}

func TestGeneralResetToDefault(t *testing.T) {
	e, svc := newGeneralEnv(t, "ratelimit: { login_acct_per_hour: 12 }\n")
	c := e.adminClient()
	// Nothing saved yet: no reset button anywhere.
	result(c.get("/settings/general")).status(t, http.StatusOK).lacks(t, "Reset to default")
	rec := c.submit("/settings/general", "/settings/general", url.Values{"rev": {"0"}, config.KeySessionIdle: {"45"}})
	result(rec).status(t, http.StatusSeeOther)
	page := result(c.get("/settings/general")).status(t, http.StatusOK).contains(t,
		`formaction="/settings/general/reset" name="reset" value="auth.session_idle"`, "Reset to default",
		"Default: 30 minutes.")
	if strings.Count(page.rec.Body.String(), "Reset to default</button>") != 1 {
		t.Fatalf("one reset button expected (only the saved key):\n%s", page.rec.Body.String())
	}
	reset := func(fields url.Values) *httpResult {
		fields.Set(csrfField, e.csrfToken(c))
		return result(c.do(http.MethodPost, "/settings/general/reset", fields))
	}
	reset(url.Values{"rev": {"1"}, "reset": {config.KeySessionIdle}}).status(t, http.StatusSeeOther).location(t, "/settings/general?done=general-reset")
	if g := svc.Current().General; g.SessionIdle != 30*time.Minute {
		t.Fatalf("not reset: %v", g.SessionIdle)
	}
	result(c.get("/settings/general?done=general-reset")).contains(t, "Setting reset to its default.").
		lacks(t, "Reset to default</button>")
	if rec, ok := e.findAudit(settings.ActionGeneralReset, audit.ResultOK); !ok || !strings.Contains(rec.ParamsJSON, `"after":"30 min"`) {
		t.Fatalf("reset audit = %+v", rec)
	}
	// Refusals: a file-managed key (403), a stale revision (409), an unknown key (400).
	reset(url.Values{"rev": {"2"}, "reset": {config.KeyLoginAcctPerHour}}).status(t, http.StatusForbidden)
	reset(url.Values{"rev": {"0"}, "reset": {config.KeyTheme}}).status(t, http.StatusSeeOther).
		location(t, "/settings/general?done=general-unchanged")
	reset(url.Values{"rev": {"2"}, "reset": {"gelf.address"}}).status(t, http.StatusBadRequest)
}

func TestGeneralResetNeedsStepUp(t *testing.T) {
	e, _ := newGeneralEnv(t, "")
	c := e.adminClient()
	result(c.submit("/settings/general", "/settings/general", url.Values{"rev": {"0"}, config.KeyTheme: {"nord"}})).
		status(t, http.StatusSeeOther)
	e.clock.Advance(6 * time.Minute)
	form := url.Values{csrfField: {e.csrfToken(c)}, "rev": {"1"}, "reset": {config.KeyTheme}}
	resumeFrom(t, result(c.do(http.MethodPost, "/settings/general/reset", form)), "/settings/general")
	if rows, _ := e.db.Settings().All(context.Background()); len(rows) != 1 {
		t.Fatalf("reset without step-up: %+v", rows)
	}
}

// The instance name is a General field (v0.9.1): saved from the form, it shows in the
// header at once; set in config.yaml it is locked.
func TestGeneralInstanceName(t *testing.T) {
	e, svc := newGeneralEnv(t, "")
	c := e.adminClient()
	result(c.get("/settings/general")).status(t, http.StatusOK).contains(t, `name="ui.instance_name" type="text" maxlength="64"`).
		lacks(t, `<span class="inst">`)
	rec := c.submit("/settings/general", "/settings/general", url.Values{"rev": {"0"}, config.KeyInstanceName: {"Rack A"}})
	result(rec).status(t, http.StatusSeeOther)
	if got := svc.Current().General.InstanceName; got != "Rack A" {
		t.Fatalf("instance name = %q", got)
	}
	result(c.get("/settings/general")).status(t, http.StatusOK).contains(t, `<span class="inst">Rack A</span>`, `value="Rack A"`)
	rec = c.submit("/settings/general", "/settings/general", url.Values{"rev": {"1"}, config.KeyInstanceName: {"<b>x</b>"}})
	result(rec).status(t, http.StatusUnprocessableEntity).contains(t, `id="g-ui-instance-name"`, `aria-invalid="true"`)

	locked, _ := newGeneralEnv(t, "ui: { instance_name: Homelab }\n")
	result(locked.adminClient().get("/settings/general")).status(t, http.StatusOK).
		contains(t, `<span class="inst">Homelab</span>`, "Set in config.yaml (ui.instance_name)")
}
