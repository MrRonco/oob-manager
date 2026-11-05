package ui

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
)

var userIDRE = regexp.MustCompile(`href="/settings/users/([0-9a-f]{32})">victor`)

// createVictor creates "victor" through the browser and returns the one-time link token.
func createVictor(t *testing.T, c *client, role string) string {
	t.Helper()
	rec := c.submit("/settings/users", "/settings/users", url.Values{"username": {"victor"}, "role": {role}})
	r := result(rec).status(t, http.StatusOK).contains(t, "User created", "Shown once", "valid until")
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("link page is cacheable")
	}
	m := linkRE.FindStringSubmatch(r.rec.Body.String())
	if m == nil {
		t.Fatalf("no enrolment link:\n%s", r.rec.Body)
	}
	return m[1]
}

func TestCreateUserLinkEnrolLogin(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	token := createVictor(t, c, "operator")
	if e.auditContains(token) {
		t.Fatal("enrolment link in the audit log")
	}
	result(c.get("/settings/users")).contains(t, "victor", "Enrollment pending", "operator")

	anon := e.client("192.0.2.30")
	page := result(anon.get("/enroll/"+token)).status(t, http.StatusOK)
	page.contains(t, "Set up your account", "victor", "New password").lacks(t, "Sign out")
	mismatch := url.Values{"password": {testPassword}, "confirm": {testPassword + "x"},
		csrfField: {csrfForAny(t, page.rec.Body.String(), "/enroll/"+token)}}
	result(anon.do(http.MethodPost, "/enroll/"+token, mismatch)).status(t, http.StatusBadRequest).
		contains(t, "do not match", `aria-invalid="true"`)
	short := url.Values{"password": {"short"}, "confirm": {"short"},
		csrfField: {csrfForAny(t, page.rec.Body.String(), "/enroll/"+token)}}
	result(anon.do(http.MethodPost, "/enroll/"+token, short)).status(t, http.StatusBadRequest).contains(t, "12 to 256")
	noCSRF := url.Values{"password": {testPassword}, "confirm": {testPassword}}
	result(anon.do(http.MethodPost, "/enroll/"+token, noCSRF)).status(t, http.StatusForbidden)

	secret := e.enrolViaLink(token, testPassword)
	result(e.client("192.0.2.31").get("/enroll/"+token)).status(t, http.StatusNotFound).contains(t, "already used")
	if rec, ok := e.findAudit("auth.enrol", audit.ResultOK); !ok || rec.Principal != "victor" {
		t.Fatalf("enrolment not audited: %+v", rec)
	}
	vc := e.client("192.0.2.32")
	vc.login("victor", secret)
	result(vc.get("/")).status(t, http.StatusOK).contains(t, "Signed in as <strong>victor</strong>")
	result(c.get("/settings/users")).contains(t, "Active")
	if e.auditContains(secret) || e.auditContains(testPassword) {
		t.Fatal("secret or password in the audit log")
	}
}

func TestCreateUserErrorsStayOnForm(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	result(c.submit("/settings/users", "/settings/users", url.Values{"username": {"Bad Name"}, "role": {"viewer"}})).
		status(t, http.StatusBadRequest).contains(t, "3-32 characters", `id="form-error"`)
	result(c.submit("/settings/users", "/settings/users", url.Values{"username": {"morgan"}, "role": {"viewer"}})).
		status(t, http.StatusConflict).contains(t, "already taken", `value="morgan"`)
	result(c.submit("/settings/users", "/settings/users", url.Values{"username": {"victor"}, "role": {"root"}})).
		status(t, http.StatusBadRequest).contains(t, "unknown role")
}

func TestUserManagement(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	token := createVictor(t, c, "viewer")
	secret := e.enrolViaLink(token, testPassword)
	m := userIDRE.FindStringSubmatch(c.get("/settings/users").Body.String())
	if m == nil {
		t.Fatal("no user link")
	}
	userPage := "/settings/users/" + m[1]
	vc := e.client("192.0.2.40")
	vc.login("victor", secret)

	result(c.get(userPage)).status(t, http.StatusOK).contains(t, "victor", "Change role", "End session", "192.0.2.40")
	result(c.submit(userPage, userPage+"/role", url.Values{"role": {"operator"}})).
		status(t, http.StatusSeeOther).location(t, userPage+"?done=role")
	result(c.get(userPage+"?done=role")).contains(t, "Role changed.", "Role operator")

	sid := regexp.MustCompile(`/sessions/([0-9a-f]{64})/revoke`).FindStringSubmatch(c.get(userPage).Body.String())
	if sid == nil {
		t.Fatal("no session revoke form")
	}
	result(c.submit(userPage+"/sessions/"+sid[1]+"/revoke", userPage+"/sessions/"+sid[1]+"/revoke", url.Values{"confirm": {"yes"}})).status(t, http.StatusSeeOther)
	result(vc.get("/")).status(t, http.StatusSeeOther).location(t, "/login")

	result(c.submit(userPage+"/disable", userPage+"/disable", url.Values{"confirm": {"yes"}})).status(t, http.StatusSeeOther).location(t, userPage+"?done=disabled")
	result(c.get(userPage)).contains(t, "Disabled", "Enable account")
	result(c.submit(userPage, userPage+"/enable", nil)).status(t, http.StatusSeeOther).location(t, userPage+"?done=enabled")

	vc.login("victor", secret)
	result(c.submit(userPage+"/sessions/revoke-all", userPage+"/sessions/revoke-all", url.Values{"confirm": {"yes"}})).status(t, http.StatusSeeOther).
		location(t, userPage+"?done=revoked-all")
	result(vc.get("/")).status(t, http.StatusSeeOther)
	reset := c.submit(userPage+"/reset-totp", userPage+"/reset-totp", url.Values{"confirm": {"yes"}, "typed": {"victor"}})
	result(reset).status(t, http.StatusOK).contains(t, "Authenticator reset", "/enroll/")
	if u, _ := e.db.Users().ByUsername(context.Background(), "victor"); u.TOTPConfirmed {
		t.Fatal("authenticator not reset")
	}
	for _, a := range []string{"admin.user.role", "admin.session.revoke", "admin.user.disable", "admin.user.enable",
		"admin.user.reset_totp", "admin.session.revoke_all"} {
		if _, ok := e.findAudit(a, audit.ResultOK); !ok {
			t.Errorf("%s not audited", a)
		}
	}
}

func TestSelfChangesAreRefused(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	u, err := e.db.Users().ByUsername(context.Background(), "morgan")
	must(t, err)
	self := "/settings/users/" + u.ID
	result(c.get(self)).status(t, http.StatusOK).contains(t, "You cannot change your own role").lacks(t, `/disable"`)
	// The guard holds even when the form is posted by hand.
	tok := e.csrfToken(c)
	result(c.do(http.MethodPost, self+"/role", url.Values{csrfField: {tok}, "role": {"viewer"}})).
		status(t, http.StatusConflict).contains(t, "last admin")
	result(c.do(http.MethodPost, self+"/disable", url.Values{csrfField: {tok}, "confirm": {"yes"}})).status(t, http.StatusConflict)
	if rec, ok := e.findAudit("admin.user.role", audit.ResultDenied); !ok || rec.ErrorClass != "refused" {
		t.Fatalf("refusal not audited: %+v", rec)
	}
	result(c.get("/settings/users/zz")).status(t, http.StatusNotFound)
	result(c.get("/settings/users/"+strings.Repeat("0", 32))).status(t, http.StatusNotFound)
	result(c.do(http.MethodPost, "/settings/users/"+strings.Repeat("0", 32)+"/role",
		url.Values{csrfField: {tok}, "role": {"viewer"}})).status(t, http.StatusNotFound)
}

func TestRevokingOwnSessionSignsOut(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	u, _ := e.db.Users().ByUsername(context.Background(), "morgan")
	self := "/settings/users/" + u.ID
	result(c.submit(self+"/sessions/revoke-all", self+"/sessions/revoke-all", url.Values{"confirm": {"yes"}})).status(t, http.StatusSeeOther).location(t, "/login")
}

func TestEnrolLinkInvalidAndRateLimited(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t, func(d *Deps) { d.LinkPerIP = RateLimit{Events: 2, Per: time.Hour} })
	anon := e.client("192.0.2.70")
	bogus, _ := auth.NewLinkToken()
	result(anon.get("/enroll/"+bogus)).status(t, http.StatusNotFound).contains(t, "Ask your administrator")
	if rec, ok := e.findAudit("auth.enrol", audit.ResultDenied); !ok || rec.ErrorClass != "invalid_link" {
		t.Fatalf("invalid link not audited: %+v", rec)
	}
	result(anon.get("/enroll/short")).status(t, http.StatusNotFound)
	rec := anon.get("/enroll/" + bogus)
	result(rec).status(t, http.StatusTooManyRequests)
	if e.auditContains(bogus) {
		t.Fatal("link token in the audit log")
	}
}

func TestAuditViewerAndVerify(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	_, err := e.deps.Audit.Record(context.Background(), audit.Entry{Principal: "system", Action: "app.start",
		Result: audit.ResultOK})
	must(t, err)
	c := e.adminClient()
	r := result(c.get("/settings/audit")).status(t, http.StatusOK)
	r.contains(t, "auth.login", "app.start", "Verify chain", `<option value="auth.login">`)
	result(c.get("/settings/audit?action=auth.login&result=ok&principal=morgan")).status(t, http.StatusOK).
		contains(t, `<span class="chip mono">auth.login</span>`, "morgan signed in").lacks(t, `<span class="chip mono">app.start</span>`)
	for _, q := range []string{"?action=DROP%20TABLE", "?result=maybe", "?before=-1", "?server=Bad%20ID", "?principal=a%20b"} {
		result(c.get("/settings/audit"+q)).status(t, http.StatusBadRequest)
	}
	result(c.submit("/settings/audit", "/settings/audit/verify", nil)).status(t, http.StatusOK).
		contains(t, "Chain intact.", "rows verified", "Head hash")
	if rec, ok := e.findAudit("admin.audit.verify", audit.ResultOK); !ok || !strings.Contains(rec.ParamsJSON, "head") {
		t.Fatalf("verify not audited: %+v", rec)
	}
	result(c.submit("/settings/audit", "/settings/audit/verify", nil)).status(t, http.StatusTooManyRequests)
}

func TestAuditViewerKeysetPaging(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	for i := range auditPageSize + 5 {
		_ = i
		_, err := e.deps.Audit.Record(context.Background(), audit.Entry{Principal: "system", Action: "app.tick",
			Result: audit.ResultOK})
		must(t, err)
	}
	page := result(c.get("/settings/audit?action=app.tick")).status(t, http.StatusOK)
	older := regexp.MustCompile(`href="(/settings/audit\?[^"]*before=\d+)"`).FindStringSubmatch(page.rec.Body.String())
	if older == nil {
		t.Fatal("no older link")
	}
	next := strings.ReplaceAll(older[1], "&amp;", "&")
	result(c.get(next)).status(t, http.StatusOK).contains(t, "Back to the newest").lacks(t, `rel="next"`)
}

func TestAboutPage(t *testing.T) {
	t.Parallel()
	e := newSettingsEnv(t)
	c := e.adminClient()
	result(c.get("/about")).status(t, http.StatusOK).
		contains(t, "1.2.3", "abc1234", "go1.27.3", "example.test/mod", "Apache License", "Report a problem",
			`aria-current="page">About`).lacks(t, "github.com")
	e2 := newSettingsEnv(t, func(d *Deps) { d.Build.RepoURL = "https://example.test/oob" })
	result(e2.adminClient().get("/about")).contains(t, `href="https://example.test/oob/issues"`, `href="https://example.test/oob"`)
	result(c.get("/")).contains(t, "v1.2.3 (abc1234)")
	result(e.client("192.0.2.99").get("/login")).lacks(t, "1.2.3")
}
