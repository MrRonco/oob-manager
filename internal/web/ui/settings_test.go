package ui

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
)

var (
	tokenRE = regexp.MustCompile(`value="(oobk_[A-Za-z0-9_-]{43})"`)
	linkRE  = regexp.MustCompile(`value="https://oob\.test/enroll/([A-Za-z0-9_-]{43})"`)
)

func TestSettingsNavAndAccessAreAdminOnly(t *testing.T) {
	e := newSettingsEnv(t)
	c := e.adminClient()
	result(c.get("/")).status(t, http.StatusOK).contains(t, `href="/settings"`)
	result(c.get("/settings")).status(t, http.StatusSeeOther).location(t, "/settings/users")
	result(c.get("/settings/users")).status(t, http.StatusOK).
		contains(t, "morgan", "(you)", "Step-up fresh until", `aria-current="page">Users`, `href="/settings" aria-current="page"`)

	link, err := e.svc.CreateUser(context.Background(), actorFor(t, e, "morgan"), "victor", authz.RoleViewer)
	must(t, err)
	viewer := e.enrolViaLink(link.Token, testPassword)
	vc := e.client("192.0.2.20")
	vc.login("victor", viewer)
	result(vc.get("/")).status(t, http.StatusOK).lacks(t, `href="/settings"`)
	for _, p := range []string{"/settings", "/settings/users", "/settings/tokens", "/settings/audit"} {
		result(vc.get(p)).status(t, http.StatusForbidden).contains(t, "Sign out")
	}
	if rec, ok := e.findAudit(string(authz.AdminUsers), audit.ResultDenied); !ok || rec.Principal != "victor" {
		t.Fatalf("viewer denial not audited: %+v", rec)
	}
	// A viewer's POST is refused even with a valid CSRF token of their own session.
	form := url.Values{csrfField: {e.csrfToken(vc)}, "name": {"x"}, "expires": {"0"}}
	result(vc.do(http.MethodPost, "/settings/tokens", form)).status(t, http.StatusForbidden)
	if rec, ok := e.findAudit(string(authz.AdminTokensManage), audit.ResultDenied); !ok || rec.ErrorClass != "forbidden" {
		t.Fatalf("viewer change not audited as forbidden: %+v", rec)
	}
}

func TestTokenCreateIsShownOnceThenRevoke(t *testing.T) {
	e := newSettingsEnv(t)
	c := e.adminClient()
	rec := c.submit("/settings/tokens", "/settings/tokens", url.Values{"name": {"dashboard"}, "expires": {"90"}})
	r := result(rec).status(t, http.StatusOK).contains(t, "Token created", "Shown once", "expires 2027-01-19")
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("reveal Cache-Control = %q", cc)
	}
	m := tokenRE.FindStringSubmatch(r.rec.Body.String())
	if m == nil {
		t.Fatalf("token not on the reveal page:\n%s", r.rec.Body)
	}
	raw := m[1]
	if _, _, err := e.tokens.Verify(context.Background(), raw); err != nil {
		t.Fatalf("shown token does not work: %v", err)
	}
	list := result(c.get("/settings/tokens")).status(t, http.StatusOK).contains(t, "dashboard", "Active").lacks(t, raw)
	id := regexp.MustCompile(`href="/settings/tokens/([0-9a-f]{32})/revoke"`).FindStringSubmatch(list.rec.Body.String())
	if id == nil {
		t.Fatal("no revoke link")
	}
	revoke := "/settings/tokens/" + id[1] + "/revoke"
	result(c.submit(revoke, revoke, url.Values{"confirm": {"yes"}, "typed": {"dashboard"}})).
		status(t, http.StatusSeeOther).location(t, "/settings/tokens?done=token-revoked")
	result(c.get("/settings/tokens?done=token-revoked")).contains(t, "Token revoked.", "Revoked")
	if _, _, err := e.tokens.Verify(context.Background(), raw); err == nil {
		t.Fatal("revoked token still works")
	}
	if _, ok := e.findAudit("token.create", audit.ResultOK); !ok {
		t.Fatal("token.create not audited")
	}
	if _, ok := e.findAudit("token.revoke", audit.ResultOK); !ok {
		t.Fatal("token.revoke not audited")
	}
	if e.auditContains(raw) {
		t.Fatal("raw token in the audit log")
	}
}

func TestTokenCreateValidation(t *testing.T) {
	e := newSettingsEnv(t)
	c := e.adminClient()
	result(c.submit("/settings/tokens", "/settings/tokens", url.Values{"name": {"x"}, "expires": {"3"}})).
		status(t, http.StatusBadRequest).contains(t, "Choose one of the offered lifetimes.", `value="x"`)
	result(c.submit("/settings/tokens", "/settings/tokens", url.Values{"name": {""}, "expires": {"0"}})).
		status(t, http.StatusBadRequest).contains(t, "token name")
}

func TestChangesNeedFreshStepUp(t *testing.T) {
	e := newSettingsEnv(t)
	c := e.adminClient()
	page := c.get("/settings/tokens").Body.String()
	e.clock.Advance(6 * time.Minute)
	form := url.Values{csrfField: {csrfForAny(t, page, "/settings/tokens")}, "name": {"late"}, "expires": {"0"}}
	resumeFrom(t, result(c.do(http.MethodPost, "/settings/tokens", form)), "/settings/tokens")
	if rec, ok := e.findAudit(string(authz.AdminTokensManage), audit.ResultDenied); !ok || rec.ErrorClass != "stepup_required" {
		t.Fatalf("missing step-up not audited: %+v", rec)
	}
	result(c.get("/settings/tokens")).contains(t, "Changes need a fresh code from your authenticator")
	step := result(c.get("/stepup?next=/settings/tokens")).status(t, http.StatusOK).contains(t, "Confirm it is you")
	bad := url.Values{csrfField: {csrfForAny(t, step.rec.Body.String(), "/stepup")}, "code": {"000000"},
		"next": {"/settings/tokens"}}
	result(c.do(http.MethodPost, "/stepup", bad)).status(t, http.StatusUnauthorized).contains(t, msgBadCode)
	old := c.jar[auth.SessionCookieName]
	result(c.submit("/stepup?next=/settings/tokens", "/stepup", url.Values{"code": {e.code(e.secret)},
		"next": {"/settings/tokens"}})).status(t, http.StatusSeeOther).location(t, "/settings/tokens")
	if c.jar[auth.SessionCookieName] == old {
		t.Fatal("session not rotated on step-up")
	}
	if _, ok := e.findAudit("auth.stepup", audit.ResultOK); !ok {
		t.Fatal("step-up not audited")
	}
	// The old form's token was bound to the old session: refused.
	result(c.do(http.MethodPost, "/settings/tokens", form)).status(t, http.StatusForbidden)
	result(c.submit("/settings/tokens", "/settings/tokens", url.Values{"name": {"late"}, "expires": {"0"}})).
		status(t, http.StatusOK).contains(t, "Token created")
}

func TestStepUpRedirectOnlyToLocalPaths(t *testing.T) {
	for in, want := range map[string]string{"/settings/users": "/settings/users", "https://evil.test/": "/x",
		"//evil.test": "/x", "/\\evil": "/x", "": "/x", "/a\nb": "/x", "settings": "/x"} {
		if got := localPath(in, "/x"); got != want {
			t.Errorf("localPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSettingsChangeRequiresCSRF(t *testing.T) {
	e := newSettingsEnv(t)
	c := e.adminClient()
	result(c.do(http.MethodPost, "/settings/users", url.Values{"username": {"mallory"}, "role": {"admin"}})).
		status(t, http.StatusForbidden)
	if _, err := e.db.Users().ByUsername(context.Background(), "mallory"); err == nil {
		t.Fatal("user created without a CSRF token")
	}
	if rec, ok := e.findAudit(string(authz.AdminUsersManage), audit.ResultDenied); !ok || rec.ErrorClass != "csrf" {
		t.Fatalf("CSRF refusal not audited: %+v", rec)
	}
}

func TestSettingsChangesAreRateLimited(t *testing.T) {
	e := newSettingsEnv(t, func(d *Deps) { d.ChangesPerUser = RateLimit{Events: 1, Per: time.Hour} })
	c := e.adminClient()
	result(c.submit("/settings/tokens", "/settings/tokens", url.Values{"name": {"a"}, "expires": {"0"}})).
		status(t, http.StatusOK)
	rec := c.submit("/settings/tokens", "/settings/tokens", url.Values{"name": {"b"}, "expires": {"0"}})
	result(rec).status(t, http.StatusTooManyRequests)
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After")
	}
}

func TestSettingsUnavailableWithoutBackend(t *testing.T) {
	_, c := signedInAdmin(t)
	result(c.get("/settings/users")).status(t, http.StatusNotFound)
	result(c.do(http.MethodPost, "/settings/users", url.Values{})).status(t, http.StatusNotFound)
	result(c.get("/enroll/abc")).status(t, http.StatusNotFound)
}

func signedInAdmin(t *testing.T) (*harness, *client) {
	t.Helper()
	h := newHarness(t)
	secret := h.addUser("boss", authz.RoleAdmin, true)
	c := h.client("192.0.2.100")
	c.login("boss", secret)
	return h, c
}

// csrfToken returns a Settings-form token for c's session (as a page would render).
func (h *harness) csrfToken(c *client) string {
	s := csrfSigner{key: h.deps.CSRFKey, ttl: DefaultCSRFTTL, now: h.clock.Now}
	return s.issue(formSettings, sessionBinding(c.jar[auth.SessionCookieName]))
}

func actorFor(t *testing.T, e *settingsEnv, name string) admin.Actor {
	t.Helper()
	u, err := e.db.Users().ByUsername(context.Background(), name)
	must(t, err)
	return admin.Actor{UserID: u.ID, Username: u.Username, Role: authz.Role(u.Role), Method: "local"}
}

// enrolViaLink drives the browser enrolment for a link and returns the new secret.
func (e *settingsEnv) enrolViaLink(token, password string) string {
	t := e.t
	t.Helper()
	anon := e.client("192.0.2.33")
	path := "/enroll/" + token
	rec := anon.submit(path, path, url.Values{"password": {password}, "confirm": {password}})
	r := result(rec).status(t, http.StatusOK).contains(t, "Scan your authenticator")
	secret := regexp.MustCompile(`data-secret="([A-Z2-7]{32})"`).FindStringSubmatch(r.rec.Body.String())
	if secret == nil {
		t.Fatalf("no secret on the reveal page:\n%s", r.rec.Body)
	}
	user := regexp.MustCompile(`id="c-username"[^>]*value="([a-z0-9._-]+)"`).FindStringSubmatch(r.rec.Body.String())
	if user == nil {
		t.Fatal("username not prefilled")
	}
	confirm := url.Values{"username": {user[1]}, "password": {password}, "code": {e.code(secret[1])},
		csrfField: {csrfForAny(t, r.rec.Body.String(), "/enroll")}}
	result(anon.do(http.MethodPost, "/enroll", confirm)).status(t, http.StatusOK).contains(t, msgEnrolled)
	return secret[1]
}
