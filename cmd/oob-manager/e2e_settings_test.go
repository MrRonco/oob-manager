//go:build e2e

package main

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	e2eTokenRE  = regexp.MustCompile(`value="(oobk_[A-Za-z0-9_-]{43})"`)
	e2eLinkRE   = regexp.MustCompile(`value="https://[^"]+/enroll/([A-Za-z0-9_-]{43})"`)
	e2eSecretRE = regexp.MustCompile(`data-secret="([A-Z2-7]{32})"`)
)

const e2eNewUser, e2eNewPassword = "victor", "victor's e2e password" //nolint:gosec // G101: throwaway e2e test password

// formCSRF is the CSRF token of the form posting to action on p.
func formCSRF(t *testing.T, p page, action string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)action="` + regexp.QuoteMeta(action) + `"[^>]*>.*?name="csrf_token" value="([^"]+)"`)
	m := re.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no form posting to %s (%d)", action, p.status)
	}
	return m[1]
}

// submit loads from, then posts the form for action with fields.
func (b browser) submit(from, action string, fields url.Values) page {
	b.t.Helper()
	form := url.Values{"csrf_token": {formCSRF(b.t, b.get(from), action)}}
	for k, v := range fields {
		form[k] = v
	}
	return b.post(action, form)
}

// checkSettings drives slice S1 through the real stack: API token shown once, used and
// revoked; a user invited by link who enrols and signs in; the audit chain verified.
// It runs inside the admin's session (the login code counts as the step-up).
func checkSettings(t *testing.T, b browser, s *stack) {
	expectPage(t, b.get("/settings/users"), "Users", "Step-up fresh until")

	reveal := b.submit("/settings/tokens", "/settings/tokens", url.Values{"name": {"e2e-ui"}, "expires": {"30"}})
	expectPage(t, reveal, "Token created", "Shown once")
	if reveal.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("token page Cache-Control %q", reveal.header.Get("Cache-Control"))
	}
	raw := e2eTokenRE.FindStringSubmatch(reveal.body)
	if raw == nil {
		t.Fatal("token not shown")
	}
	if p := b.do(http.MethodGet, "/api/v1/servers", raw[1], nil); p.status != http.StatusOK {
		t.Fatalf("UI token rejected by the API: %d", p.status)
	}
	list := b.get("/settings/tokens")
	if strings.Contains(list.body, raw[1]) {
		t.Fatal("token shown a second time")
	}
	id := regexp.MustCompile(`(?s)>e2e-ui <.*?href="(/settings/tokens/[0-9a-f]{32}/revoke)"`).FindStringSubmatch(list.body)
	if id == nil {
		t.Fatal("no revoke link")
	}
	// The token was just used, so its confirm page asks for the typed name (UX-06).
	expectPage(t, b.get(id[1]), "Revoke token e2e-ui?", "Type <code>e2e-ui</code> to confirm")
	expectRedirect(t, b.submit(id[1], id[1], url.Values{"confirm": {"yes"}, "typed": {"e2e-ui"}}), "/settings/tokens?done=token-revoked")
	if p := b.do(http.MethodGet, "/api/v1/servers", raw[1], nil); p.status != http.StatusUnauthorized {
		t.Fatalf("revoked UI token still accepted: %d", p.status)
	}
	s.uiToken = raw[1]

	checkInviteAndEnrol(t, b, s)

	verify := b.submit("/settings/audit", "/settings/audit/verify", nil)
	expectPage(t, verify, "Chain intact.", "Head hash")
}

func checkInviteAndEnrol(t *testing.T, b browser, s *stack) {
	created := b.submit("/settings/users", "/settings/users", url.Values{"username": {e2eNewUser}, "role": {"viewer"}})
	expectPage(t, created, "User created")
	link := e2eLinkRE.FindStringSubmatch(created.body)
	if link == nil {
		t.Fatal("no enrolment link shown")
	}
	anon := browser{t: t, base: s.base, c: s.client(t)}
	path := "/enroll/" + link[1]
	revealed := anon.submit(path, path, url.Values{"password": {e2eNewPassword}, "confirm": {e2eNewPassword}})
	expectPage(t, revealed, "Scan your authenticator")
	secret := e2eSecretRE.FindStringSubmatch(revealed.body)
	if secret == nil {
		t.Fatal("no TOTP secret shown")
	}
	s.newSecret = secret[1]
	confirm := url.Values{"username": {e2eNewUser}, "password": {e2eNewPassword},
		"code": {totpCode(t, secret[1], time.Now())}, "csrf_token": {formCSRF(t, revealed, "/enroll")}}
	expectPage(t, anon.post("/enroll", confirm), "Authenticator confirmed")
	if p := anon.get(path); p.status != http.StatusNotFound {
		t.Fatalf("used link still works: %d", p.status)
	}
	// Sign in as the new user with the next step's code (the confirmation used this one).
	form := url.Values{"username": {e2eNewUser}, "password": {e2eNewPassword}, "csrf_token": {csrfFrom(t, anon.get("/login"))}}
	expectRedirect(t, anon.post("/login", form), "/login/totp")
	code := url.Values{"code": {totpCode(t, secret[1], time.Now().Add(30*time.Second))},
		"csrf_token": {csrfFrom(t, anon.get("/login/totp"))}}
	expectRedirect(t, anon.post("/login/totp", code), "/")
	s.viewer = anon.c
	overview := anon.get("/")
	expectPage(t, overview, "Signed in as <strong>victor</strong>")
	if strings.Contains(overview.body, `href="/settings"`) {
		t.Fatal("viewer sees Settings")
	}
	if p := anon.get("/settings/users"); p.status != http.StatusForbidden {
		t.Fatalf("viewer reached Settings: %d", p.status)
	}
}
