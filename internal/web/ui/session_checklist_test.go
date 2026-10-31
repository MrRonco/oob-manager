package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
)

// Plan 06 §3.1 session fixation / CSRF checklist: one test per line that had none.
// Covered elsewhere: rotation on step-up (stepup tests), TOFU proof from another
// server's form (TestProofBoundToPurpose), CSRF on every POST (csrf_test.go), the
// cross-origin POST refusal (TestCrossOriginPostRejected), enrolment link single use.

// TestDemotedAdminLosesAccessOnNextRequest: role is read from the user row on every
// request, so a demotion applies at once (real store and admin service).
func TestDemotedAdminLosesAccessOnNextRequest(t *testing.T) {
	e := newSettingsEnv(t)
	link, err := e.svc.CreateUser(context.Background(), actorFor(t, e, "morgan"), "alice", authz.RoleAdmin)
	must(t, err)
	alice := e.client("192.0.2.60")
	alice.login("alice", e.enrolViaLink(link.Token, testPassword))
	result(alice.get("/settings/users")).status(t, http.StatusOK)
	must(t, e.svc.SetRole(context.Background(), actorFor(t, e, "morgan"), actorFor(t, e, "alice").UserID, authz.RoleViewer))
	result(alice.get("/settings/users")).status(t, http.StatusForbidden)
}

// TestDisabledUserSignedOutOnNextRequest: a disabled user's next request is refused
// (the browser is sent to sign in) and the session is gone.
func TestDisabledUserSignedOutOnNextRequest(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("morgan", authz.RoleViewer, true)
	c := h.client("192.0.2.61")
	c.login("morgan", secret)
	result(c.get("/")).status(t, http.StatusOK)
	must(t, h.users.update("id-morgan", func(u auth.User) auth.User { u.Disabled = true; return u }))
	result(c.get("/")).status(t, http.StatusSeeOther).location(t, "/login")
	result(c.get("/servers/r730xd")).status(t, http.StatusSeeOther).location(t, "/login")
	// Re-enabled, the old cookie is still refused: the session was deleted, not just
	// refused while the account was disabled.
	must(t, h.users.update("id-morgan", func(u auth.User) auth.User { u.Disabled = false; return u }))
	result(c.get("/")).status(t, http.StatusSeeOther).location(t, "/login")
}

// TestPlantedCookiesReplacedAtLogin: a session cookie planted before sign-in is never
// adopted (fixation), and the pre-session cookie is cleared once signed in, so nothing
// an attacker set before login survives it.
func TestPlantedCookiesReplacedAtLogin(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("morgan", authz.RoleViewer, true)
	c := h.client("192.0.2.62")
	planted := strings.Repeat("A", 43)
	c.jar[auth.SessionCookieName] = planted
	c.jar[preCookieName] = strings.Repeat("B", 43)
	c.login("morgan", secret)
	if got := c.jar[auth.SessionCookieName]; got == "" || got == planted {
		t.Fatalf("session cookie after login = %q (planted %q)", got, planted)
	}
	if _, ok := c.jar[preCookieName]; ok {
		t.Fatal("the pre-session cookie survived sign-in")
	}
	attacker := h.client("192.0.2.66")
	attacker.jar[auth.SessionCookieName] = planted
	result(attacker.get("/")).status(t, http.StatusSeeOther).location(t, "/login")
}

// TestPendingTokenRejectedAfterLogin: the real fixation case. The cookie handed out
// after the password stage (a pending session) is not the one that is signed in: once the
// code is accepted, a copy of the pending cookie is refused, end to end through the UI.
func TestPendingTokenRejectedAfterLogin(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("morgan", authz.RoleViewer, true)
	c := h.client("192.0.2.65")
	page := c.get("/login").Body.String()
	result(c.do(http.MethodPost, "/login", url.Values{"username": {"morgan"}, "password": {testPassword},
		csrfField: {csrfFor(t, page, "/login")}})).status(t, http.StatusSeeOther).location(t, "/login/totp")
	pending := c.jar[auth.SessionCookieName]
	if pending == "" {
		t.Fatal("no pending session cookie after the password stage")
	}
	page = c.get("/login/totp").Body.String()
	if !strings.Contains(page, "<strong>morgan</strong>") {
		t.Fatal("the TOTP page does not name the account (the refusal check below would be vacuous)")
	}
	result(c.do(http.MethodPost, "/login/totp", url.Values{"code": {h.code(secret)},
		csrfField: {csrfFor(t, page, "/login/totp")}})).status(t, http.StatusSeeOther).location(t, "/")
	if full := c.jar[auth.SessionCookieName]; full == "" || full == pending {
		t.Fatalf("signed-in cookie %q equals the pending one", full)
	}
	result(c.get("/")).status(t, http.StatusOK)
	copyCat := h.client("192.0.2.67")
	copyCat.jar[auth.SessionCookieName] = pending
	result(copyCat.get("/")).status(t, http.StatusSeeOther).location(t, "/login")
	result(copyCat.get("/login/totp")).lacks(t, "<strong>morgan</strong>")
}

// TestCookieReplayedAfterLogout: logout deletes the session server-side, so a copy of
// the cookie taken before logout is refused afterwards.
func TestCookieReplayedAfterLogout(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("morgan", authz.RoleViewer, true)
	c := h.client("192.0.2.63")
	c.login("morgan", secret)
	stolen := c.jar[auth.SessionCookieName]
	tok := csrfFor(t, c.get("/").Body.String(), "/logout")
	result(c.do(http.MethodPost, "/logout", url.Values{csrfField: {tok}})).status(t, http.StatusSeeOther)
	thief := h.client("192.0.2.64")
	thief.jar[auth.SessionCookieName] = stolen
	result(thief.get("/")).status(t, http.StatusSeeOther).location(t, "/login")
	result(thief.get("/settings/users")).status(t, http.StatusSeeOther).location(t, "/login")
}

// TestConsoleWebSocketOriginPortMismatch: the same host on another port is a foreign
// origin for the console upgrade.
func TestConsoleWebSocketOriginPortMismatch(t *testing.T) {
	h, c, _, _ := consoleHarness(t, authz.RoleAdmin)
	srv := httptest.NewServer(h.handler)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	must(t, err)
	other := "http://" + u.Hostname() + ":1"
	if other == srv.URL {
		other = "http://" + u.Hostname() + ":2"
	}
	if _, code, err := wsDial(t, srv, "/servers/r730xd/console/ws?ticket=t", c.jar[auth.SessionCookieName], other); err == nil || code != http.StatusForbidden {
		t.Fatalf("origin %s: code %d err %v, want 403", other, code, err)
	}
}
