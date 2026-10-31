package ui

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
)

func postLogin(c *client, user, pass string) *httpResult {
	page := c.get("/login").Body.String()
	return result(c.do(http.MethodPost, "/login", url.Values{"username": {user}, "password": {pass},
		csrfField: {csrfFor(c.h.t, page, "/login")}}))
}

func TestLoginFlowEndToEnd(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("morgan", authz.RoleAdmin, true)
	c := h.client("192.0.2.100")
	c.login("morgan", secret)
	if _, ok := c.jar[auth.SessionCookieName]; !ok {
		t.Fatal("no session cookie after login")
	}
	rec := c.get("/")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Storage node R730XD") {
		t.Fatalf("overview after login: %d\n%s", rec.Code, rec.Body)
	}
	e, ok := h.audit.find("auth.login", audit.ResultOK)
	if !ok || e.Principal != "morgan" || e.Role != "admin" || e.SrcIP != "192.0.2.100" {
		t.Fatalf("login not audited correctly: %+v", e)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	h := newHarness(t)
	h.addUser("morgan", authz.RoleAdmin, true)
	c := h.client("192.0.2.100")
	r := postLogin(c, "morgan", "wrong password here")
	r.status(t, http.StatusUnauthorized).contains(t, msgBadLogin)
	if _, ok := c.jar[auth.SessionCookieName]; ok {
		t.Fatal("session cookie set after a failed login")
	}
	if e, ok := h.audit.find("auth.login", audit.ResultDenied); !ok || e.Principal != anonymous {
		t.Fatalf("failure not audited as anonymous: %+v", e)
	}
	for _, e := range h.audit.entries {
		if strings.Contains(e.Principal+e.ErrorClass, "wrong password") {
			t.Fatal("typed credentials reached the audit log")
		}
	}
}

func TestLoginUnconfirmedTOTPRefused(t *testing.T) {
	h := newHarness(t)
	h.addUser("newbie", authz.RoleViewer, false)
	postLogin(h.client("192.0.2.5"), "newbie", testPassword).status(t, http.StatusUnauthorized)
}

func TestLoginCSRFRejected(t *testing.T) {
	h := newHarness(t)
	h.addUser("morgan", authz.RoleAdmin, true)
	c := h.client("192.0.2.100")
	c.get("/login")
	form := url.Values{"username": {"morgan"}, "password": {testPassword}}
	result(c.do(http.MethodPost, "/login", form)).status(t, http.StatusForbidden).contains(t, msgFormExpired)

	other := h.client("192.0.2.101")
	stolen := csrfFor(t, other.get("/login").Body.String(), "/login")
	form.Set(csrfField, stolen)
	result(c.do(http.MethodPost, "/login", form)).status(t, http.StatusForbidden)

	noCookie := h.client("192.0.2.102")
	result(noCookie.do(http.MethodPost, "/login", form)).status(t, http.StatusForbidden)
	if n := h.sessions.count(); n != 0 {
		t.Fatalf("%d sessions created despite CSRF failure", n)
	}
	if _, ok := h.audit.find("auth.login", audit.ResultDenied); !ok {
		t.Fatal("CSRF failure not audited")
	}
}

func TestTOTPCSRFBoundToSession(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("morgan", authz.RoleAdmin, true)
	a, b := h.client("192.0.2.100"), h.client("192.0.2.101")
	postLogin(a, "morgan", testPassword).status(t, http.StatusSeeOther)
	postLogin(b, "morgan", testPassword).status(t, http.StatusSeeOther)
	tokB := csrfFor(t, b.get("/login/totp").Body.String(), "/login/totp")
	rec := a.do(http.MethodPost, "/login/totp", url.Values{"code": {h.code(secret)}, csrfField: {tokB}})
	result(rec).status(t, http.StatusForbidden)
	result(a.do(http.MethodPost, "/login/totp", url.Values{"code": {h.code(secret)}})).status(t, http.StatusForbidden)
}

func TestTOTPWrongCode(t *testing.T) {
	h := newHarness(t)
	h.addUser("morgan", authz.RoleAdmin, true)
	c := h.client("192.0.2.100")
	postLogin(c, "morgan", testPassword).status(t, http.StatusSeeOther)
	tok := csrfFor(t, c.get("/login/totp").Body.String(), "/login/totp")
	result(c.do(http.MethodPost, "/login/totp", url.Values{"code": {"000000"}, csrfField: {tok}})).
		status(t, http.StatusUnauthorized).contains(t, msgBadCode)
}

func TestTOTPPendingExpired(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("morgan", authz.RoleAdmin, true)
	c := h.client("192.0.2.100")
	postLogin(c, "morgan", testPassword).status(t, http.StatusSeeOther)
	tok := csrfFor(t, c.get("/login/totp").Body.String(), "/login/totp")
	h.clock.Advance(auth.DefaultPendingTTL + time.Minute)
	result(c.do(http.MethodPost, "/login/totp", url.Values{"code": {h.code(secret)}, csrfField: {tok}})).
		status(t, http.StatusUnauthorized).contains(t, msgExpired)
	if _, ok := c.jar[auth.SessionCookieName]; ok {
		t.Fatal("expired pending cookie not cleared")
	}
}

func TestTOTPPageRedirects(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("morgan", authz.RoleAdmin, true)
	c := h.client("192.0.2.100")
	result(c.get("/login/totp")).status(t, http.StatusSeeOther).location(t, "/login")
	result(c.do(http.MethodPost, "/login/totp", url.Values{})).status(t, http.StatusSeeOther).location(t, "/login")
	c.login("morgan", secret)
	result(c.get("/login/totp")).status(t, http.StatusSeeOther).location(t, "/")
	result(c.get("/login")).status(t, http.StatusSeeOther).location(t, "/")
}

func TestLoginRateLimitPerIP(t *testing.T) {
	h := newHarness(t)
	h.addUser("morgan", authz.RoleAdmin, true)
	c := h.client("192.0.2.66")
	for i := range 5 {
		r := postLogin(c, "user"+strconv.Itoa(i), "wrong password here")
		r.status(t, http.StatusUnauthorized)
	}
	r := postLogin(c, "user9", "wrong password here")
	r.status(t, http.StatusTooManyRequests).contains(t, msgRateLimited)
	if ra, err := strconv.Atoi(r.rec.Header().Get("Retry-After")); err != nil || ra < 1 || ra > 12 {
		t.Fatalf("Retry-After = %q", r.rec.Header().Get("Retry-After"))
	}
	postLogin(h.client("192.0.2.67"), "morgan", testPassword).status(t, http.StatusSeeOther)
	h.clock.Advance(12 * time.Second)
	postLogin(c, "morgan", testPassword).status(t, http.StatusSeeOther)
	if _, ok := h.audit.find("auth.login", audit.ResultDenied); !ok {
		t.Fatal("rate limit not audited")
	}
}

func TestLoginRateLimitPerAccount(t *testing.T) {
	h := newHarness(t)
	h.addUser("morgan", authz.RoleAdmin, true)
	for i := range 10 {
		postLogin(h.client("198.51.100."+strconv.Itoa(i)), "morgan", testPassword).status(t, http.StatusSeeOther)
	}
	postLogin(h.client("198.51.100.99"), "morgan", testPassword).
		status(t, http.StatusTooManyRequests).contains(t, msgRateLimited)
}

func TestTOTPRateLimit(t *testing.T) {
	h := newHarness(t, func(d *Deps) { d.LoginPerIP = RateLimit{Events: 2, Per: time.Minute} })
	h.addUser("morgan", authz.RoleAdmin, true)
	c := h.client("192.0.2.100")
	postLogin(c, "morgan", testPassword).status(t, http.StatusSeeOther)
	for range 2 {
		tok := csrfFor(t, c.get("/login/totp").Body.String(), "/login/totp")
		result(c.do(http.MethodPost, "/login/totp", url.Values{"code": {"000000"}, csrfField: {tok}})).
			status(t, http.StatusUnauthorized)
	}
	tok := csrfFor(t, c.get("/login/totp").Body.String(), "/login/totp")
	result(c.do(http.MethodPost, "/login/totp", url.Values{"code": {"000000"}, csrfField: {tok}})).
		status(t, http.StatusTooManyRequests)
}

func TestAccountLockoutShowsRetryAfter(t *testing.T) {
	h := newHarness(t)
	h.addUser("morgan", authz.RoleAdmin, true)
	var last *httpResult
	for i := range 6 {
		last = postLogin(h.client("203.0.113."+strconv.Itoa(i)), "morgan", "wrong password here")
	}
	last.status(t, http.StatusTooManyRequests).contains(t, msgLockedOut)
	if last.rec.Header().Get("Retry-After") == "" {
		t.Fatal("no Retry-After on lockout")
	}
}

func TestLogout(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("morgan", authz.RoleViewer, true)
	c := h.client("192.0.2.100")
	c.login("morgan", secret)
	tok := csrfFor(t, c.get("/").Body.String(), "/logout")
	result(c.do(http.MethodPost, "/logout", url.Values{csrfField: {tok}})).
		status(t, http.StatusSeeOther).location(t, "/login")
	if n := h.sessions.count(); n != 0 {
		t.Fatalf("%d sessions left after logout", n)
	}
	result(c.get("/")).status(t, http.StatusSeeOther).location(t, "/login")
	if e, ok := h.audit.find("auth.logout", audit.ResultOK); !ok || e.Principal != "morgan" {
		t.Fatalf("logout not audited: %+v", e)
	}
	result(h.client("192.0.2.9").do(http.MethodPost, "/logout", url.Values{})).status(t, http.StatusSeeOther)
}

func TestLogoutNeedsCSRF(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("morgan", authz.RoleViewer, true)
	c := h.client("192.0.2.100")
	c.login("morgan", secret)
	result(c.do(http.MethodPost, "/logout", url.Values{})).status(t, http.StatusForbidden)
	result(c.get("/")).status(t, http.StatusOK)
}

func TestCrossOriginPostRejected(t *testing.T) {
	h := newHarness(t)
	h.addUser("morgan", authz.RoleAdmin, true)
	c := h.client("192.0.2.100")
	page := c.get("/login").Body.String()
	form := url.Values{"username": {"morgan"}, "password": {testPassword}, csrfField: {csrfFor(t, page, "/login")}}
	rec := c.do(http.MethodPost, "/login", form, "Sec-Fetch-Site", "cross-site")
	result(rec).status(t, http.StatusForbidden)
	if n := h.sessions.count(); n != 0 {
		t.Fatal("cross-origin login created a session")
	}
}

func TestAuditFailureBlocksLogin(t *testing.T) {
	h := newHarness(t)
	secret := h.addUser("morgan", authz.RoleAdmin, true)
	c := h.client("192.0.2.100")
	postLogin(c, "morgan", testPassword).status(t, http.StatusSeeOther)
	tok := csrfFor(t, c.get("/login/totp").Body.String(), "/login/totp")
	h.audit.setFail(true)
	result(c.do(http.MethodPost, "/login/totp", url.Values{"code": {h.code(secret)}, csrfField: {tok}})).
		status(t, http.StatusInternalServerError).contains(t, msgUnavailable)
	if n := h.sessions.count(); n != 0 {
		t.Fatalf("%d sessions survive an unaudited login", n)
	}
}

func TestMalformedFormBody(t *testing.T) {
	h := newHarness(t)
	c := h.client("192.0.2.100")
	big := url.Values{"username": {strings.Repeat("a", maxFormBytes+10)}}
	for _, path := range []string{"/login", "/login/totp", "/enroll"} {
		if path == "/login/totp" {
			c.jar[auth.SessionCookieName] = "x"
		}
		result(c.do(http.MethodPost, path, big)).status(t, http.StatusBadRequest)
	}
}
