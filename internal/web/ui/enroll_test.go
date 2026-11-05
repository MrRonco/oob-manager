package ui

import (
	"net/http"
	"net/url"
	"testing"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
)

func enrollForm(t *testing.T, c *client, user, code string) url.Values {
	t.Helper()
	tok := csrfFor(t, c.get("/enroll").Body.String(), "/enroll")
	return url.Values{"username": {user}, "password": {testPassword}, "code": {code}, csrfField: {tok}}
}

func TestEnrollConfirmThenLogin(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addUser("newbie", authz.RoleViewer, false)
	c := h.client("192.0.2.100")
	page := result(c.get("/enroll")).status(t, http.StatusOK)
	page.contains(t, "one-time setup link").lacks(t, `action="/enroll/reveal"`)
	result(c.do(http.MethodPost, "/enroll", enrollForm(t, c, "newbie", h.code(secret)))).
		status(t, http.StatusOK).contains(t, msgEnrolled, `action="/login"`)
	if e, ok := h.audit.find("auth.totp.enroll", audit.ResultOK); !ok || e.Principal != "newbie" {
		t.Fatalf("enrolment not audited: %+v", e)
	}
	c.login("newbie", secret)
}

func TestEnrollRejects(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.addUser("newbie", authz.RoleViewer, false)
	c := h.client("192.0.2.100")
	result(c.do(http.MethodPost, "/enroll", enrollForm(t, c, "newbie", "000000"))).
		status(t, http.StatusUnauthorized).contains(t, "Invalid username, password or code.", `value="newbie"`)
	if _, ok := h.audit.find("auth.totp.enroll", audit.ResultDenied); !ok {
		t.Fatal("failed enrolment not audited")
	}
	form := enrollForm(t, c, "newbie", "000000")
	form.Del(csrfField)
	result(c.do(http.MethodPost, "/enroll", form)).status(t, http.StatusForbidden)
	result(c.do(http.MethodPost, "/enroll/reveal", form)).status(t, http.StatusNotFound)
	bad := enrollForm(t, c, "<b>x</b>", "000000")
	result(c.do(http.MethodPost, "/enroll", bad)).status(t, http.StatusUnauthorized).lacks(t, "<b>x</b>", "&lt;b&gt;")
}

func TestEnrollRateLimited(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.addUser("newbie", authz.RoleViewer, false)
	c := h.client("192.0.2.100")
	for range 5 {
		c.do(http.MethodPost, "/enroll", enrollForm(t, c, "newbie", "000000"))
	}
	result(c.do(http.MethodPost, "/enroll", enrollForm(t, c, "newbie", "000000"))).
		status(t, http.StatusTooManyRequests)
}

func TestEnrollRevealShowsSecretOnce(t *testing.T) {
	t.Parallel()
	enr, err := auth.NewTOTPEnrollment("oob-manager", "newbie")
	must(t, err)
	h := newHarness(t, func(d *Deps) {
		d.Enroller = fakeEnroller{user: "newbie", pass: testPassword, enr: enr}
	})
	c := h.client("192.0.2.100")
	page := c.get("/enroll").Body.String()
	tok := csrfFor(t, page, "/enroll/reveal")
	form := url.Values{"username": {"newbie"}, "password": {testPassword}, csrfField: {tok}}
	result(c.do(http.MethodPost, "/enroll/reveal", form)).status(t, http.StatusOK).
		contains(t, enr.Secret, "data:image/png;base64,", `action="/enroll"`, `value="newbie"`)
	if _, ok := h.audit.find("auth.totp.reveal", audit.ResultOK); !ok {
		t.Fatal("reveal not audited")
	}
	for _, e := range h.audit.entries {
		if containsAny(e.Principal+e.ErrorClass+e.Action, enr.Secret) {
			t.Fatal("secret in audit entry")
		}
	}
	result(c.get("/enroll")).lacks(t, enr.Secret)
	form.Set("password", "wrong password here")
	form.Set(csrfField, csrfFor(t, c.get("/enroll").Body.String(), "/enroll/reveal"))
	result(c.do(http.MethodPost, "/enroll/reveal", form)).status(t, http.StatusUnauthorized).lacks(t, enr.Secret)
	form.Del(csrfField)
	result(c.do(http.MethodPost, "/enroll/reveal", form)).status(t, http.StatusForbidden)
}

func TestQRDataURLBadURI(t *testing.T) {
	t.Parallel()
	if got := qrDataURL("not a uri"); got != "" {
		t.Fatalf("qrDataURL(bad) = %q", got)
	}
}
