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

var tokenIDLine = regexp.MustCompile(`(?m)^([0-9a-f]{32})\s+dashboard\s`)

// checkCLITokens: a token minted by `token create` works against the API, appears in
// `token list` without its value, and is refused (401) once `token revoke` ran.
func checkCLITokens(t *testing.T, b browser, s *stack) {
	raw := s.cli(t, "token", "create", "--config", s.configPath, "--name", "dashboard", "--expires", "90d")
	if p := b.do(http.MethodGet, "/api/v1/servers", raw, nil); p.status != http.StatusOK {
		t.Fatalf("CLI token rejected: %d %s", p.status, p.body)
	}
	list := s.cli(t, "token", "list", "--config", s.configPath)
	m := tokenIDLine.FindStringSubmatch(list)
	if m == nil || strings.Contains(list, raw) || !strings.Contains(list, "active") {
		t.Fatalf("token list: %s", list)
	}
	s.cli(t, "token", "revoke", m[1], "--config", s.configPath)
	if p := b.do(http.MethodGet, "/api/v1/servers", raw, nil); p.status != http.StatusUnauthorized {
		t.Fatalf("revoked token: %d", p.status)
	}
	if p := b.do(http.MethodGet, "/api/v1/servers", s.token, nil); p.status != http.StatusOK {
		t.Fatalf("revoking one token affected another: %d", p.status)
	}
}

// checkResetTOTP runs on its own stack, because the flow needs five login/enrolment
// POSTs and the per-IP limit (5/min) is shared with the main test. reset-totp ends the
// live session and replaces the secret; the old secret stops working, the enrolment page
// confirms the new one, and login works with it.
func checkResetTOTP(t *testing.T) {
	s := startStack(t, "127.0.0.1:0")
	b := browser{t: t, base: s.base, c: s.client(t)}
	loginAt(t, b, s, time.Now())
	expectPage(t, b.get("/"), "Sign out")

	out := s.cli(t, "reset-totp", "--config", s.configPath, "--user", e2eUser)
	m := secretLine.FindStringSubmatch(out)
	if m == nil || m[1] == s.secret {
		t.Fatalf("reset-totp output: %s", out)
	}
	oldSecret, newSecret := s.secret, m[1]
	expectRedirect(t, b.get("/"), "/login")

	// Unconfirmed: the password alone no longer gets as far as the TOTP step.
	form := url.Values{"username": {e2eUser}, "password": {e2ePassword}, "csrf_token": {csrfFrom(t, b.get("/login"))}}
	if p := b.post("/login", form); p.status != http.StatusUnauthorized {
		t.Fatalf("login before confirming the new secret: %d", p.status)
	}
	if p := confirmEnrol(t, b, totpCode(t, oldSecret, time.Now().Add(30*time.Second))); p.status != http.StatusUnauthorized {
		t.Fatalf("the old secret on the enrolment page: %d", p.status)
	}
	// The new secret's previous step is accepted: the reset cleared the last-used step.
	clearOfStepEdge(10 * time.Second)
	if p := confirmEnrol(t, b, totpCode(t, newSecret, time.Now().Add(-30*time.Second))); p.status != http.StatusOK ||
		!strings.Contains(p.body, "Authenticator confirmed") {
		t.Fatalf("enrolment with the new secret: %d %s", p.status, p.body)
	}
	s.secret = newSecret
	loginAt(t, b, s, time.Now())
	expectPage(t, b.get("/"), "Sign out")
	if code := s.stop(); code != 0 {
		t.Fatalf("serve exit %d", code)
	}
	assertAudited(t, s.dbPath, "admin.totp_reset", "auth.totp.enroll", "auth.login")
	for _, leak := range []string{oldSecret, newSecret, e2ePassword} {
		if strings.Contains(s.errOut.String(), leak) {
			t.Fatal("a secret reached the application log")
		}
	}
}

func confirmEnrol(t *testing.T, b browser, code string) page {
	t.Helper()
	return b.post("/enroll", url.Values{"username": {e2eUser}, "password": {e2ePassword}, "code": {code},
		"csrf_token": {csrfFrom(t, b.get("/enroll"))}})
}

func loginAt(t *testing.T, b browser, s *stack, at time.Time) {
	t.Helper()
	form := url.Values{"username": {e2eUser}, "password": {e2ePassword}, "csrf_token": {csrfFrom(t, b.get("/login"))}}
	expectRedirect(t, b.post("/login", form), "/login/totp")
	code := url.Values{"code": {totpCode(t, s.secret, at)}, "csrf_token": {csrfFrom(t, b.get("/login/totp"))}}
	expectRedirect(t, b.post("/login/totp", code), "/")
}

// checkNoPSUTelemetry: the R240 fixture has no PSU telemetry but does report voltages.
func checkNoPSUTelemetry(t *testing.T, b browser) {
	p := b.get("/servers/r240/sensors")
	expectPage(t, p, "Not monitored by this server", "Voltage rails", "CPU1 VCORE VR", "0.18 V")
	if strings.Contains(p.body, "No power supplies reported.") {
		t.Error("R240 PSU table rendered as empty instead of not monitored")
	}
	expectPage(t, b.get("/servers/r730xd/sensors"), "Chassis power", "Voltage rails")
}
