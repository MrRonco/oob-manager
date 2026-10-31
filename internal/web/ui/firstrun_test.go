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
	"oob-manager/internal/authz"
	"oob-manager/internal/firstrun"
)

// firstRunHarness is a harness with no account and a live setup code.
func firstRunHarness(t *testing.T, notice *firstrun.Notice) (*harness, string) {
	t.Helper()
	setup, code, err := firstrun.NewSetup(time.Now, time.Hour)
	must(t, err)
	svc := &firstrun.Service{Setup: setup, Notice: notice}
	h := newHarness(t, func(d *Deps) { d.FirstRun = svc })
	svc.Users = func(context.Context) (int, error) {
		h.users.mu.Lock()
		defer h.users.mu.Unlock()
		return len(h.users.byID), nil
	}
	svc.Bootstrap = h.authn.BootstrapAdmin
	return h, code
}

func setupForm(t *testing.T, c *client, code, user, pw, confirm string) url.Values {
	t.Helper()
	tok := csrfFor(t, c.get("/setup").Body.String(), "/setup")
	return url.Values{"code": {code}, "username": {user}, "password": {pw}, "confirm": {confirm}, csrfField: {tok}}
}

var secretAttr = regexp.MustCompile(`data-secret="([A-Z2-7]+)"`)

func TestSetupCreatesTheFirstAdminThenCloses(t *testing.T) {
	h, code := firstRunHarness(t, nil)
	c := h.client("192.0.2.100")
	result(c.get("/login")).status(t, http.StatusOK).contains(t, `href="/setup"`)
	page := result(c.get("/setup")).status(t, http.StatusOK)
	page.contains(t, "Setup code", `action="/setup"`).lacks(t, code)

	rec := c.do(http.MethodPost, "/setup", setupForm(t, c, strings.ToLower(code), "owner", testPassword, testPassword))
	body := result(rec).status(t, http.StatusOK).contains(t, "Scan your authenticator", `action="/enroll"`, `value="owner"`)
	body.lacks(t, code)
	m := secretAttr.FindStringSubmatch(rec.Body.String())
	if m == nil {
		t.Fatal("no secret on the reveal page")
	}
	if e, ok := h.audit.find("setup.claim", audit.ResultOK); !ok || e.Principal != "owner" {
		t.Fatalf("setup not audited: %+v", e)
	}
	for _, e := range h.audit.entries {
		if containsAny(e.Principal+e.ErrorClass+e.Action, code, m[1]) {
			t.Fatal("setup code or secret in an audit entry")
		}
	}
	result(c.do(http.MethodPost, "/enroll", enrollForm(t, c, "owner", h.code(m[1])))).
		status(t, http.StatusOK).contains(t, msgEnrolled)
	c.login("owner", m[1])

	result(c.get("/setup")).status(t, http.StatusNotFound)
	other := h.client("192.0.2.101")
	result(other.get("/login")).lacks(t, `href="/setup"`)
	result(other.do(http.MethodPost, "/setup", url.Values{"code": {code}})).status(t, http.StatusNotFound)
	u, err := h.users.GetByUsername(context.Background(), "owner")
	must(t, err)
	if u.Role != authz.RoleAdmin {
		t.Errorf("role %q, want admin", u.Role)
	}
}

func TestSetupRejects(t *testing.T) {
	h, code := firstRunHarness(t, nil)
	c := h.client("192.0.2.100")
	result(c.do(http.MethodPost, "/setup", setupForm(t, c, "AAAA-BBBB-CCCC", "owner", testPassword, testPassword))).
		status(t, http.StatusUnauthorized).contains(t, "setup code is not valid", `value="owner"`)
	if e, ok := h.audit.find("setup.claim", audit.ResultDenied); !ok || e.ErrorClass != "bad_code" {
		t.Fatalf("bad code not audited: %+v", e)
	}
	result(c.do(http.MethodPost, "/setup", setupForm(t, c, code, "owner", testPassword, "different password!"))).
		status(t, http.StatusBadRequest).contains(t, "do not match")
	result(c.do(http.MethodPost, "/setup", setupForm(t, c, code, "Owner!", testPassword, testPassword))).
		status(t, http.StatusBadRequest).contains(t, "lowercase").lacks(t, "Owner!")
	form := setupForm(t, c, code, "owner", testPassword, testPassword)
	form.Set(csrfField, "forged")
	result(c.do(http.MethodPost, "/setup", form)).status(t, http.StatusForbidden)
	if len(h.users.byID) != 0 {
		t.Fatal("an account was created by a rejected request")
	}
	// The code still works after those failures.
	result(c.do(http.MethodPost, "/setup", setupForm(t, c, code, "owner", testPassword, testPassword))).
		status(t, http.StatusOK)
}

func TestSetupRateLimited(t *testing.T) {
	h, _ := firstRunHarness(t, nil)
	c := h.client("192.0.2.100")
	for range 5 {
		c.do(http.MethodPost, "/setup", setupForm(t, c, "WRONG", "owner", testPassword, testPassword))
	}
	result(c.do(http.MethodPost, "/setup", setupForm(t, c, "WRONG", "owner", testPassword, testPassword))).
		status(t, http.StatusTooManyRequests)
}

// Behind a userland proxy every client can share one address: a flood of rate-limited
// /setup requests must write one audit row per window, not one per request (plan 09 N1).
// The limiter itself still refuses every request over the limit.
func TestSetupRateLimitedAuditsOncePerWindow(t *testing.T) {
	h, _ := firstRunHarness(t, nil)
	c := h.client("192.0.2.100")
	flood := func(n int) {
		for range n {
			c.do(http.MethodPost, "/setup", setupForm(t, c, "WRONG", "owner", testPassword, testPassword))
		}
	}
	flood(5)
	for range 10 {
		result(c.do(http.MethodPost, "/setup", setupForm(t, c, "WRONG", "owner", testPassword, testPassword))).
			status(t, http.StatusTooManyRequests)
	}
	if n := h.audit.countDenied("setup.claim", "rate_limited"); n != 1 {
		t.Fatalf("rate-limited setup audited %d times in one window, want 1", n)
	}
	// Another address is limited on its own and audited on its own.
	other := h.client("192.0.2.101")
	for range 7 {
		other.do(http.MethodPost, "/setup", setupForm(t, other, "WRONG", "owner", testPassword, testPassword))
	}
	if n := h.audit.countDenied("setup.claim", "rate_limited"); n != 2 {
		t.Fatalf("second address: %d rate-limited rows, want 2", n)
	}
	// The next window audits the first refusal again.
	h.clock.Advance(setupRate.Per + time.Second)
	flood(5)
	result(c.do(http.MethodPost, "/setup", setupForm(t, c, "WRONG", "owner", testPassword, testPassword))).
		status(t, http.StatusTooManyRequests)
	if n := h.audit.countDenied("setup.claim", "rate_limited"); n != 3 {
		t.Fatalf("next window: %d rate-limited rows, want 3", n)
	}
	if n := h.audit.countDenied("setup.claim", "bad_code"); n != 15 {
		t.Fatalf("every allowed wrong code is still audited: %d, want 15", n)
	}
}

// countDenied counts the denied entries for action with class.
func (f *fakeAudit) countDenied(action, class string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, e := range f.entries {
		if e.Action == action && e.Result == audit.ResultDenied && e.ErrorClass == class {
			n++
		}
	}
	return n
}

// /setup has its own per-IP bucket: a flood of wrong setup codes for "admin" must not
// charge the sign-in buckets, and failed sign-ins must not block the administrator's real claim.
func TestSetupBucketIsSeparateFromSignIn(t *testing.T) {
	h, _ := firstRunHarness(t, nil)
	c := h.client("192.0.2.100")
	for range 8 {
		c.do(http.MethodPost, "/setup", setupForm(t, c, "WRONG", "admin", testPassword, testPassword))
	}
	// Sign-in from the same address, for the same name, is refused for the password (no
	// account), not for the rate limit.
	postLogin(c, "admin", "wrong password here").status(t, http.StatusUnauthorized)

	h2, code2 := firstRunHarness(t, nil)
	c2 := h2.client("192.0.2.101")
	for range 8 {
		postLogin(c2, "owner", "wrong password here")
	}
	postLogin(c2, "owner", "wrong password here").status(t, http.StatusTooManyRequests)
	result(c2.do(http.MethodPost, "/setup", setupForm(t, c2, code2, "owner", testPassword, testPassword))).
		status(t, http.StatusOK).contains(t, "Scan your authenticator")
}

// The acknowledgement is audited or not done: with the audit store down, the notice stays.
func TestKeyBackupNoticeNeedsTheAudit(t *testing.T) {
	data := t.TempDir()
	if _, err := firstrun.EnsureKeys(data, func() (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	n := firstrun.NewNotice(data)
	h, _ := firstRunHarness(t, &n)
	secret := h.addUser("owner", authz.RoleAdmin, true)
	a := h.client("192.0.2.100")
	a.login("owner", secret)
	tok := csrfFor(t, a.get("/").Body.String(), "/keys/backup-notice")
	h.audit.mu.Lock()
	h.audit.fail = true
	h.audit.mu.Unlock()
	result(a.do(http.MethodPost, "/keys/backup-notice", url.Values{csrfField: {tok}, "next": {"/"}})).
		status(t, http.StatusInternalServerError)
	if !n.Pending() {
		t.Fatal("the notice was dismissed without an audit row")
	}
}

func TestSetupAbsentWithoutFirstRun(t *testing.T) {
	h := newHarness(t)
	c := h.client("192.0.2.100")
	result(c.get("/setup")).status(t, http.StatusNotFound)
	result(c.get("/login")).lacks(t, `href="/setup"`)
}

func TestSetupClosedWhenAnAccountExists(t *testing.T) {
	h, _ := firstRunHarness(t, nil)
	h.addUser("someone", authz.RoleAdmin, true)
	c := h.client("192.0.2.100")
	result(c.get("/setup")).status(t, http.StatusNotFound)
	result(c.get("/login")).lacks(t, `href="/setup"`)
}

func TestKeyBackupNotice(t *testing.T) {
	data := t.TempDir()
	if _, err := firstrun.EnsureKeys(data, func() (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	n := firstrun.NewNotice(data)
	h, _ := firstRunHarness(t, &n)
	adminSecret := h.addUser("owner", authz.RoleAdmin, true)
	viewerSecret := h.addUser("viewer", authz.RoleViewer, true)

	v := h.client("192.0.2.101")
	v.login("viewer", viewerSecret)
	result(v.get("/")).status(t, http.StatusOK).lacks(t, "Back up the encryption key")
	result(v.do(http.MethodPost, "/keys/backup-notice", url.Values{csrfField: {"x"}})).status(t, http.StatusForbidden)

	a := h.client("192.0.2.100")
	a.login("owner", adminSecret)
	page := a.get("/").Body.String()
	if !strings.Contains(page, "Back up the encryption key") || !strings.Contains(page, n.IdentityPath()) {
		t.Fatal("admin does not see the backup notice")
	}
	tok := csrfFor(t, page, "/keys/backup-notice")
	result(a.do(http.MethodPost, "/keys/backup-notice", url.Values{csrfField: {"forged"}})).status(t, http.StatusForbidden)
	if !n.Pending() {
		t.Fatal("a forged form dismissed the notice")
	}
	result(a.do(http.MethodPost, "/keys/backup-notice", url.Values{csrfField: {tok}, "next": {"/"}})).
		status(t, http.StatusSeeOther)
	if n.Pending() {
		t.Fatal("notice still pending")
	}
	if e, ok := h.audit.find("keys.backup_acknowledged", audit.ResultOK); !ok || e.Principal != "owner" {
		t.Fatalf("dismiss not audited: %+v", e)
	}
	result(a.get("/")).lacks(t, "Back up the encryption key")
}
