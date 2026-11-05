package ui

import (
	"net/http"
	"net/url"
	"testing"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/firstrun"
)

// Plan 06 §3.1: every POST route has a limit (security.md §3 table). These are the
// routes that had none, plus the display preferences limiter that had no test.

// TestPrefsRoutesRateLimited: the theme and auto-refresh toggles share the 30/min
// annotate rate (their own bucket), then 429 with Retry-After.
func TestPrefsRoutesRateLimited(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/prefs/theme", "/prefs/refresh"} {
		t.Run(path, func(t *testing.T) {
			h := newHarness(t)
			secret := h.addUser("morgan", authz.RoleViewer, true)
			c := h.client("192.0.2.70")
			c.login("morgan", secret)
			form := url.Values{csrfField: {csrfFor(t, c.get("/").Body.String(), path)}, "theme": {"dark"},
				"refresh": {"on"}, "next": {"/"}}
			for i := range maintChangeRate.Events {
				if rec := c.do(http.MethodPost, path, form); rec.Code != http.StatusSeeOther {
					t.Fatalf("request %d: %d", i, rec.Code)
				}
			}
			rec := c.do(http.MethodPost, path, form)
			result(rec).status(t, http.StatusTooManyRequests).contains(t, "Try again in")
			if rec.Header().Get("Retry-After") == "" {
				t.Fatal("no Retry-After")
			}
		})
	}
}

// TestDisplayPrefsRateLimited: /preferences uses the per-user change limit (10/min),
// and the refusal is audited.
func TestDisplayPrefsRateLimited(t *testing.T) {
	t.Parallel()
	e, _ := newGeneralEnv(t, "")
	c := e.adminClient()
	for i := range 10 {
		if rec := c.submit("/preferences", "/preferences", url.Values{"time_zone": {"UTC"}}); rec.Code != http.StatusSeeOther {
			t.Fatalf("save %d: %d", i, rec.Code)
		}
	}
	result(c.submit("/preferences", "/preferences", url.Values{"time_zone": {"UTC"}})).
		status(t, http.StatusTooManyRequests)
	if rec, ok := e.findAudit(string(authz.UserPrefs), audit.ResultDenied); !ok || rec.ErrorClass != "rate_limited" {
		t.Fatalf("refusal not audited: %+v", rec)
	}
}

// TestKeyBackupNoticeRateLimited: the dismissal writes an audit row, so a replayed form
// cannot add rows without bound.
func TestKeyBackupNoticeRateLimited(t *testing.T) {
	t.Parallel()
	data := t.TempDir()
	if _, err := firstrun.EnsureKeys(data, func() (bool, error) { return true, nil }); err != nil {
		t.Fatal(err)
	}
	n := firstrun.NewNotice(data)
	h, _ := firstRunHarness(t, &n)
	secret := h.addUser("owner", authz.RoleAdmin, true)
	a := h.client("192.0.2.100")
	a.login("owner", secret)
	form := url.Values{csrfField: {csrfFor(t, a.get("/").Body.String(), "/keys/backup-notice")}, "next": {"/"}}
	for i := range 10 {
		if rec := a.do(http.MethodPost, "/keys/backup-notice", form); rec.Code != http.StatusSeeOther {
			t.Fatalf("request %d: %d", i, rec.Code)
		}
	}
	result(a.do(http.MethodPost, "/keys/backup-notice", form)).status(t, http.StatusTooManyRequests)
}
