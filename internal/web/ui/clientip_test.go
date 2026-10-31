package ui

import (
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
)

// TestForwardingHeadersAreIgnored: the console has no trusted proxy, so the audit source
// address and the per-IP sign-in limit both use the TCP peer, never X-Forwarded-For,
// X-Real-IP or Forwarded (any client could send them).
func TestForwardingHeadersAreIgnored(t *testing.T) {
	h := newHarness(t, func(d *Deps) { d.LoginPerIP = RateLimit{Events: 3, Per: time.Minute} })
	h.addUser("morgan", authz.RoleAdmin, true)
	c := h.client("192.0.2.100")
	var last *httpResult
	for i := range 4 {
		spoof := "198.51.100." + strconv.Itoa(i)
		page := c.get("/login").Body.String()
		last = result(c.do(http.MethodPost, "/login", url.Values{"username": {"morgan"},
			"password": {"wrong password here"}, csrfField: {csrfFor(t, page, "/login")}},
			"X-Forwarded-For", spoof, "X-Real-IP", spoof, "Forwarded", "for="+spoof))
	}
	last.status(t, http.StatusTooManyRequests)
	e, ok := h.audit.find("auth.login", audit.ResultDenied)
	if !ok || e.SrcIP != "192.0.2.100" {
		t.Fatalf("audit source = %+v, want the TCP peer 192.0.2.100", e)
	}
}
