//go:build e2e

package main

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/notify"
)

// e2eRestartCadence is the fleet's BMC restart window cadence in every e2e stack (the
// env test hook): one second of quiet, then a poll every second.
var e2eRestartCadence = restartCadence{quiet: time.Second, retry: time.Second}

// e2eBMCDowntime is how long each mock BMC answers 503 after a Manager.Reset.
func e2eBMCDowntime(id string) time.Duration {
	if id == "r240" {
		return 3 * time.Second
	}
	return time.Second
}

// checkBMCReset runs its own stack (a BMC restart drops every session on the mock, which
// would upset the main stack's session accounting): the BMC panel on both iDRAC
// generations, a serial console ended by the restart, the typed name, the restart window
// (API, Operations, a power action refused), verification with notifications and no
// reachability alarm, the cooldown, and an iDRAC8 privilege refusal.
func checkBMCReset(t *testing.T) {
	s := startStack(t, "127.0.0.1:0")
	b := browser{t: t, base: s.base, c: s.client(t)}
	login(t, b, s)
	expectPage(t, b.get("/servers/r240"), `href="/servers/r240/bmc/reset"`, "(reported by the BMC)", "14G Monolithic")
	expectPage(t, b.get("/servers/r730xd"), `href="/servers/r730xd/bmc/reset"`) // iDRAC8 advertises it too

	console := dialSerial(t, b, s, "r240", startSerial(t, b, "r240"))
	var got bytes.Buffer
	readSerial(t, console, &got, `{"type":"connected"}`)
	path := "/servers/r240/bmc/reset"
	expectPage(t, b.get(path), "Restart the BMC of Edge node R240?", "The serial console of admin is open; it ends now.",
		"Type <code>Edge node R240</code>", "autofocus>Cancel</a>")
	if p := b.submit(path, path, url.Values{"confirm": {"yes"}, "typed": {"edge node r240"}}); p.status != http.StatusUnprocessableEntity {
		t.Fatalf("restart without the exact typed name: %d", p.status)
	}
	if n := s.mocks["r240"].ManagerResetStats().Resets; n != 0 {
		t.Fatalf("a reset reached the BMC without the typed name (%d)", n)
	}
	expectRedirect(t, b.submit(path, path, url.Values{"confirm": {"yes"}, "typed": {"Edge node R240"}}),
		"/servers/r240#now-h")
	readSerial(t, console, &got, `bmc_reset`)
	checkRestartWindow(t, b, s)

	waitFor(t, "BMC back", func() bool { return strings.Contains(b.get("/servers/r240").body, "BMC back after") })
	waitFor(t, "BMC restart notifications", func() bool {
		return s.hooks.has(notify.ClassBMC, "BMC restart requested") && s.hooks.has(notify.ClassBMC, "BMC back")
	})
	if s.hooks.has(notify.ClassReachability, "unreachable") {
		t.Error("an expected BMC restart raised a reachability alarm")
	}
	if g := b.get(path); g.status != http.StatusTooManyRequests || g.header.Get("Retry-After") == "" {
		t.Fatalf("cooldown: %d %q", g.status, g.header.Get("Retry-After"))
	}
	if st := s.mocks["r240"].ManagerResetStats(); st.Resets != 1 || st.Bodies[0] != `{"ResetType":"GracefulRestart"}` ||
		s.mocks["r240"].OtherWrites() != 0 {
		t.Fatalf("mock saw %+v (other writes %d)", st, s.mocks["r240"].OtherWrites())
	}
	checkBMCPrivilegeRefusal(t, b, s)
	if code := s.stop(); code != 0 {
		t.Fatalf("serve exit %d", code)
	}
	assertPowerAudit(t, s.dbPath, "bmc.reset", "denied:confirm_mismatch", "started:", "ok:", "denied:cooldown", "error:auth")
	assertPowerAudit(t, s.dbPath, "bmc.reset.verified", "ok:")
	assertAudited(t, s.dbPath, "console.serial.stop")
}

// checkRestartWindow runs while the mock R240 is down: the API and the pages say it is
// restarting (not unreachable) and a power action is refused before reaching the BMC.
func checkRestartWindow(t *testing.T, b browser, s *stack) {
	t.Helper()
	if p := b.do(http.MethodGet, "/api/v1/servers/r240", s.token, nil); !strings.Contains(p.body, `"bmc_restarting":true`) ||
		!strings.Contains(p.body, `"restarting":true`) {
		t.Errorf("API during the window: %s", p.body)
	}
	expectPage(t, b.get("/servers/r240"), "BMC restarting · requested", "The BMC is restarting; power actions wait")
	if p := b.get("/servers/r240/power/force-restart"); p.status != http.StatusConflict || !strings.Contains(p.body, "The BMC is restarting") {
		t.Errorf("power during the window: %d", p.status)
	}
	expectPage(t, b.get("/"), "restarting")
	if n := len(s.mocks["r240"].PowerStats().Resets); n != 0 {
		t.Fatalf("a power reset reached the restarting BMC (%d)", n)
	}
}

// checkBMCPrivilegeRefusal: the iDRAC8 BMC answers 403 (an operator account without
// Configure iDRAC); the page says so and the panel keeps the reason.
func checkBMCPrivilegeRefusal(t *testing.T, b browser, s *stack) {
	t.Helper()
	s.mocks["r730xd"].FailNextManagerReset(http.StatusForbidden)
	path := "/servers/r730xd/bmc/reset"
	p := b.submit(path, path, url.Values{"confirm": {"yes"}, "typed": {"Storage node R730XD"}})
	if p.status != http.StatusBadGateway || !strings.Contains(p.body, "Configure iDRAC") {
		t.Fatalf("privilege refusal: %d", p.status)
	}
	expectPage(t, b.get("/servers/r730xd"), "The operator account lacks the privilege for this action")
	if s.mocks["r730xd"].ManagerRestarting() {
		t.Fatal("a refused reset restarted the mock")
	}
}
