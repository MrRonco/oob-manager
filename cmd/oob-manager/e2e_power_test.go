//go:build e2e

package main

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/store"
)

// e2ePowerTransition is how long a mock BMC takes to change power state after a reset.
const e2ePowerTransition = 300 * time.Millisecond

// powerYAML: the R240 is a critical gateway with a "What goes down" list; the R730XD
// is the host oob-manager runs on.
func powerYAML(id string) string {
	if id == "r240" {
		return "    tags: [critical]\n    power: { impact: [\"Network gateway: all internet access drops\"] }\n"
	}
	return "    power: { self_host: true }\n"
}

// checkPower drives power control through the real stack as the admin (fresh step-up
// from the login): capability-based buttons, the confirm page, the typed name for a
// forced action, success with a verified transition at the mock, then the cooldown.
func checkPower(t *testing.T, b browser, s *stack) {
	expectPage(t, b.get("/servers/r240"), `href="/servers/r240/power/force-off"`,
		`href="/servers/r240/power/power-cycle"`, "The server is already on.")
	r730 := b.get("/servers/r730xd")
	expectPage(t, r730, `href="/servers/r730xd/power/force-off"`, "Not offered by this BMC.")
	if strings.Contains(r730.body, `href="/servers/r730xd/power/power-cycle"`) {
		t.Error("iDRAC8 fixture offers no PowerCycle, but the action is enabled")
	}
	expectPage(t, b.get("/servers/r730xd/power/force-off"),
		"This server runs oob-manager; the console will go offline until it boots.", "Type <code>Storage node R730XD</code>")
	expectPage(t, b.get("/servers/r240/power/force-off"), "Edge node R240 is tagged critical", "What goes down",
		"Network gateway: all internet access drops", "Type <code>Edge node R240</code>", "autofocus>Cancel</a>")

	path := "/servers/r240/power/force-off"
	if p := b.submit(path, path, url.Values{"confirm": {"yes"}, "typed": {"edge node r240"}}); p.status != http.StatusUnprocessableEntity {
		t.Fatalf("forced action without the exact typed name: %d", p.status)
	}
	if n := len(s.mocks["r240"].PowerStats().Resets); n != 0 {
		t.Fatalf("a reset reached the BMC without the typed name (%d)", n)
	}
	expectRedirect(t, b.submit(path, path, url.Values{"confirm": {"yes"}, "typed": {"Edge node R240"}}), "/servers/r240#now-h")
	waitFor(t, "force off verified", func() bool {
		return strings.Contains(b.get("/servers/r240").body, "Force off done: the server reported Off")
	})
	st := s.mocks["r240"].PowerStats()
	if len(st.Bodies) != 1 || st.Bodies[0] != `{"ResetType":"ForceOff"}` || st.Rejected != 0 {
		t.Fatalf("mock saw %+v", st)
	}
	// The verified state is published at once (audit R2-08): the API, the Operations
	// header and the Overview agree without waiting for the next poll.
	if p := b.do(http.MethodGet, "/api/v1/servers/r240", s.token, nil); !strings.Contains(p.body, `"power_state":"Off"`) {
		t.Fatalf("API still reports the polled state: %s", p.body)
	}
	expectPage(t, b.get("/servers/r240"), "Power: Off", "(force off by admin)")
	expectPage(t, b.get("/"), "Powered off since", "(forced off by admin).")

	// Cooldown: the next action on the same server is refused with 429 before any BMC traffic.
	token := formCSRF(t, b.get("/servers/r730xd/power/graceful-shutdown"), "/servers/r730xd/power/graceful-shutdown")
	p := b.post("/servers/r240/power/on", url.Values{"csrf_token": {token}, "confirm": {"yes"}})
	if p.status != http.StatusTooManyRequests || p.header.Get("Retry-After") == "" || !strings.Contains(p.body, "Try again in") {
		t.Fatalf("cooldown: %d %q", p.status, p.header.Get("Retry-After"))
	}
	if g := b.get("/servers/r240/power/on"); g.status != http.StatusTooManyRequests {
		t.Fatalf("cooldown confirm page: %d", g.status)
	}
	if n := len(s.mocks["r240"].PowerStats().Resets); n != 1 {
		t.Fatalf("a reset was sent during the cooldown (%d)", n)
	}
}

// checkPowerStepUp runs a second stack whose step-up window is 2 s: once it lapses, a
// power action is refused without a code and runs with one (inline on the confirm page).
func checkPowerStepUp(t *testing.T) {
	s := startStackStepUp(t, "127.0.0.1:0", 2*time.Second)
	b := browser{t: t, base: s.base, c: s.client(t)}
	login(t, b, s)
	time.Sleep(2500 * time.Millisecond)
	path := "/servers/r240/power/graceful-restart"
	confirm := b.get(path)
	expectPage(t, confirm, "<strong>Graceful restart · Edge node R240</strong> needs a fresh code")
	p := b.post(path, url.Values{"csrf_token": {formCSRF(t, confirm, path)}, "confirm": {"yes"}, "typed": {"Edge node R240"}})
	if p.status != http.StatusUnauthorized || !strings.Contains(p.body, "6-digit code") {
		t.Fatalf("without step-up: %d", p.status)
	}
	if n := len(s.mocks["r240"].PowerStats().Resets); n != 0 {
		t.Fatalf("reset sent without a step-up (%d)", n)
	}
	code := totpCode(t, s.secret, time.Now().Add(30*time.Second)) // the login used the current step
	p = b.submit(path, path, url.Values{"confirm": {"yes"}, "typed": {"Edge node R240"}, "code": {code}})
	expectRedirect(t, p, "/servers/r240#now-h")
	waitFor(t, "graceful restart verified", func() bool {
		return strings.Contains(b.get("/servers/r240").body, "Graceful restart done")
	})
	if code := s.stop(); code != 0 {
		t.Fatalf("serve exit %d", code)
	}
	assertPowerAudit(t, s.dbPath, "power.graceful_restart", "denied:stepup_required", "started:", "ok:")
}

// assertPowerAudit checks that action has rows with each "result:class" in want.
func assertPowerAudit(t *testing.T, dbPath, action string, want ...string) {
	t.Helper()
	db, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.AuditSearch().Search(context.Background(), store.AuditFilter{Action: action, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.Result+":"+r.ErrorClass] = true
		if r.ServerID == "" {
			t.Errorf("%s row without server: %+v", action, r)
		}
	}
	for _, w := range want {
		if !seen[w] {
			t.Errorf("%s: no %q row (have %v)", action, w, seen)
		}
	}
}
