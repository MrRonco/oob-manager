//go:build e2e

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// browser is a cookie-keeping HTTPS client for one stack.
type browser struct {
	t    *testing.T
	base string
	c    *http.Client
}

type page struct {
	status int
	header http.Header
	body   string
}

func (b browser) do(method, path, bearer string, form url.Values) page {
	b.t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(context.Background(), method, b.base+path, body)
	if err != nil {
		b.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return page{status: resp.StatusCode, header: resp.Header, body: string(raw)}
}

func (b browser) get(path string) page { return b.do(http.MethodGet, path, "", nil) }

func (b browser) post(path string, form url.Values) page {
	return b.do(http.MethodPost, path, "", form)
}

var csrfInput = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

func csrfFrom(t *testing.T, p page) string {
	t.Helper()
	m := csrfInput.FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no CSRF token in page (%d): %s", p.status, p.body)
	}
	return m[1]
}

func expectRedirect(t *testing.T, p page, to string) {
	t.Helper()
	if p.status != http.StatusSeeOther || p.header.Get("Location") != to {
		t.Fatalf("want 303 to %s, got %d %q", to, p.status, p.header.Get("Location"))
	}
}

func expectPage(t *testing.T, p page, wants ...string) {
	t.Helper()
	if p.status != http.StatusOK {
		t.Fatalf("status %d: %s", p.status, p.body)
	}
	for _, w := range wants {
		if !strings.Contains(p.body, w) {
			t.Errorf("page does not contain %q", w)
		}
	}
}

// login runs password then TOTP and returns the overview page.
func login(t *testing.T, b browser, s *stack) page {
	t.Helper()
	form := url.Values{"username": {e2eUser}, "password": {e2ePassword},
		"csrf_token": {csrfFrom(t, b.get("/login"))}}
	expectRedirect(t, b.post("/login", form), "/login/totp")
	code := url.Values{"code": {totpCode(t, s.secret, time.Now())},
		"csrf_token": {csrfFrom(t, b.get("/login/totp"))}}
	expectRedirect(t, b.post("/login/totp", code), "/")
	return b.get("/")
}

func TestE2E(t *testing.T) {
	s := startStack(t, "127.0.0.1:0")
	b := browser{t: t, base: s.base, c: s.client(t)}

	t.Run("probes", func(t *testing.T) {
		expectPage(t, b.get("/healthz"), "ok")
		expectPage(t, b.get("/readyz"), `"ok"`)
	})
	t.Run("configured install generates nothing", func(t *testing.T) {
		for _, d := range []string{"keys", "tls"} { // plan 09: only a store install gets these
			if _, err := os.Stat(filepath.Join(filepath.Dir(s.dbPath), d)); !os.IsNotExist(err) {
				t.Errorf("%s/ created for an install whose config.yaml names its files", d)
			}
		}
		if strings.Contains(s.errOut.String(), "first-run setup") || b.get("/setup").status != http.StatusNotFound {
			t.Error("setup offered although an admin exists")
		}
	})
	t.Run("signed out", func(t *testing.T) {
		expectRedirect(t, b.get("/"), "/login")
		expectRedirect(t, b.get("/servers/r240"), "/login")
	})
	t.Run("csrf rejected", func(t *testing.T) {
		b.get("/login") // sets the pre-login binding cookie
		p := b.post("/login", url.Values{"username": {e2eUser}, "password": {e2ePassword},
			"csrf_token": {"forged"}})
		if p.status != http.StatusForbidden {
			t.Fatalf("forged CSRF token: %d", p.status)
		}
		expectRedirect(t, b.get("/"), "/login")
	})
	t.Run("wrong password", func(t *testing.T) {
		p := b.post("/login", url.Values{"username": {e2eUser}, "password": {"wrong password here"},
			"csrf_token": {csrfFrom(t, b.get("/login"))}})
		if p.status != http.StatusUnauthorized || strings.Contains(p.body, "wrong password here") {
			t.Fatalf("wrong password: %d", p.status)
		}
	})
	t.Run("ui", func(t *testing.T) { checkUI(t, b, s) })
	t.Run("api", func(t *testing.T) { checkAPI(t, b, s) })
	t.Run("cli tokens", func(t *testing.T) { checkCLITokens(t, b, s) })
	t.Run("reset totp", checkResetTOTP)
	t.Run("power step-up", checkPowerStepUp)
	t.Run("bmc reset", checkBMCReset)
	t.Run("servers", checkServers)
	t.Run("notify settings", checkNotifySettings)
	t.Run("integrations", checkIntegrations)
	t.Run("metrics", checkMetrics)
	t.Run("security", checkSecurity)
	t.Run("firmware", checkFirmware)
	t.Run("history", checkHistory)
	t.Run("shutdown", func(t *testing.T) {
		if code := s.stop(); code != 0 {
			t.Fatalf("serve exit %d: %s", code, s.errOut.String())
		}
		for id, m := range s.mocks {
			// The only writes allowed: one session login and its logout at shutdown.
			// Each native console launch, each power action and each fan floor read or PATCH
			// logs in with the operator account and out again.
			st, want := m.SessionStats(), 1+m.KVMStats().Launches+len(m.PowerStats().Resets)+fanFloorLogins(m)
			if n := m.OtherWrites(); n != 0 || st.Created != want || st.Deleted != want || m.LiveSessions() != 0 || st.BasicGETs != 0 {
				t.Errorf("%s: other writes %d, sessions %+v, live %d", id, n, st, m.LiveSessions())
			}
		}
		assertAudited(t, s.dbPath, "admin.bootstrap", "admin.totp_confirmed", "app.start",
			"auth.login", "auth.logout", "app.stop", "token.create", "token.revoke",
			"admin.user.create", "auth.enrol", "auth.totp.enroll", "admin.audit.verify",
			"console.vnc.start", "console.vnc.stop", "console.kvm_launch", "console.serial.start", "console.serial.stop",
			"power.force_off", "power.on", "fan.lease.create", "fan.lease.end", "admin.general.update", "user.prefs.update")
		assertPowerAudit(t, s.dbPath, "power.force_off", "denied:confirm_mismatch", "started:", "ok:")
		assertPowerAudit(t, s.dbPath, "power.on", "denied:cooldown")
		for _, leak := range []string{e2ePassword, s.secret, s.token, s.uiToken, s.newSecret, e2eNewPassword} {
			if leak == "" {
				t.Fatal("settings flow did not run")
			}
			if strings.Contains(s.errOut.String(), leak) {
				t.Fatal("a secret reached the application log")
			}
		}
	})
}

func checkUI(t *testing.T, b browser, s *stack) {
	overview := login(t, b, s)
	expectPage(t, overview, "Storage node R730XD", "Edge node R240", "Sign out", `id="verdict"`, `class="rec-svg"`)
	expectPage(t, b.get("/servers"), "Inlet °C", `aria-label="Fleet table"`)
	if strings.Contains(overview.body, "Stale (last:") || strings.Contains(overview.body, "chip-stale") {
		t.Error("freshly polled servers shown as stale")
	}

	expectPage(t, b.get("/servers/r730xd"), "Verdict and exceptions", "· poll ")
	r730 := b.get("/servers/r730xd/sensors")
	expectPage(t, r730, "Fans", "Power supplies")
	if strings.Contains(r730.body, "refresh is overdue") {
		t.Error("freshly read sections flagged overdue")
	}
	if n := fanRows(r730.body); n != 6 {
		t.Errorf("R730XD shows %d fans, want 6", n)
	}
	checkNoPSUTelemetry(t, b)
	expectPage(t, b.get("/servers/r240/inventory"), "License", "Enterprise")

	for _, path := range []string{"/servers/r730xd/events?log=sel", "/servers/r730xd/events?log=lifecycle",
		"/servers/r240/events?log=sel", "/servers/r240/events?log=lifecycle"} {
		p := b.get(path)
		expectPage(t, p, "<tbody")
		if strings.Contains(p.body, "could not be read") || strings.Contains(p.body, "does not provide") {
			t.Errorf("%s: log not shown", path)
		}
	}
	if p := b.get("/servers/unknown-server"); p.status != http.StatusNotFound {
		t.Errorf("unknown server: %d", p.status)
	}
	// Pages are gzipped for a client that asks (audit A9): an explicit Accept-Encoding
	// stops Go's transparent decompression, so the header is visible.
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, s.base+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.Header.Get("Content-Encoding") != "gzip" || resp.Header.Get("Vary") != "Accept-Encoding" {
		t.Errorf("overview not compressed: %v", resp.Header)
	}
	// The seeded SEL pages: two pagers with distinct landmark labels (audit R2-25).
	expectPage(t, b.get("/events?severity=all&range=all"), `aria-label="Event pages"`, `aria-label="Event pages, bottom"`,
		"Synthetic informational event")
	expectPage(t, b.get("/servers/r240/events?page=2"), `aria-label="Log pages"`, `aria-label="Log pages, bottom"`)
	if p := b.get("/servers/r240/events?log=bogus"); p.status != http.StatusBadRequest {
		t.Errorf("bogus log kind: %d", p.status)
	}

	t.Run("settings", func(t *testing.T) { checkSettings(t, b, s) })
	t.Run("general", func(t *testing.T) { checkGeneral(t, b, s) })
	t.Run("fans", func(t *testing.T) { checkFans(t, b, s) })
	t.Run("console", func(t *testing.T) { checkConsole(t, b, s) })
	t.Run("power", func(t *testing.T) { checkPower(t, b, s) })
	t.Run("serial", func(t *testing.T) { checkSerial(t, b, s) })
	t.Run("notify", func(t *testing.T) { checkNotifyEvents(t, b, s) })

	logout := url.Values{"csrf_token": {formCSRF(t, b.get("/"), "/logout")}}
	expectRedirect(t, b.post("/logout", logout), "/login")
	expectRedirect(t, b.get("/"), "/login")
}

// fanRows counts the rows of the server page's fan table.
func fanRows(body string) int {
	_, rest, ok := strings.Cut(body, `id="fans-h"`)
	if !ok {
		return -1
	}
	section, _, _ := strings.Cut(rest, "</section>")
	return strings.Count(section, "<li")
}

func checkAPI(t *testing.T, b browser, s *stack) {
	if p := b.do(http.MethodGet, "/api/v1/servers", "", nil); p.status != http.StatusUnauthorized {
		t.Fatalf("API without token: %d", p.status)
	}
	p := b.do(http.MethodGet, "/api/v1/servers", s.token, nil)
	var list struct {
		Data []struct {
			ID        string `json:"id"`
			Reachable bool   `json:"reachable"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(p.body), &list); p.status != http.StatusOK || err != nil || len(list.Data) != 2 {
		t.Fatalf("servers: %d %s", p.status, p.body)
	}
	if list.Data[0].ID != "r730xd" || list.Data[1].ID != "r240" || !list.Data[0].Reachable || !list.Data[1].Reachable {
		t.Fatalf("servers: %+v", list.Data)
	}
	checkAPIPollTiming(t, b, s)
	p = b.do(http.MethodGet, "/api/v1/servers/r730xd/events?log=lifecycle&limit=5", s.token, nil)
	if p.status != http.StatusOK || strings.Count(p.body, `"id":`) != 5 {
		t.Fatalf("events: %d %s", p.status, p.body)
	}
	if p = b.do(http.MethodPost, "/api/v1/servers", s.token, url.Values{}); p.status != http.StatusMethodNotAllowed {
		t.Fatalf("API POST: %d", p.status)
	}
	if p = b.do(http.MethodGet, "/api/v1/servers", "not-a-token", nil); p.status != http.StatusUnauthorized {
		t.Fatalf("bad token: %d", p.status)
	}
}

// checkAPIPollTiming: the iDRAC8 kind gets its slower defaults (interval raised to the
// 150 s cycle timeout), and every tier has been read once at startup.
func checkAPIPollTiming(t *testing.T, b browser, s *stack) {
	t.Helper()
	for id, wantInterval := range map[string]int64{"r730xd": 150, "r240": 60} {
		p := b.do(http.MethodGet, "/api/v1/servers/"+id, s.token, nil)
		var d struct {
			LastPollDurationMS *int64 `json:"last_poll_duration_ms"`
			PollIntervalS      int64  `json:"poll_interval_s"`
			Sections           map[string]struct {
				AsOf    *string `json:"as_of"`
				Overdue bool    `json:"overdue"`
			} `json:"sections"`
		}
		if err := json.Unmarshal([]byte(p.body), &d); err != nil || p.status != http.StatusOK {
			t.Fatalf("%s detail: %d %v", id, p.status, err)
		}
		if d.LastPollDurationMS == nil || d.PollIntervalS != wantInterval {
			t.Errorf("%s: duration %v interval %d", id, d.LastPollDurationMS, d.PollIntervalS)
		}
		for _, sec := range []string{"sel", "lifecycle", "inventory"} {
			if d.Sections[sec].AsOf == nil || d.Sections[sec].Overdue {
				t.Errorf("%s %s: %+v", id, sec, d.Sections[sec])
			}
		}
	}
}
