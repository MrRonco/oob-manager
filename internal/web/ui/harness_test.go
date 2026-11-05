package ui

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/web"
)

const testPassword = "correct horse battery staple"

type harness struct {
	t        *testing.T
	clock    *clock
	users    *memUsers
	sessions *memSessions
	authn    *auth.Authenticator
	hasher   *auth.PasswordHasher
	sealer   auth.Sealer
	fleet    *fakeFleet
	audit    *fakeAudit
	handler  http.Handler
	deps     Deps
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// Every top-level test in this package calls t.Parallel(). Each one builds its own
// harness (clock, fakes, store, parsed templates) and no test changes package state, so
// they are independent; run one after another under -race they took most of the nightly
// soak's 30-minute budget (make soak). A new test does the same.
func newHarness(t *testing.T, tweak ...func(*Deps)) *harness {
	t.Helper()
	h := &harness{t: t, clock: &clock{t: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)},
		users: &memUsers{byID: map[string]auth.User{}}, sessions: &memSessions{m: map[string]auth.Session{}},
		fleet: testFleet(), audit: &fakeAudit{}}
	h.fleet.servers = fleetAt(h.clock.Now())
	var err error
	h.hasher, err = auth.NewPasswordHasher(auth.Argon2Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, auth.MaxHashConcurrency)
	must(t, err)
	h.sealer, err = auth.NewAESGCMSealer([]byte(strings.Repeat("s", 32)))
	must(t, err)
	h.authn, err = auth.New(auth.Config{Users: h.users, Sessions: h.sessions,
		Lockouts: &memLockouts{m: map[string]auth.LockoutState{}}, Hasher: h.hasher, Sealer: h.sealer,
		Now: h.clock.Now, Logger: quiet()})
	must(t, err)
	h.deps = Deps{Auth: h.authn, Fleet: h.fleet, Audit: h.audit, Logger: quiet(), Now: h.clock.Now,
		CSRFKey: []byte(strings.Repeat("c", 32))}
	for _, fn := range tweak {
		fn(&h.deps)
	}
	app, err := New(h.deps)
	must(t, err)
	h.handler, err = web.NewHandler(app, web.Options{Logger: quiet()})
	must(t, err)
	return h
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// addUser stores a user directly and returns its TOTP secret.
func (h *harness) addUser(name string, role authz.Role, confirmed bool) string {
	h.t.Helper()
	enr, err := auth.NewTOTPEnrollment("oob-manager", name)
	must(h.t, err)
	hash, err := h.hasher.Hash(context.Background(), testPassword)
	must(h.t, err)
	id := "id-" + name
	enc, err := h.sealer.Seal([]byte(enr.Secret), []byte(id))
	must(h.t, err)
	h.users.put(auth.User{ID: id, Username: name, Role: role, PasswordHash: hash, TOTPSecretEnc: enc,
		TOTPConfirmed: confirmed, CreatedAt: h.clock.Now()})
	return enr.Secret
}

// code returns the TOTP for secret at the harness time, then moves the clock one step
// on so the next code is not a replay.
func (h *harness) code(secret string) string {
	h.t.Helper()
	c, err := totp.GenerateCode(secret, h.clock.Now())
	must(h.t, err)
	h.clock.Advance(31 * time.Second)
	return c
}

type client struct {
	h   *harness
	jar map[string]string
	ip  string
}

func (h *harness) client(ip string) *client { return &client{h: h, jar: map[string]string{}, ip: ip} }

func (c *client) do(method, path string, form url.Values, hdr ...string) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequestWithContext(context.Background(), method, "https://oob.test"+path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	req.RemoteAddr = c.ip + ":50000"
	for k, v := range c.jar {
		req.AddCookie(&http.Cookie{Name: k, Value: v, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	rec := httptest.NewRecorder()
	c.h.handler.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(c.jar, ck.Name)
		} else {
			c.jar[ck.Name] = ck.Value
		}
	}
	return rec
}

func (c *client) get(path string) *httptest.ResponseRecorder { return c.do(http.MethodGet, path, nil) }

// csrfFor extracts the CSRF token of the form posting to action.
func csrfFor(t *testing.T, body, action string) string {
	t.Helper()
	re := regexp.MustCompile(`action="` + regexp.QuoteMeta(action) +
		`"[^>]*>\s*<input type="hidden" name="csrf_token" value="([^"]+)"`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no CSRF token for form %s in:\n%s", action, body)
	}
	return m[1]
}

// login runs the whole password + TOTP flow and asserts it lands on the overview.
func (c *client) login(user, secret string) {
	t := c.h.t
	t.Helper()
	page := c.get("/login").Body.String()
	rec := c.do(http.MethodPost, "/login", url.Values{"username": {user}, "password": {testPassword},
		csrfField: {csrfFor(t, page, "/login")}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login/totp" {
		t.Fatalf("password stage: %d %s\n%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	page = c.get("/login/totp").Body.String()
	rec = c.do(http.MethodPost, "/login/totp", url.Values{"code": {c.h.code(secret)},
		csrfField: {csrfFor(t, page, "/login/totp")}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("totp stage: %d %s\n%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
}

// Fixtures: a fresh R730XD, a stale R240, and a server never polled.

func testFleet() *fakeFleet { return &fakeFleet{logs: map[string]bmc.EventLog{}} }

func fleetAt(now time.Time) []ServerView {
	return []ServerView{
		{ID: "r730xd", Name: "Storage node R730XD", Snapshot: snapshotAt(now.Add(-20*time.Second), bmc.HealthOK),
			HasSnapshot: true, LastSuccess: now.Add(-20 * time.Second), Inventory: testInventory(), HasInventory: true,
			Capabilities: bmc.NewCapabilities(bmc.CapabilityParams{Flags: bmc.CapabilityFlags{
				Product: "Integrated Dell Remote Access Controller", RedfishVersion: "1.4.0", SEL: true}}),
			HasCapabilities: true},
		{ID: "r240", Name: "Edge node R240", Snapshot: snapshotAt(now.Add(-10*time.Minute), bmc.HealthWarning),
			HasSnapshot: true, LastSuccess: now.Add(-10 * time.Minute), ErrorClass: bmc.ClassTimeout},
		{ID: "spare", Name: "Spare box", ErrorClass: bmc.ClassUnreachable},
	}
}

func snapshotAt(at time.Time, h bmc.Health) bmc.Snapshot {
	return bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: at, PowerState: bmc.PowerOn, Health: h,
		Temperatures: []bmc.Temperature{
			{ID: "0", Name: "System Board Inlet Temp", Context: "Intake", Celsius: bmc.ReadingOf(23),
				WarnAbove: bmc.ReadingOf(42), CritAbove: bmc.ReadingOf(47), Health: bmc.HealthOK},
			{ID: "1", Name: "CPU1 Temp", Context: "CPU", Celsius: bmc.ReadingOf(48), WarnAbove: bmc.ReadingOf(85),
				Health: bmc.HealthOK},
			{ID: "2", Name: "CPU2 Temp", Context: "CPU", Celsius: bmc.ReadingOf(51), Health: bmc.HealthOK},
			{ID: "3", Name: "<script>alert(1)</script>", Celsius: bmc.NoReading(), Health: bmc.HealthUnknown},
		},
		Fans: []bmc.Fan{
			{ID: "f1", Name: "Fan1A", Speed: bmc.ReadingOf(7440), Units: bmc.FanRPM, Health: bmc.HealthOK},
			{ID: "f2", Name: "Fan2A", Speed: bmc.ReadingOf(7200), Units: bmc.FanRPM, Health: bmc.HealthOK},
		},
		PSUs: []bmc.PSU{
			{ID: "p1", Name: "PS1", Model: "PWR SPLY,750W", InputWatts: bmc.ReadingOf(120), Health: bmc.HealthOK},
			{ID: "p2", Name: "PS2", Model: "PWR SPLY,750W", InputWatts: bmc.ReadingOf(121), Health: bmc.HealthCritical},
		},
		Power:    bmc.PowerDraw{ConsumedWatts: bmc.ReadingOf(241), MaxWatts: bmc.ReadingOf(390)},
		Problems: []string{"power: timeout"},
	})
}

func testInventory() bmc.Inventory {
	return bmc.NewInventory(bmc.InventoryParams{
		InventoryInfo: bmc.InventoryInfo{Manufacturer: "Dell Inc.", Model: "PowerEdge R730xd", SKU: "SVCTAG1",
			BIOSVersion: "2.19.0", BMCFirmware: "2.86.86.86", MemoryGiB: 160, ProcessorCount: 2,
			ProcessorModel: "Xeon E5-2660 v4", LogicalProcessors: 56},
		Firmware: []bmc.FirmwareItem{{ID: "Installed-25227-2.86", Name: "Integrated Dell Remote Access Controller",
			Version: "2.86.86.86", State: "Installed", ComponentID: "25227"}},
		License: bmc.License{Tier: bmc.LicenseEnterprise, Source: "LicenseService",
			Description: "iDRAC8 Enterprise License", GraphicalConsole: true},
	})
}

// httpResult wraps a recorder with chainable assertions.
type httpResult struct{ rec *httptest.ResponseRecorder }

func result(rec *httptest.ResponseRecorder) *httpResult { return &httpResult{rec: rec} }

func (r *httpResult) status(t *testing.T, want int) *httpResult {
	t.Helper()
	if r.rec.Code != want {
		t.Fatalf("status = %d, want %d\n%s", r.rec.Code, want, r.rec.Body)
	}
	return r
}

func (r *httpResult) contains(t *testing.T, subs ...string) *httpResult {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(r.rec.Body.String(), s) {
			t.Errorf("body lacks %q", s)
		}
	}
	if t.Failed() {
		t.Logf("body:\n%s", r.rec.Body)
	}
	return r
}

func (r *httpResult) lacks(t *testing.T, subs ...string) *httpResult {
	t.Helper()
	for _, s := range subs {
		if strings.Contains(r.rec.Body.String(), s) {
			t.Errorf("body contains %q", s)
		}
	}
	return r
}

func (r *httpResult) location(t *testing.T, want string) *httpResult {
	t.Helper()
	if got := r.rec.Header().Get("Location"); got != want {
		t.Fatalf("Location = %q, want %q", got, want)
	}
	return r
}
