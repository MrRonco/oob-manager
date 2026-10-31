package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
	"oob-manager/internal/store"
	"oob-manager/internal/store/authrepo"
	"oob-manager/internal/web"
)

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// staticFleet is a fleet.Reader over fixed states.
type staticFleet struct {
	states []fleet.ServerState
	polled bool
}

func (f staticFleet) Servers() []fleet.ServerState {
	return append([]fleet.ServerState(nil), f.states...)
}

func (f staticFleet) Server(id string) (fleet.ServerState, bool) {
	for _, s := range f.states {
		if s.ID == id {
			return s, true
		}
	}
	return fleet.ServerState{}, false
}

func (f staticFleet) Polled() bool { return f.polled }

type pinger struct{ err error }

func (p pinger) Ping(context.Context) error { return p.err }

// shipper is a GELF shipper state; off is the zero state of a disabled one.
type shipper struct{ connected, paused, off bool }

func (s shipper) Stats() audit.ShipperStats {
	return audit.ShipperStats{Active: !s.off, Connected: s.connected, PinMismatch: s.paused}
}

// fakeVerifier returns a fixed principal for one token string.
type fakeVerifier struct {
	token string
	p     authz.Principal
}

func (v fakeVerifier) Verify(_ context.Context, raw string) (auth.APIToken, authz.Principal, error) {
	if raw != v.token {
		return auth.APIToken{}, authz.Principal{}, auth.ErrInvalidToken
	}
	return auth.APIToken{ID: "tok1", Scope: auth.ScopeRead}, v.p, nil
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func healthyState() fleet.ServerState {
	snap := bmc.NewSnapshot(bmc.SnapshotParams{
		TakenAt: t0, PowerState: bmc.PowerOn, Health: bmc.HealthOK,
		Temperatures: []bmc.Temperature{{ID: "cpu1", Name: "CPU1 Temp", Celsius: bmc.ReadingOf(45),
			CritAbove: bmc.ReadingOf(95), Health: bmc.HealthOK}},
		Fans:  []bmc.Fan{{ID: "fan1", Name: "Fan 1", Speed: bmc.ReadingOf(7920), Units: bmc.FanRPM, Health: bmc.HealthOK}},
		PSUs:  []bmc.PSU{{ID: "PSU.Slot.1", Name: "PS1", LineInputVolts: bmc.ReadingOf(118), Health: bmc.HealthOK}},
		Power: bmc.PowerDraw{ConsumedWatts: bmc.ReadingOf(263)},
		Voltages: []bmc.Voltage{{ID: "0", Name: "CPU1 VCORE PG", Context: "CPU", Volts: bmc.ReadingOf(1),
			Health: bmc.HealthOK}, {ID: "1", Name: "PG", Health: bmc.HealthOK}},
		PowerTelemetry: bmc.PowerTelemetryAvailable,
	})
	return fleet.ServerState{ID: "r730xd", Name: "Storage node R730XD", Tags: []string{"critical"}, Snapshot: snap,
		HasSnapshot: true, LastAttempt: t0, LastSuccess: t0, Breaker: fleet.BreakerClosed,
		SEL: selLog(), HasSEL: true, SELAsOf: t0, SELOverdue: true,
		LastPollDuration: 4200 * time.Millisecond, Interval: 150 * time.Second}
}

func deadState() fleet.ServerState {
	return fleet.ServerState{ID: "r240", Name: "Edge node R240", LastAttempt: t0, LastError: bmc.ClassTimeout,
		FailingSince: t0.Add(-time.Hour), ConsecutiveFailures: 5, Breaker: fleet.BreakerOpen, Stale: true}
}

// selLog has 7 entries; IDs 1..7, one minute apart, plus none undated.
func selLog() bmc.EventLog {
	var es []bmc.Event
	for i := 1; i <= 7; i++ {
		es = append(es, bmc.Event{ID: strconv.Itoa(i), Created: t0.Add(time.Duration(i) * time.Minute),
			Severity: bmc.SeverityOK, Message: "<b>entry</b> " + strconv.Itoa(i)})
	}
	return bmc.NewEventLog("/sel", es, false)
}

const goodToken = "oobk_good"

func newTestAPI(t *testing.T, d Deps) *API {
	t.Helper()
	if d.Fleet == nil {
		d.Fleet = staticFleet{states: []fleet.ServerState{healthyState(), deadState()}, polled: true}
	}
	if d.Tokens == nil {
		d.Tokens = fakeVerifier{token: goodToken, p: authz.Principal{Kind: authz.KindToken, Role: authz.RoleViewer}}
	}
	if d.DB == nil {
		d.DB = pinger{}
	}
	d.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	d.Version = "1.2.3"
	a, err := New(d)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func do(t *testing.T, h http.Handler, method, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), method, target, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func decode[T any](t *testing.T, w *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
	return v
}

func assertProblem(t *testing.T, w *httptest.ResponseRecorder, status int) web.Problem {
	t.Helper()
	if w.Code != status || w.Header().Get("Content-Type") != web.ProblemContentType {
		t.Fatalf("want %d problem, got %d %q %s", status, w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	return decode[web.Problem](t, w)
}

func TestNewRequiresDeps(t *testing.T) {
	if _, err := New(Deps{}); err == nil {
		t.Fatal("want error")
	}
}

func TestHealthz(t *testing.T) {
	w := do(t, newTestAPI(t, Deps{}), http.MethodGet, "/healthz", "")
	if w.Code != 200 || decode[statusJSON](t, w).Status != StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	assertProblem(t, do(t, newTestAPI(t, Deps{}), http.MethodPost, "/healthz", ""), http.StatusMethodNotAllowed)
}

func TestReadyz(t *testing.T) {
	cases := []struct {
		name string
		d    Deps
		code int
		want string
	}{
		{"ok without shipper", Deps{}, 200, StatusOK},
		{"ok with shipper", Deps{Shipper: shipper{connected: true}}, 200, StatusOK},
		{"graylog down", Deps{Shipper: shipper{}}, 200, StatusDegraded},
		{"pin mismatch", Deps{Shipper: shipper{connected: true, paused: true}}, 200, StatusDegraded},
		{"shipping disabled", Deps{Shipper: shipper{off: true}}, 200, StatusOK},
		{"db down", Deps{DB: pinger{err: errors.New("disk I/O at /data/secret")}}, 503, StatusUnavailable},
		{"never polled", Deps{Fleet: staticFleet{}}, 503, StatusUnavailable},
	}
	for _, c := range cases {
		w := do(t, newTestAPI(t, c.d), http.MethodGet, "/readyz", "")
		if w.Code != c.code || decode[statusJSON](t, w).Status != c.want {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body.String())
		}
	}
}

func TestBearerRequired(t *testing.T) {
	a := newTestAPI(t, Deps{})
	for _, path := range []string{"/api/v1/servers", "/api/v1/servers/r730xd", "/api/v1/servers/r730xd/events",
		"/api/v1/version", "/api/v1/nope"} {
		w := do(t, a, http.MethodGet, path, "")
		assertProblem(t, w, http.StatusUnauthorized)
		if w.Header().Get("WWW-Authenticate") != bearerChallenge {
			t.Errorf("%s: missing challenge", path)
		}
		assertProblem(t, do(t, a, http.MethodGet, path, "oobk_wrong"), http.StatusUnauthorized)
	}
	// A token in the query string is never accepted.
	assertProblem(t, do(t, a, http.MethodGet, "/api/v1/servers?access_token="+goodToken, ""), http.StatusUnauthorized)
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/v1/servers", nil)
	r.Header.Set("Authorization", "Basic "+goodToken)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	assertProblem(t, w, http.StatusUnauthorized)
}

func TestTokenPrincipalIsReadOnly(t *testing.T) {
	// Even a verifier that (wrongly) hands out an admin token principal gets reads only,
	// and a session-kind or unknown principal is never accepted on the API.
	for _, p := range []authz.Principal{
		{Kind: authz.KindToken, Role: authz.RoleAdmin},
		{Kind: authz.KindToken, Role: authz.RoleViewer},
	} {
		a := newTestAPI(t, Deps{Tokens: fakeVerifier{token: goodToken, p: p}})
		if w := do(t, a, http.MethodGet, "/api/v1/servers", goodToken); w.Code != 200 {
			t.Fatalf("%+v: read refused: %d", p, w.Code)
		}
		assertProblem(t, do(t, a, http.MethodPost, "/api/v1/servers", goodToken), http.StatusMethodNotAllowed)
		assertProblem(t, do(t, a, http.MethodDelete, "/api/v1/servers/r730xd", goodToken), http.StatusMethodNotAllowed)
	}
	a := newTestAPI(t, Deps{Tokens: fakeVerifier{token: goodToken, p: authz.Principal{Kind: "bogus", Role: authz.RoleAdmin}}})
	assertProblem(t, do(t, a, http.MethodGet, "/api/v1/servers", goodToken), http.StatusForbidden)
}

func TestListServers(t *testing.T) {
	w := do(t, newTestAPI(t, Deps{}), http.MethodGet, "/api/v1/servers", goodToken)
	body := decode[struct {
		Data []serverSummary `json:"data"`
		Meta struct {
			Total int `json:"total"`
		} `json:"meta"`
	}](t, w)
	if w.Code != 200 || body.Meta.Total != 2 || len(body.Data) != 2 {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	h, d := body.Data[0], body.Data[1]
	if h.ID != "r730xd" || h.Health != "OK" || h.PowerState != "On" || !h.Reachable || h.Stale || h.LastPoll == nil {
		t.Errorf("healthy %+v", h)
	}
	if d.Health != "Unknown" || d.Reachable || !d.Stale || d.LastError != "timeout" || d.Breaker != "open" ||
		d.UnreachableSince == nil || d.Tags == nil {
		t.Errorf("dead %+v", d)
	}
}

func TestServerDetail(t *testing.T) {
	a := newTestAPI(t, Deps{})
	w := do(t, a, http.MethodGet, "/api/v1/servers/r730xd", goodToken)
	d := decode[serverDetail](t, w)
	if w.Code != 200 || len(d.Temperatures) != 1 || *d.Temperatures[0].Celsius != 45 || d.Temperatures[0].WarnAbove != nil {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	if *d.Fans[0].Speed != 7920 || *d.Power.ConsumedWatts != 263 || d.Power.CapacityWatts != nil || d.PSUs[0].CapacityWatts != nil {
		t.Fatalf("detail %+v", d)
	}
	if d.PowerTelemetry != "available" || len(d.Voltages) != 2 || *d.Voltages[0].Volts != 1 || d.Voltages[1].Volts != nil {
		t.Fatalf("power telemetry %q voltages %+v", d.PowerTelemetry, d.Voltages)
	}
	dead := decode[serverDetail](t, do(t, a, http.MethodGet, "/api/v1/servers/r240", goodToken))
	if dead.TakenAt != nil || dead.Temperatures == nil || len(dead.Fans) != 0 || dead.Problems == nil ||
		dead.PowerTelemetry != "unknown" || dead.Voltages == nil {
		t.Fatalf("dead detail %+v", dead)
	}
	p := assertProblem(t, do(t, a, http.MethodGet, "/api/v1/servers/%3Cscript%3E", goodToken), http.StatusNotFound)
	if p.Detail != "unknown server" {
		t.Fatalf("detail must not echo input: %+v", p)
	}
	assertProblem(t, do(t, a, http.MethodGet, "/api/v1/nothing", goodToken), http.StatusNotFound)
}

func TestVersion(t *testing.T) {
	w := do(t, newTestAPI(t, Deps{}), http.MethodGet, "/api/v1/version", goodToken)
	b := decode[BuildInfo](t, w)
	if w.Code != 200 || b.Version != "1.2.3" || b.GoVersion == "" {
		t.Fatalf("%d %+v", w.Code, b)
	}
}

func TestRateLimitPerToken(t *testing.T) {
	c := &clock{now: t0}
	a := newTestAPI(t, Deps{Now: c.Now, TokenRatePerMinute: 3})
	for i := 0; i < 3; i++ {
		if w := do(t, a, http.MethodGet, "/api/v1/servers", goodToken); w.Code != 200 {
			t.Fatalf("request %d: %d", i, w.Code)
		}
	}
	w := do(t, a, http.MethodGet, "/api/v1/servers", goodToken)
	assertProblem(t, w, http.StatusTooManyRequests)
	if w.Header().Get("Retry-After") != "20" {
		t.Fatalf("Retry-After %q", w.Header().Get("Retry-After"))
	}
	c.Advance(20 * time.Second)
	if w := do(t, a, http.MethodGet, "/api/v1/servers", goodToken); w.Code != 200 {
		t.Fatalf("after refill: %d", w.Code)
	}
}

// TestRealTokensAgainstSQLite wires the real TokenService over the SQLite store.
func TestRealTokensAgainstSQLite(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "oob.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err = db.Users().Create(ctx, store.User{ID: "u1", Username: "morgan", Role: store.RoleAdmin,
		PwHash: "x", CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	ts, err := auth.NewTokenService(authrepo.New(db).Tokens, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, tok, err := ts.Issue(ctx, "homepage", "u1")
	if err != nil {
		t.Fatal(err)
	}
	a := newTestAPI(t, Deps{Tokens: ts, DB: db})
	if w := do(t, a, http.MethodGet, "/api/v1/servers/r730xd", raw); w.Code != 200 {
		t.Fatalf("valid token: %d", w.Code)
	}
	if w := do(t, a, http.MethodGet, "/readyz", ""); w.Code != 200 {
		t.Fatalf("readyz with real DB: %d", w.Code)
	}
	if err := ts.Revoke(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	assertProblem(t, do(t, a, http.MethodGet, "/api/v1/servers/r730xd", raw), http.StatusUnauthorized)
}

func TestServerDetailPollTiming(t *testing.T) {
	a := newTestAPI(t, Deps{})
	d := decode[serverDetail](t, do(t, a, http.MethodGet, "/api/v1/servers/r730xd", goodToken))
	if d.LastPollDurationMS == nil || *d.LastPollDurationMS != 4200 || d.PollIntervalS != 150 {
		t.Fatalf("poll timing %+v %d", d.LastPollDurationMS, d.PollIntervalS)
	}
	sel := d.Sections.SEL
	if sel.AsOf == nil || !sel.AsOf.Equal(t0) || !sel.Overdue || d.Sections.Inventory.AsOf != nil || d.Sections.Inventory.Overdue {
		t.Fatalf("sections %+v", d.Sections)
	}
	dead := decode[serverDetail](t, do(t, a, http.MethodGet, "/api/v1/servers/r240", goodToken))
	if dead.LastPollDurationMS != nil {
		t.Fatalf("no successful-or-failed timing recorded yet must be null: %v", *dead.LastPollDurationMS)
	}
}
