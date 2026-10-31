package metrics

import (
	"bytes"
	"context"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
)

var update = flag.Bool("update", false, "rewrite testdata/*.golden")

func render(t *testing.T, cfg Config) string {
	t.Helper()
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body, err := c.Render(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func TestGoldenScrape(t *testing.T) {
	got := render(t, fullConfig(staticFleet{states: []fleet.ServerState{healthyState(), staleState(), neverPolled()}}))
	path := filepath.Join("testdata", "scrape.golden")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) // #nosec G304 -- fixed test path
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("scrape differs from %s (run go test -run Golden -update):\n%s", path, got)
	}
}

func TestNoIdentifiersUnlessOptedIn(t *testing.T) {
	cfg := fullConfig(staticFleet{states: []fleet.ServerState{healthyState()}})
	out := render(t, cfg)
	for _, leak := range []string{"SERIAL-1", "TAG1", "2.86", "Enterprise", "R730xd"} {
		if strings.Contains(out, leak) {
			t.Errorf("identifier %q exposed without include_inventory", leak)
		}
	}
	cfg.IncludeInventory = true
	out = render(t, cfg)
	if !strings.Contains(out, `serial="SERIAL-1"`) || !strings.Contains(out, `license_tier="Enterprise"`) {
		t.Fatalf("include_inventory did not add identity labels:\n%s", out)
	}
}

func TestOptionalSourcesLeftOut(t *testing.T) {
	out := render(t, Config{Fleet: staticFleet{states: []fleet.ServerState{healthyState()}}, Now: func() time.Time { return t0 }})
	for _, absent := range []string{"oob_fan_lease_active", "oob_console_sessions_active", "oob_notify_", "oob_audit_",
		"oob_login_failures_total", "oob_process_start_time_seconds"} {
		if strings.Contains(out, absent) {
			t.Errorf("%s written without its source", absent)
		}
	}
	if !strings.Contains(out, `oob_server_maintenance{server="storage"} 0`) {
		t.Error("maintenance hook absent must read 0")
	}
	if !strings.Contains(out, "oob_process_goroutines ") {
		t.Error("default runtime stats missing")
	}
}

func manySensors(n int) fleet.ServerState {
	temps := make([]bmc.Temperature, n)
	fans := make([]bmc.Fan, n)
	for i := range temps {
		temps[i] = bmc.Temperature{ID: "t" + strings.Repeat("x", i), Name: "T", Celsius: r(30)}
		fans[i] = bmc.Fan{ID: "f" + strings.Repeat("x", i), Name: "F", Speed: r(1000), Units: bmc.FanRPM}
	}
	s := healthyState()
	s.Snapshot = bmc.NewSnapshot(bmc.SnapshotParams{TakenAt: t0, PowerState: bmc.PowerOn, Health: bmc.HealthOK,
		Temperatures: temps, Fans: fans})
	return s
}

func TestCardinalityCaps(t *testing.T) {
	out := render(t, Config{Fleet: staticFleet{states: []fleet.ServerState{manySensors(MaxSensorsPerServer + 10)}},
		Now: func() time.Time { return t0 }})
	if n := strings.Count(out, "\noob_temperature_celsius{"); n != MaxSensorsPerServer {
		t.Fatalf("temperature series = %d, want %d", n, MaxSensorsPerServer)
	}
	if n := strings.Count(out, "\noob_fan_speed_rpm{"); n != MaxSensorsPerServer {
		t.Fatalf("fan series = %d, want %d", n, MaxSensorsPerServer)
	}
	// 10 temperatures × 3 families + 10 fans.
	if !strings.Contains(out, "\noob_scrape_series_dropped 40\n") {
		t.Fatalf("dropped count missing:\n%s", out[strings.LastIndex(out, "# HELP"):])
	}
}

func TestNotifyTargetCap(t *testing.T) {
	ts := make([]NotifyTarget, MaxNotifyTargets+2)
	for i := range ts {
		ts[i] = NotifyTarget{ID: "t" + strings.Repeat("x", i), Enabled: true}
	}
	out := render(t, Config{Fleet: staticFleet{}, NotifyTargets: func() []NotifyTarget { return ts }, Now: func() time.Time { return t0 }})
	if n := strings.Count(out, "\noob_notify_target_failing{"); n != MaxNotifyTargets {
		t.Fatalf("target series = %d", n)
	}
	if !strings.Contains(out, "\noob_scrape_series_dropped 8\n") {
		t.Fatal("dropped targets not counted")
	}
}

func TestRenderCache(t *testing.T) {
	var reads atomic.Int64
	now := t0
	cfg := Config{Fleet: staticFleet{states: []fleet.ServerState{healthyState()}, reads: &reads},
		Now: func() time.Time { return now }}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := c.Render(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if reads.Load() != 1 {
		t.Fatalf("fleet read %d times within the cache window", reads.Load())
	}
	now = now.Add(DefaultCacheFor)
	if _, err := c.Render(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reads.Load() != 2 {
		t.Fatal("cache not refreshed after its window")
	}
}

func TestServeHTTP(t *testing.T) {
	c, err := New(Config{Fleet: staticFleet{states: []fleet.ServerState{healthyState()}}})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	c.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != ContentType ||
		rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), "oob_server_up") {
		t.Fatalf("GET: %d %v", rec.Code, rec.Header())
	}
	rec = httptest.NewRecorder()
	c.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodHead, "/metrics", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("HEAD: %d, %d bytes", rec.Code, rec.Body.Len())
	}
}

func TestNewRequiresFleet(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("collector without a fleet accepted")
	}
}

func TestLoginCounter(t *testing.T) {
	var nilCounter *LoginCounter
	nilCounter.Failure(StagePassword) // must not panic
	c := &LoginCounter{}
	c.Failure("weird")
	out := render(t, Config{Fleet: staticFleet{}, Logins: c, Now: func() time.Time { return t0 }})
	if !strings.Contains(out, `oob_login_failures_total{stage="other"} 1`) ||
		!strings.Contains(out, `oob_login_failures_total{stage="password"} 0`) {
		t.Fatalf("login counter:\n%s", out)
	}
}

func TestEveryLineParses(t *testing.T) {
	out := render(t, fullConfig(staticFleet{states: []fleet.ServerState{healthyState(), staleState(), neverPolled()}}))
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if strings.HasPrefix(line, "# HELP ") || strings.HasPrefix(line, "# TYPE ") {
			continue
		}
		if !parseSampleLine(line) {
			t.Errorf("unparsable line %q", line)
		}
	}
	if !bytes.HasSuffix([]byte(out), []byte("\n")) {
		t.Error("exposition must end with a newline")
	}
}

func TestPowerStates(t *testing.T) {
	cases := map[bmc.PowerState]string{bmc.PowerOn: "on", bmc.PowerOff: "off", bmc.PowerPoweringOn: "powering_on",
		bmc.PowerPoweringOff: "powering_off", bmc.PowerUnknown: "unknown"}
	for in, want := range cases {
		s := fleet.ServerState{HasSnapshot: true, Snapshot: bmc.NewSnapshot(bmc.SnapshotParams{PowerState: in})}
		if got := powerState(s, true); got != want {
			t.Errorf("%s: %s, want %s", in, got, want)
		}
	}
}
