package api

import (
	"context"
	"encoding/csv"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
	"oob-manager/internal/history"
	"oob-manager/internal/store"
	"oob-manager/internal/web"
)

// newHistory is a real history service over a temporary database holding 6 hours of
// one-minute samples for r730xd, ending at t0.
func newHistory(t *testing.T) *history.Service {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oob.db")
	db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	ro, err := store.OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ro.Close(); _ = db.Close() })
	for ts := t0.Add(-6 * time.Hour); ts.Before(t0); ts = ts.Add(time.Minute) {
		if _, err = db.History().Insert(ctx, store.SensorPoll{ServerID: "r730xd", TS: ts, Samples: []store.SensorSample{
			{Key: "temp:cpu1", Kind: store.SensorTemp, Unit: store.UnitCelsius, Name: "=CPU1 Temp", Value: 40 + float64(ts.Minute()%10)},
			{Key: "power:consumed", Kind: store.SensorPower, Unit: store.UnitWatts, Name: "Power draw", Value: 250},
		}}); err != nil {
			t.Fatal(err)
		}
	}
	svc, err := history.New(history.Config{Writer: db.History(), Reader: ro.History(), Audit: ro.AuditSearch(),
		Retention: func() history.Retention { return history.Retention{RawDays: 7, HourlyDays: 90, DailyDays: 730} },
		Now:       func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestHistorySensorsAndSeries(t *testing.T) {
	a := newTestAPI(t, Deps{History: newHistory(t)})
	sensors := decode[struct {
		Data []sensorJSON `json:"data"`
	}](t, do(t, a, http.MethodGet, "/api/v1/servers/r730xd/history/sensors", goodToken))
	if len(sensors.Data) != 2 || sensors.Data[0].Key != "temp:cpu1" || sensors.Data[0].Unit != "celsius" ||
		sensors.Data[1].Kind != "power" || sensors.Data[0].First == nil {
		t.Fatalf("sensors = %+v", sensors)
	}
	got := decode[struct {
		Data []pointJSON `json:"data"`
		Meta seriesMeta  `json:"meta"`
	}](t, do(t, a, http.MethodGet, "/api/v1/servers/r730xd/history?sensor=temp:cpu1&range=24h", goodToken))
	if len(got.Data) != 36 || got.Meta.Tier != "raw" || got.Meta.StepS != 600 || got.Meta.Points != 144 ||
		got.Meta.Unit != "celsius" || got.Meta.ClockJump != nil || len(got.Meta.Tiers) != 1 || got.Data[0].N != 10 ||
		got.Data[0].Min != 40 || got.Data[0].Max != 49 {
		t.Fatalf("series = %d points, meta %+v, first %+v", len(got.Data), got.Meta, got.Data)
	}
	custom := decode[struct {
		Data []pointJSON `json:"data"`
		Meta seriesMeta  `json:"meta"`
	}](t, do(t, a, http.MethodGet, "/api/v1/servers/r730xd/history?sensor=power:consumed&from=2026-10-20T06:00:00Z&to=2026-10-20T12:00:00Z&step=1", goodToken))
	if custom.Meta.StepS != 60 || custom.Meta.Points != 360 || len(custom.Data) != 360 {
		t.Fatalf("custom = %+v (%d points)", custom.Meta, len(custom.Data))
	}
}

func TestHistoryRefusals(t *testing.T) {
	a := newTestAPI(t, Deps{History: newHistory(t)})
	for path, want := range map[string]int{
		"/api/v1/servers/nope/history/sensors":                               http.StatusNotFound,
		"/api/v1/servers/r730xd/history?sensor=temp:nope":                    http.StatusBadRequest,
		"/api/v1/servers/r730xd/history?sensor=temp:cpu1&range=5y":           http.StatusBadRequest,
		"/api/v1/servers/r730xd/history?sensor=temp:cpu1&from=x&to=y":        http.StatusBadRequest,
		"/api/v1/servers/r730xd/history.csv?all=1&range=24h":                 http.StatusForbidden,
		"/api/v1/servers/r730xd/history.csv?sensor=temp:cpu1&range=1y&raw=1": http.StatusBadRequest,
	} {
		w := do(t, a, http.MethodGet, path, goodToken)
		assertProblem(t, w, want)
	}
	if w := do(t, a, http.MethodGet, "/api/v1/servers/r730xd/history/sensors", ""); w.Code != http.StatusUnauthorized {
		t.Errorf("no token: %d", w.Code)
	}
	none := newTestAPI(t, Deps{})
	assertProblem(t, do(t, none, http.MethodGet, "/api/v1/servers/r730xd/history/sensors", goodToken), http.StatusNotFound)
}

func TestHistoryCSV(t *testing.T) {
	a := newTestAPI(t, Deps{History: newHistory(t), ExportsPerMinute: 2})
	w := do(t, a, http.MethodGet, "/api/v1/servers/r730xd/history.csv?sensor=temp:cpu1&range=24h&raw=1", goodToken)
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/csv; charset=utf-8" ||
		w.Header().Get("Content-Disposition") != `attachment; filename="r730xd_temp-cpu1_24h_raw_20261020T1200Z.csv"` ||
		w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("csv %d %v", w.Code, w.Header())
	}
	recs, err := csv.NewReader(w.Body).ReadAll()
	if err != nil || len(recs) != 361 || recs[1][3] != "'=CPU1 Temp" || recs[0][0] != "timestamp_utc" {
		t.Fatalf("records %d %q %v", len(recs), recs[1], err)
	}
	bucketed := do(t, a, http.MethodGet, "/api/v1/servers/r730xd/history.csv?sensor=temp:cpu1&range=24h", goodToken)
	recs, err = csv.NewReader(bucketed.Body).ReadAll()
	if err != nil || len(recs) != 37 || recs[0][0] != "bucket_start_utc" {
		t.Fatalf("bucketed %d %v", len(recs), err)
	}
	third := do(t, a, http.MethodGet, "/api/v1/servers/r730xd/history.csv?sensor=temp:cpu1", goodToken)
	if third.Code != http.StatusTooManyRequests || third.Header().Get("Retry-After") == "" {
		t.Fatalf("third export within a minute: %d", third.Code)
	}
}

// historyDriver counts every BMC call.
type historyDriver struct{ calls atomic.Int64 }

func (d *historyDriver) Probe(context.Context) (bmc.Capabilities, error) {
	d.calls.Add(1)
	return bmc.NewCapabilities(bmc.CapabilityParams{}), nil
}

func (d *historyDriver) Snapshot(context.Context) (bmc.Snapshot, error) {
	d.calls.Add(1)
	return healthyState().Snapshot, nil
}

func (d *historyDriver) EventLog(context.Context, time.Time) (bmc.EventLog, error) {
	d.calls.Add(1)
	return bmc.NewEventLog("sel", nil, true), nil
}

func (d *historyDriver) Inventory(context.Context) (bmc.Inventory, error) {
	d.calls.Add(1)
	return bmc.Inventory{}, nil
}

// TestHistoryNeverCallsTheBMC: 50 history requests against a real, polled fleet add no
// driver call.
func TestHistoryNeverCallsTheBMC(t *testing.T) {
	d := &historyDriver{}
	fl, err := fleet.New(fleet.Config{Targets: []fleet.Target{{ID: "r730xd", Name: "R730XD", Driver: d}},
		Interval: time.Hour, CycleTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { fl.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	deadline := time.Now().Add(10 * time.Second)
	for {
		if s, _ := fl.Server("r730xd"); s.HasSnapshot && s.HasInventory && s.HasSEL {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("first poll never completed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	a := newTestAPI(t, Deps{Fleet: fl, History: newHistory(t), ExportsPerMinute: 100})
	before := d.calls.Load()
	paths := []string{"/api/v1/servers/r730xd/history/sensors", "/api/v1/servers/r730xd/history?sensor=temp:cpu1&range=7d",
		"/api/v1/servers/r730xd/history.csv?sensor=power:consumed&range=30d"}
	for i := 0; i < 50; i++ {
		if w := do(t, a, http.MethodGet, paths[i%len(paths)], goodToken); w.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", paths[i%len(paths)], w.Code, strings.TrimSpace(w.Body.String()))
		}
	}
	if after := d.calls.Load(); after != before {
		t.Fatalf("history requests called the BMC %d times", after-before)
	}
}

// brokenStream is the real history with a stream that fails after the first rows.
type brokenStream struct{ HistoryView }

func (b brokenStream) WriteCSV(_ context.Context, w io.Writer, flush func(), _ history.PreparedExport) error {
	_, _ = io.WriteString(w, "bucket_start_utc,bucket_end_utc\r\n2026-10-20T00:00:00Z,2026-10-20T00:10:00Z\r\n")
	flush()
	return errors.New("disk read failed")
}

// TestHistoryCSVFailureAbortsTheResponse (review MEDIUM-2): a stream that fails after the
// headers went out ends the connection without the chunked terminator, so the client
// reads an error, never a clean end of a cut file.
func TestHistoryCSVFailureAbortsTheResponse(t *testing.T) {
	a := newTestAPI(t, Deps{History: brokenStream{newHistory(t)}})
	h, err := web.NewHandler(a, web.Options{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		srv.URL+"/api/v1/servers/r730xd/history.csv?sensor=temp:cpu1&range=24h", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+goodToken)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || err == nil || !strings.Contains(string(body), "bucket_start_utc") {
		t.Fatalf("status %d, read error %v (want an aborted body), %q", resp.StatusCode, err, body)
	}
}
