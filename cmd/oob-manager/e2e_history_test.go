//go:build e2e

package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/config"
	"oob-manager/internal/fleet"
	"oob-manager/internal/history"
	"oob-manager/internal/secrets"
	"oob-manager/internal/store"
)

// History seeding (tech_doc §39): 48 hours of samples every 5 minutes for both servers,
// written into the install's database before serve starts, so the History tab, the
// sparklines, the exports and the janitor's first rollup have data. The sensor keys come
// from a snapshot of a SEPARATE mock built from the same fixture: the stack's own mocks
// see no extra request or session.
//
// The seed is deterministic on the sparkline grid (history.SparkStep, 30 minutes since
// the epoch): it ends on a grid line, and its wave is indexed from that end, so every
// run draws the same 24 h sparklines and Overview recorder (the visual baseline compares
// them) whatever the minute the stack starts. The last bucket holds the fixture's
// constant values only (seeded up to a minute before now, then the live polls). Only a run that crosses a grid line between
// seeding and a screenshot shifts the window by one bucket.
const (
	seedSpan = 48 * time.Hour
	seedStep = 5 * time.Minute
	// rawMinRows/rawMaxRows bound a 24 h raw export: 20 h of seed points at least, and
	// one full day of seed points plus a margin for live polls at most.
	rawMinRows = int(20 * time.Hour / seedStep)
	rawMaxRows = int(24*time.Hour/seedStep) + 60
)

func (s *stack) seedHistory(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	cfg, err := config.Load(s.configPath)
	if err != nil {
		t.Fatal(err)
	}
	creds, err := secrets.ParseCredentials([]byte("ro: {username: " + redfishmock.User + ", password: " + redfishmock.Password + "}\n"))
	if err != nil {
		t.Fatal(err)
	}
	ro, err := creds.Lookup("ro")
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, s.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	now := time.Now()
	end := seedEnd(now)
	s.seedEnd = end
	for _, srv := range e2eServers() {
		samples := seedSamples(t, cfg, srv, ro)
		if err := db.WithTx(ctx, func(tx *store.Tx) error { return insertSeed(ctx, tx, srv.id, samples, end, now) }); err != nil {
			t.Fatalf("seed %s: %v", srv.id, err)
		}
	}
}

// seedEnd is the grid line at or before now. Seed points after it carry the fixture's
// values and stop a minute before now, older than the first live poll (no clock jump).
func seedEnd(now time.Time) time.Time { return now.Truncate(history.SparkStep) }

// seedSamples reads one snapshot of srv's fixture from a throwaway mock.
func seedSamples(t *testing.T, cfg config.Config, srv e2eServer, ro secrets.Credential) []store.SensorSample {
	t.Helper()
	m := redfishmock.New(t, redfishmock.FixtureDir(t, srv.fixture))
	var cs config.Server
	for _, x := range cfg.Servers {
		if x.ID == srv.id {
			cs = x
		}
	}
	cs.TLSPinSHA256 = m.PinSHA256()
	d, err := bmcDriverAt(cs, ro, m.URL())
	if err != nil {
		t.Fatal(err)
	}
	snap, err := d.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("seed snapshot of %s: %v", srv.id, err)
	}
	if c, ok := d.(fleet.Closer); ok {
		_ = c.Close(context.Background())
	}
	return fleet.HistorySamples(snap, fleet.AllSampling())
}

// insertSeed writes the wave up to end, then the fixture's own values (what the live
// polls read) every seedStep up to a minute before now, so no bucket is empty before the
// first live poll and the current sparkline bucket averages the same value every run.
func insertSeed(ctx context.Context, tx *store.Tx, id string, samples []store.SensorSample, end, now time.Time) error {
	for ts := end; !ts.After(now.Add(-time.Minute)); ts = ts.Add(seedStep) {
		if _, err := tx.History().Insert(ctx, store.SensorPoll{ServerID: id, TS: ts, Samples: samples}); err != nil {
			return err
		}
	}
	n := int(seedSpan / seedStep)
	for i := 0; i < n; i++ {
		p := store.SensorPoll{ServerID: id, TS: end.Add(-time.Duration(n-i) * seedStep)}
		wave := math.Sin(float64(i) / 18)
		for _, sm := range samples {
			sm.Value += wave * seedSpread(sm.Unit)
			p.Samples = append(p.Samples, sm)
		}
		if _, err := tx.History().Insert(ctx, p); err != nil {
			return err
		}
	}
	return nil
}

func seedSpread(u store.SensorUnit) float64 {
	switch u {
	case store.UnitCelsius:
		return 3
	case store.UnitVolts:
		return 0.02
	case store.UnitPercent:
		return 4
	default:
		return 60
	}
}

type e2eSensor struct {
	Key, Kind string
}

type e2eSeries struct {
	Data []struct {
		T   time.Time `json:"t"`
		Avg float64   `json:"avg"`
		N   int64     `json:"n"`
	} `json:"data"`
	Meta struct {
		Tier  string   `json:"tier"`
		Tiers []string `json:"tiers"`
	} `json:"meta"`
}

// checkHistory runs on its own stack: the History tab renders a panel per sampled kind
// with charts and data tables; the Hardware tab has sparklines; a CSV download parses
// with the expected rows and matches the API's JSON; the janitor's first pass rolled the
// seed up (the 7-day series is served from hourly rows); and none of it reached a BMC.
func checkHistory(t *testing.T) {
	s := startStack(t, "127.0.0.1:0")
	b := browser{t: t, base: s.base, c: s.client(t)}
	login(t, b, s)
	var sensors struct{ Data []e2eSensor }
	decodeJSON(t, b.do(http.MethodGet, "/api/v1/servers/r730xd/history/sensors", s.token, nil), &sensors)
	if len(sensors.Data) < 5 {
		t.Fatalf("sensors %+v", sensors)
	}
	tab := b.get("/servers/r730xd/history")
	expectPage(t, tab, `href="/servers/r730xd/history" aria-current="page">`, `role="img"`, "Data table:", "Events in this period")
	for kind, panel := range map[string]string{"temp": `id="h-temp"`, "fan": `id="h-fan"`, "power": `id="h-power"`,
		"psu_in": `id="h-psu"`, "volt": `id="h-volt"`} {
		if hasKind(sensors.Data, kind) && !strings.Contains(tab.body, panel) {
			t.Errorf("no %s panel for the %s sensors", panel, kind)
		}
	}
	expectPage(t, b.get("/servers/r730xd"), `<a class="spark" href="/servers/r730xd/history?focus=`)
	key := sensors.Data[0].Key
	// The janitor rolled the seed up at startup: the 7-day series comes from hourly rows.
	// (Polled slowly: every API call spends from the shared token's 60 a minute.)
	for try := 0; ; try++ {
		var w e2eSeries
		decodeJSON(t, b.do(http.MethodGet, "/api/v1/servers/r730xd/history?range=7d&sensor="+url.QueryEscape(key), s.token, nil), &w)
		if w.Meta.Tier == "hourly" && len(w.Data) >= 47 && strings.Contains(strings.Join(w.Meta.Tiers, ","), "hourly") {
			break
		}
		if try == 20 {
			t.Fatalf("the seed was not rolled up: %+v (%d points)", w.Meta, len(w.Data))
		}
		time.Sleep(500 * time.Millisecond)
	}
	checkHistoryCSVMatchesJSON(t, b, s, key)
	assertHistorySilent(t, b, s, key)
}

func hasKind(ss []e2eSensor, kind string) bool {
	for _, s := range ss {
		if s.Kind == kind {
			return true
		}
	}
	return false
}

func decodeJSON(t *testing.T, p page, v any) {
	t.Helper()
	if p.status != http.StatusOK {
		t.Fatalf("status %d: %s", p.status, p.body)
	}
	if err := json.Unmarshal([]byte(p.body), v); err != nil {
		t.Fatalf("decode %s: %v", p.body, err)
	}
}

// checkHistoryCSVMatchesJSON compares the API's series and the UI's CSV for the same
// sensor and a closed window (one that ended before the live polls), bucket by bucket.
func checkHistoryCSVMatchesJSON(t *testing.T, b browser, s *stack, key string) {
	t.Helper()
	to := time.Now().Add(-time.Hour).Truncate(time.Hour)
	q := url.Values{"sensor": {key}, "from": {to.Add(-12 * time.Hour).Format(time.RFC3339)},
		"to": {to.Format(time.RFC3339)}, "step": {"600"}}
	var js e2eSeries
	decodeJSON(t, b.do(http.MethodGet, "/api/v1/servers/r730xd/history?"+q.Encode(), s.token, nil), &js)
	p := b.get("/servers/r730xd/history.csv?" + q.Encode())
	recs, err := csv.NewReader(strings.NewReader(p.body)).ReadAll()
	if p.status != http.StatusOK || err != nil || len(recs) != 1+72 || len(js.Data) != 72 {
		t.Fatalf("csv %d, %d records, %v; json %d points", p.status, len(recs), err, len(js.Data))
	}
	for i, d := range js.Data {
		row := recs[i+1]
		avg, _ := strconv.ParseFloat(row[8], 64)
		if row[0] != d.T.Format(time.RFC3339) || avg != d.Avg || row[10] != strconv.FormatInt(d.N, 10) {
			t.Fatalf("bucket %d: csv %v, json %+v", i, row, d)
		}
	}
	raw := b.get("/servers/r730xd/history.csv?range=24h&raw=1&sensor=" + url.QueryEscape(key))
	rr, err := csv.NewReader(strings.NewReader(raw.body)).ReadAll()
	// Raw rows are every seeded 5-minute point inside the sliding 24 h window. The window
	// moves on while the test runs, so the exact count depends on timing; well above the
	// 144 ten-minute buckets and at most every seed point (plus live polls) proves raw mode.
	if raw.status != http.StatusOK || err != nil || len(rr) < 1+rawMinRows || len(rr) > 1+rawMaxRows || rr[0][0] != "timestamp_utc" {
		t.Fatalf("raw csv %d, %d records (want %d..%d data rows), %v", raw.status, len(rr), rawMinRows, rawMaxRows, err)
	}
}

// assertHistorySilent: a burst of History pages, series and exports adds no request to
// any mock BMC (the pollers keep running, so a burst that overlaps a poll is retried).
func assertHistorySilent(t *testing.T, b browser, s *stack, key string) {
	t.Helper()
	count := func() int {
		n := 0
		for _, m := range s.mocks {
			n += len(m.Requests())
		}
		return n
	}
	for range 3 {
		before := count()
		for _, r := range []string{"24h", "7d", "30d", "1y"} {
			expectPage(t, b.get("/servers/r730xd/history?range="+r))
		}
		decodeJSON(t, b.do(http.MethodGet, "/api/v1/servers/r240/history/sensors", s.token, nil), &struct{}{})
		if p := b.get("/servers/r730xd/history.csv?range=7d&sensor=" + url.QueryEscape(key)); p.status != http.StatusOK {
			t.Fatalf("export: %d", p.status)
		}
		if count() == before {
			return
		}
	}
	t.Fatal("every history burst coincided with BMC requests")
}
