package ui

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/config"
	"oob-manager/internal/fleet"
	"oob-manager/internal/history"
	"oob-manager/internal/store"
	"oob-manager/internal/web"
)

// newHistorySvc is a real history service over a temporary database: 48 hours of
// samples every 10 minutes for r730xd's fixture sensors (taken from the fixture
// snapshot, so keys match the Hardware tab), a power action two hours ago, and one
// janitor pass.
func newHistorySvc(t *testing.T, now time.Time) *history.Service {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "hist.db")
	db, err := store.Open(ctx, path)
	must(t, err)
	ro, err := store.OpenReadOnly(ctx, path)
	must(t, err)
	t.Cleanup(func() { _ = ro.Close(); _ = db.Close() })
	samples := fleet.HistorySamples(snapshotAt(now, bmc.HealthOK), fleet.AllSampling())
	for i, ts := 0, now.Add(-48*time.Hour); ts.Before(now); i, ts = i+1, ts.Add(10*time.Minute) {
		poll := store.SensorPoll{ServerID: "r730xd", TS: ts}
		for _, s := range samples {
			s.Value += float64(i % 6)
			poll.Samples = append(poll.Samples, s)
		}
		_, err = db.History().Insert(ctx, poll)
		must(t, err)
	}
	at := now.Add(-2 * time.Hour)
	lg := audit.NewLogger(db.Audit(), nil, func() time.Time { return at }, quiet())
	_, err = lg.Record(ctx, audit.Entry{Principal: "ops", ServerID: "r730xd", Action: string(authz.PowerGracefulRestart),
		Result: audit.ResultStarted})
	must(t, err)
	svc, err := history.New(history.Config{Writer: db.History(), Reader: ro.History(), Audit: ro.AuditSearch(),
		Retention: func() history.Retention { return history.Retention{RawDays: 7, HourlyDays: 90, DailyDays: 730} },
		Now:       func() time.Time { return now }, Logger: quiet()})
	must(t, err)
	must(t, svc.RunOnce(ctx))
	return svc
}

func withHistory(t *testing.T) func(*Deps) {
	return func(d *Deps) { d.History = newHistorySvc(t, d.Now()) }
}

var focusPath = regexp.MustCompile(`class="ser ser-focus" d="([^"]*)"`)

// section is the History panel with the given id.
func section(t *testing.T, body, id string) string {
	t.Helper()
	i := strings.Index(body, `<section class="panel hist-panel" id="`+id+`"`)
	if i < 0 {
		t.Fatalf("no panel %s", id)
	}
	j := strings.Index(body[i:], "</section>")
	return body[i : i+j]
}

func TestHistoryTabViewer(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t, withHistory(t))
	h.fleet.logs["r730xd/sel"] = bmc.NewEventLog("", []bmc.Event{{ID: "9", Created: h.clock.Now().Add(-3 * time.Hour),
		Severity: bmc.SeverityCritical, Message: "<b>PSU 2</b> lost input"}}, true)
	page := result(c.get("/servers/r730xd/history")).status(t, http.StatusOK)
	page.contains(t, "<h1>Storage node R730XD: history", `href="/servers/r730xd/history" aria-current="page">`,
		`aria-current="page">24 hours</a>`, `href="/servers/r730xd/history?range=7d"`, ">Temperatures ", ">Fans ",
		">Power draw ", ">Power supplies ", `role="img" aria-labelledby="h-temp-t h-temp-d"`,
		`<title id="h-temp-t">Temperatures: CPU1 Temp, last 24 hours</title>`, "minimum 48.0 °C",
		`href="/servers/r730xd/history?focus=temp%3A0&amp;range=24h#h-temp"`, "Data table: CPU1 Temp",
		`href="/servers/r730xd/history.csv?range=24h&amp;sensor=temp%3A1"`, "Every sample (CSV)",
		"Graceful restart requested by ops", "&lt;b&gt;PSU 2&lt;/b&gt; lost input", `class="mark mark-crit"`,
		"Thresholds now: warning above 85.0 °C.").
		lacks(t, "<b>PSU 2</b>", "Export every sensor", " style=", "<script>")
	body := page.rec.Body.String()
	temp := section(t, body, "h-temp")
	rows := strings.Count(temp, `<tr><th scope="row"`)
	m := focusPath.FindStringSubmatch(temp)
	if m == nil || rows != 144 || len(regexp.MustCompile(`[ML]`).FindAllString(m[1], -1)) != rows {
		t.Fatalf("the data table (%d rows) must list every point of the focused line (%v)", rows, m != nil)
	}
}

func TestHistoryRangesAndFocus(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t, withHistory(t))
	week := result(c.get("/servers/r730xd/history?range=7d&focus=temp:0")).status(t, http.StatusOK)
	week.contains(t, `aria-current="page">7 days</a>`, `<title id="h-temp-t">Temperatures: System Board Inlet Temp, last 7 days</title>`,
		`href="/servers/r730xd/history?focus=temp%3A0&amp;range=24h"`, "Thresholds now: warning above 42.0 °C, critical above 47.0 °C.")
	if rows := strings.Count(section(t, week.rec.Body.String(), "h-temp"), `<tr><th scope="row"`); rows != 48 {
		t.Errorf("7 days of hourly buckets over 48 h of data: %d rows", rows)
	}
	result(c.get("/servers/r730xd/history?range=1y")).status(t, http.StatusOK).contains(t, "last 1 year").lacks(t, "Every sample (CSV)")
	result(c.get("/servers/r730xd/history?focus=temp:nope")).status(t, http.StatusOK).
		contains(t, "Temperatures: CPU1 Temp")
	result(c.get("/servers/r730xd/history?range=5y")).status(t, http.StatusBadRequest)
	result(c.get("/servers/r240/history")).status(t, http.StatusOK).contains(t, "No history yet")
	result(c.get("/servers/nope/history")).status(t, http.StatusNotFound)
}

func TestHistorySparklinesOnTheHardwareTab(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t, withHistory(t))
	page := result(c.get("/servers/r730xd")).status(t, http.StatusOK)
	page.contains(t, `<a class="spark" href="/servers/r730xd/history?focus=temp%3A2&amp;range=24h#h-temp">`,
		`href="/servers/r730xd/history?focus=temp%3A0&amp;range=24h#h-temp"`,
		`href="/servers/r730xd/history?focus=power%3Aconsumed&amp;range=24h#h-power"`,
		`<title id="sp-hot-t">CPU2 Temp, last 24 hours</title>`, `<desc id="sp-draw-d">Minimum 241 W, average`)
	if n := strings.Count(page.rec.Body.String(), `<a class="spark"`); n != 3 {
		t.Errorf("%d sparklines, want 3", n)
	}
	result(c.get("/servers/r240")).status(t, http.StatusOK).lacks(t, `class="spark"`)
}

func TestHistoryHiddenWithoutTheService(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t)
	result(c.get("/servers/r730xd")).status(t, http.StatusOK).lacks(t, ">History</a>", `class="spark"`)
	result(c.get("/servers/r730xd/history")).status(t, http.StatusNotFound)
	result(c.get("/servers/r730xd/history.csv?sensor=temp:0")).status(t, http.StatusNotFound)
}

func TestHistoryCSV(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t, withHistory(t))
	rec := c.get("/servers/r730xd/history.csv?sensor=temp:1&range=24h")
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "text/csv; charset=utf-8" ||
		rec.Header().Get("Content-Disposition") != `attachment; filename="r730xd_temp-1_24h_20261020T1200Z.csv"` ||
		rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("csv %d %v", rec.Code, rec.Header())
	}
	recs, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil || len(recs) != 145 || recs[1][4] != "CPU1 Temp" || recs[1][6] != "celsius" {
		t.Fatalf("records %d %v %v", len(recs), recs[1], err)
	}
	raw, err := csv.NewReader(c.get("/servers/r730xd/history.csv?sensor=temp:1&range=24h&raw=1").Body).ReadAll()
	if err != nil || len(raw) != 145 || raw[0][0] != "timestamp_utc" {
		t.Fatalf("raw %d %v", len(raw), err)
	}
	result(c.get("/servers/r730xd/history.csv?all=1&range=24h")).status(t, http.StatusForbidden)
	if _, ok := h.audit.find(string(authz.ExportHistoryAll), audit.ResultDenied); !ok {
		t.Error("a refused export-all is audited")
	}
	result(c.get("/servers/r730xd/history.csv?sensor=temp:nope")).status(t, http.StatusBadRequest)
	result(c.get("/servers/r730xd/history.csv?sensor=temp:1&range=forever")).status(t, http.StatusBadRequest)
	result(c.get("/servers/r730xd/history.csv?sensor=temp:1&range=1y&raw=1")).status(t, http.StatusBadRequest)
	for i := 0; i < 3; i++ {
		_ = c.get("/servers/r730xd/history.csv?sensor=temp:1")
	}
	result(c.get("/servers/r730xd/history.csv?sensor=temp:1")).status(t, http.StatusTooManyRequests)
	if _, ok := h.audit.find(string(authz.ExportHistory), audit.ResultDenied); !ok {
		t.Error("a rate-limited export is audited")
	}
}

func TestHistoryExportAllForOperators(t *testing.T) {
	t.Parallel()
	_, c := signedInOperator(t, withHistory(t))
	result(c.get("/servers/r730xd/history")).status(t, http.StatusOK).
		contains(t, `href="/servers/r730xd/history.csv?all=1&amp;range=24h" download>Export every sensor (CSV)</a>`)
	rec := c.get("/servers/r730xd/history.csv?all=1&range=24h")
	recs, err := csv.NewReader(rec.Body).ReadAll()
	if rec.Code != http.StatusOK || err != nil || len(recs) != 1+8*144 ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "r730xd_all-sensors_24h_") {
		t.Fatalf("export all: %d, %d records, %v, %v", rec.Code, len(recs), err, rec.Header())
	}
}

// TestGeneralHistoryGroup: Settings → General shows the history keys as their own group
// with the size line, switches as On/Off and retention in days, a file-managed key
// locked, and saves them like the other keys.
func TestGeneralHistoryGroup(t *testing.T) {
	t.Parallel()
	e, svc := newGeneralEnv(t, "history: { daily_days: 400 }\n")
	e.deps.History = newHistorySvc(t, e.clock.Now())
	app, err := New(e.deps)
	must(t, err)
	e.handler, err = web.NewHandler(app, web.Options{Logger: quiet()})
	must(t, err)
	c := e.adminClient()
	result(c.get("/settings/general")).status(t, http.StatusOK).contains(t, `<h3 id="gen-hist-h" class="gen-group">Sensor history</h3>`,
		"Database file ", "raw samples", `name="history.sample_psus"`, `<option value="on" selected>On</option>`,
		`max="30" step="1" required value="7"`, `<span>days</span>`, "Set in config.yaml (history.daily_days)")
	rec := c.submit("/settings/general", "/settings/general", url.Values{"rev": {"0"},
		config.KeyHistoryRawDays: {"3"}, config.KeyHistorySampleVoltages: {"off"}})
	result(rec).status(t, http.StatusSeeOther).location(t, "/settings/general?done=general")
	if g := svc.Current().General; g.HistoryRawDays != 3 || g.SampleVoltages || g.HistoryDailyDays != 400 {
		t.Fatalf("not applied: %+v", g)
	}
	rec = c.submit("/settings/general", "/settings/general", url.Values{"rev": {"1"},
		config.KeyHistoryRawDays: {"20"}, config.KeyHistoryHourlyDays: {"10"}})
	result(rec).status(t, http.StatusUnprocessableEntity).contains(t, `id="g-history-hourly-days"`, `aria-invalid="true"`)
}

// TestHistoryPanelCapsItsLists: a kind with hundreds of sensors draws 16 lines, lists 48
// more as links and counts the rest.
func TestHistoryPanelCapsItsLists(t *testing.T) {
	t.Parallel()
	var series []history.Series
	for i := 0; i < 100; i++ {
		series = append(series, history.Series{Key: store.SensorKey{ID: int64(i), Key: fmt.Sprintf("temp:%03d", i),
			Kind: store.SensorTemp, Unit: store.UnitCelsius}})
	}
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	hc := histCtx{serverID: "r1", plan: history.PlanFor(history.Range24h, now), now: now, tf: fmtIn(time.UTC), focus: "temp:090"}
	p := hc.buildPanel(panelSpecs()[0], series)
	if len(p.Legend) != maxChartSeries || len(p.Also) != maxAlso || p.AlsoMore != 100-maxChartSeries-maxAlso {
		t.Fatalf("legend %d, also %d, more %d", len(p.Legend), len(p.Also), p.AlsoMore)
	}
	if !p.Legend[maxChartSeries-1].Current || p.Legend[maxChartSeries-1].Label != "temp:090" {
		t.Errorf("the focus is always drawn: %+v", p.Legend[maxChartSeries-1])
	}
}

// brokenHistory is the real history with a stream that fails after the first bytes.
type brokenHistory struct{ History }

func (b brokenHistory) WriteCSV(_ context.Context, w io.Writer, _ func(), _ history.PreparedExport) error {
	_, _ = io.WriteString(w, "bucket_start_utc\r\n")
	return errors.New("disk read failed")
}

// TestHistoryCSVFailureAbortsTheDownload (review MEDIUM-2): the handler aborts the
// response (http.ErrAbortHandler through the middleware), so net/http drops the
// connection instead of ending a cut file cleanly.
func TestHistoryCSVFailureAbortsTheDownload(t *testing.T) {
	t.Parallel()
	_, c := signedIn(t, func(d *Deps) { d.History = brokenHistory{newHistorySvc(t, d.Now())} })
	defer func() {
		if v := recover(); v != http.ErrAbortHandler { //nolint:errorlint // the sentinel value net/http re-panics
			t.Fatalf("recovered %v, want http.ErrAbortHandler", v)
		}
	}()
	c.get("/servers/r730xd/history.csv?sensor=temp:1&range=24h")
	t.Fatal("the failed stream returned normally")
}

// TestRefusedExportsDoNotFloodTheAudit (review MEDIUM-3): a viewer looping on the
// operator-only export is rate limited first, and each kind of refusal is audited once a
// minute.
func TestRefusedExportsDoNotFloodTheAudit(t *testing.T) {
	t.Parallel()
	h, c := signedIn(t, withHistory(t))
	for i := 0; i < 20; i++ {
		_ = c.get("/servers/r730xd/history.csv?all=1&range=24h")
	}
	denied := 0
	h.audit.mu.Lock()
	for _, e := range h.audit.entries {
		if e.Result == audit.ResultDenied {
			denied++
		}
	}
	h.audit.mu.Unlock()
	if denied != 2 {
		t.Fatalf("%d denied rows for 20 refused requests; want one forbidden and one rate_limited", denied)
	}
	result(c.get("/servers/r730xd/history.csv?sensor=temp:1")).status(t, http.StatusTooManyRequests)
}

// TestHistoryNotesAClockAhead (review MEDIUM-1): after a restart with the clock days
// ahead of the last janitor pass, the History tab says retention is catching up.
func TestHistoryNotesAClockAhead(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "h.db")
	db, err := store.Open(ctx, path)
	must(t, err)
	ro, err := store.OpenReadOnly(ctx, path)
	must(t, err)
	t.Cleanup(func() { _ = ro.Close(); _ = db.Close() })
	must(t, db.History().SetPass(ctx, now.Add(-5*24*time.Hour), now.Add(-5*24*time.Hour), store.BootMark{}))
	svc, err := history.New(history.Config{Writer: db.History(), Reader: ro.History(), Audit: ro.AuditSearch(),
		Retention: func() history.Retention { return history.Retention{RawDays: 7, HourlyDays: 90, DailyDays: 730} },
		Now:       func() time.Time { return now }, Logger: quiet(),
		Boot: func() (store.BootMark, bool) { return store.BootMark{ID: "new-boot", Uptime: time.Minute}, true }})
	must(t, err)
	must(t, svc.RunOnce(ctx))
	mustInsert := func(ts time.Time) {
		_, ierr := db.History().Insert(ctx, store.SensorPoll{ServerID: "r730xd", TS: ts, Samples: []store.SensorSample{
			{Key: "temp:1", Kind: store.SensorTemp, Unit: store.UnitCelsius, Name: "CPU1 Temp", Value: 40}}})
		must(t, ierr)
	}
	mustInsert(now.Add(-time.Hour))
	_, c := signedIn(t, func(d *Deps) { d.History = svc })
	result(c.get("/servers/r730xd/history")).status(t, http.StatusOK).contains(t,
		"The clock is 4 days ahead of the history&#39;s own clock (a restart after downtime, or the clock moved forward (last seen")
}
