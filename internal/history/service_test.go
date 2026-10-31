package history

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/store"
)

// fixture is a real database (writer and read-only pool) and a service over it.
type fixture struct {
	db  *store.DB
	ro  *store.ReadDB
	svc *Service
	mu  sync.Mutex
	now time.Time
	ret Retention
	// mono is the fake monotonic clock: it follows setNow, and jump moves the wall clock
	// without it.
	mono time.Duration
}

func (f *fixture) elapsed() time.Duration {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.mono
}

// boot is one kernel boot whose uptime is the fake monotonic clock.
func (f *fixture) boot() (store.BootMark, bool) {
	return store.BootMark{ID: "boot-1", Uptime: f.elapsed()}, true
}

// jump steps the wall clock without real time passing.
func (f *fixture) jump(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func (f *fixture) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// setNow moves the wall clock and real time together.
func (f *fixture) setNow(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mono += max(t.Sub(f.now), 0) // real time never runs back
	f.now = t
}

func newFixture(t *testing.T, at time.Time) *fixture {
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
	f := &fixture{db: db, ro: ro, now: at, ret: Retention{RawDays: 7, HourlyDays: 90, DailyDays: 730}}
	svc, err := New(Config{Writer: db.History(), Reader: ro.History(), Audit: ro.AuditSearch(),
		Retention: func() Retention { return f.ret }, Now: f.clock, Elapsed: f.elapsed, Boot: f.boot,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	return f
}

// seed inserts one poll every step from from to to (exclusive) for server, with a
// temperature that follows the minute of the hour and a fan at a fixed speed.
func (f *fixture) seed(t *testing.T, server string, from, to time.Time, step time.Duration) int {
	t.Helper()
	n := 0
	for ts := from; ts.Before(to); ts = ts.Add(step) {
		_, err := f.db.History().Insert(context.Background(), store.SensorPoll{ServerID: server, TS: ts, Samples: []store.SensorSample{
			{Key: "temp:cpu1", Kind: store.SensorTemp, Unit: store.UnitCelsius, Name: "CPU1 Temp", Value: float64(ts.Minute())},
			{Key: "fan:Fan1", Kind: store.SensorFan, Unit: store.UnitRPM, Name: "Fan1", Value: 7000},
		}})
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	return n
}

func (f *fixture) key(t *testing.T, server, key string) store.SensorKey {
	t.Helper()
	keys, err := f.svc.Sensors(context.Background(), server)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range keys {
		if k.Key == key {
			return k
		}
	}
	t.Fatalf("no key %s", key)
	return store.SensorKey{}
}

var base = time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)

func TestNewRequiresDeps(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New without dependencies")
	}
}

func TestSensorsInDisplayOrder(t *testing.T) {
	f := newFixture(t, base)
	f.seed(t, "r1", base, base.Add(10*time.Minute), 5*time.Minute)
	keys, err := f.svc.Sensors(context.Background(), "r1")
	if err != nil || len(keys) != 2 || keys[0].Kind != store.SensorTemp || keys[1].Kind != store.SensorFan {
		t.Fatalf("Sensors = %+v, %v", keys, err)
	}
	if Label(keys[0]) != "CPU1 Temp" || Label(store.SensorKey{Key: "temp:x"}) != "temp:x" {
		t.Errorf("labels %q", Label(keys[0]))
	}
}

// TestJanitorRollsUpAndSeriesMatchRaw: after a pass, the 7 d plan (hourly rows plus raw
// rows for the hours not rolled up yet) draws exactly what the raw rows bucketed by hour
// would: rollups are exact aggregates.
func TestJanitorRollsUpAndSeriesMatchRaw(t *testing.T) {
	end := base.Add(3*day + 30*time.Minute)
	f := newFixture(t, end)
	f.seed(t, "r1", base, end, 5*time.Minute)
	ctx := context.Background()
	if err := f.svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st := f.svc.Status()
	if !st.HourlyDone.Equal(end.Truncate(time.Hour)) || !st.DailyDone.Equal(end.Truncate(day)) ||
		!st.LastRun.Equal(end) || st.Stats.HourlyRows != 2*72 || st.Stats.DailyRows != 2*3 || st.Err != "" {
		t.Fatalf("status = %+v", st)
	}
	k := f.key(t, "r1", "temp:cpu1")
	p := PlanFor(Range7d, end)
	sr, err := f.svc.Series(ctx, k, p)
	if err != nil {
		t.Fatal(err)
	}
	if len(sr.Segments) != 2 || sr.Segments[0].Tier != store.TierHourly || sr.Segments[1].Tier != store.TierRaw {
		t.Fatalf("segments = %+v", sr.Segments)
	}
	raw, err := f.ro.History().Buckets(ctx, k.ID, store.TierRaw, p.From, p.To, p.Step)
	if err != nil || len(raw) != 73 || len(sr.Buckets) != 73 {
		t.Fatalf("raw %d, series %d, %v", len(raw), len(sr.Buckets), err)
	}
	for i := range raw {
		if raw[i] != sr.Buckets[i] {
			t.Fatalf("bucket %d: raw %+v series %+v", i, raw[i], sr.Buckets[i])
		}
	}
	if sr.Summary.Min != 0 || sr.Summary.Max != 55 || sr.Summary.N != int64(3*288+6) {
		t.Errorf("summary = %+v", sr.Summary)
	}
	if _, _, ok := sr.Coarse(p); ok {
		t.Error("no coarser tier was needed")
	}
	if err = f.svc.RunOnce(ctx); err != nil {
		t.Fatalf("second pass: %v", err)
	}
}

// TestJanitorRetention: rows older than each tier's retention go, the hourly tier fills
// the chart before the raw retention ("hourly averages before …"), and a key whose
// rows are all gone is deleted.
func TestJanitorRetention(t *testing.T) {
	end := base.Add(3 * day)
	f := newFixture(t, end)
	f.seed(t, "r1", base, end, 10*time.Minute)
	ctx := context.Background()
	if err := f.svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	f.ret = Retention{RawDays: 1, HourlyDays: 7, DailyDays: 30}
	if err := f.svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	k := f.key(t, "r1", "temp:cpu1")
	first, _, _ := f.ro.History().Earliest(ctx, k.ID, store.TierRaw)
	if !first.Equal(end.Add(-day)) {
		t.Errorf("oldest raw = %v, want %v", first, end.Add(-day))
	}
	p := Plan{From: end.Add(-2 * day), To: end, Step: 10 * time.Minute, Tier: store.TierRaw}
	sr, err := f.svc.Series(ctx, k, p)
	if err != nil {
		t.Fatal(err)
	}
	tier, until, ok := sr.Coarse(p)
	if !ok || tier != store.TierHourly || !until.Equal(end.Add(-day)) {
		t.Errorf("coarse = %v %v %v", tier, until, ok)
	}
	f.setNow(end.Add(40 * day))
	if err = f.svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if st := f.svc.Status(); st.Stats.Keys != 0 || st.Stats.RawRows != 0 || st.Stats.DailyRows != 0 {
		t.Errorf("after every retention passed: %+v", st.Stats)
	}
	if keepRaw(7) != 30240 {
		t.Errorf("count rule for 7 days = %d", keepRaw(7))
	}
}

// TestSyncServersKeepsAGraceperiod (review M1): a server missing from the registry (a
// typo, a commented-out entry) keeps its history for SyncGrace after its last sample.
func TestSyncServersKeepsAGracePeriod(t *testing.T) {
	f := newFixture(t, base.Add(time.Hour))
	f.seed(t, "r1", base, base.Add(time.Hour), 10*time.Minute)
	f.seed(t, "typo", base, base.Add(time.Hour), 10*time.Minute)
	f.seed(t, "gone", base.Add(-40*day), base.Add(-40*day+time.Hour), 10*time.Minute)
	ctx := context.Background()
	if err := f.svc.SyncServers(ctx, []string{"r1"}); err != nil {
		t.Fatal(err)
	}
	all, _ := f.ro.History().Keys(ctx, "")
	servers := map[string]bool{}
	for _, k := range all {
		servers[k.ServerID] = true
	}
	if !servers["r1"] || !servers["typo"] || servers["gone"] {
		t.Fatalf("servers left %v", servers)
	}
}

func TestRunLoopWaitsForTheNextHour(t *testing.T) {
	f := newFixture(t, base.Add(10*time.Minute))
	waits := make(chan time.Duration, 4)
	tick := make(chan time.Time)
	f.svc.cfg.After = func(d time.Duration) <-chan time.Time { waits <- d; return tick }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.svc.Run(ctx); close(done) }()
	if d := <-waits; d != 52*time.Minute {
		t.Errorf("first wait %v, want until 00:02 next hour", d)
	}
	tick <- base
	<-waits
	cancel()
	<-done
	if untilNextRun(base.Add(RunAt)) != time.Hour || untilNextRun(base) != RunAt {
		t.Error("untilNextRun")
	}
	if f.svc.Status().LastRun.IsZero() {
		t.Error("no pass recorded")
	}
}

func TestRunOnceReportsCancellation(t *testing.T) {
	f := newFixture(t, base.Add(2*day))
	f.seed(t, "r1", base, base.Add(time.Hour), 10*time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.svc.RunOnce(ctx); err == nil {
		t.Fatal("a cancelled pass succeeded")
	}
	if st := f.svc.Status(); st.Err != "canceled" || !st.LastRun.IsZero() {
		t.Errorf("status = %+v", st)
	}
}

func TestOverlay(t *testing.T) {
	end := base.Add(day)
	f := newFixture(t, end)
	ctx := context.Background()
	lg := audit.NewLogger(f.db.Audit(), nil, f.clock, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for i, e := range []audit.Entry{
		{Principal: "alice", ServerID: "r1", Action: "power.on", Result: audit.ResultStarted},
		{Principal: "alice", ServerID: "r2", Action: "power.on", Result: audit.ResultStarted},
		{Principal: "alice", ServerID: "r1", Action: "server.maintenance.start", Result: audit.ResultOK},
	} {
		f.setNow(base.Add(time.Duration(i+1) * time.Hour))
		if _, err := lg.Record(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	f.setNow(end)
	p := PlanFor(Range24h, end)
	m, err := f.svc.Overlay(ctx, "r1", p, []LogEntry{{Event: logEvent(base.Add(5 * time.Hour)), Log: "System Event Log"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Marks) != 2 || m.Marks[0].Text != "Power on requested by alice" || m.Marks[1].Kind != MarkLog ||
		len(m.Spans) != 1 || !m.Spans[0].Open {
		t.Fatalf("overlay = %+v", m)
	}
	if j, err := f.svc.ClockJump(ctx); err != nil || !j.IsZero() {
		t.Errorf("clock jump = %v, %v", j, err)
	}
}

func logEvent(at time.Time) bmc.Event {
	return bmc.Event{Created: at, Severity: bmc.SeverityCritical, Message: "PSU 1 lost input"}
}

// TestJanitorRecoversFromAClockThatWasAhead: a pass with the clock a month ahead leaves
// watermarks in the future; once the clock is right again the next pass rolls up from
// now instead of waiting a month.
func TestJanitorRecoversFromAClockThatWasAhead(t *testing.T) {
	end := base.Add(2 * day)
	f := newFixture(t, end.Add(30*day))
	ctx := context.Background()
	if err := f.svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	f.setNow(end)
	f.seed(t, "r1", end.Add(-6*time.Hour), end, 10*time.Minute)
	if err := f.svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st := f.svc.Status()
	if !st.HourlyDone.Equal(end) || !st.DailyDone.Equal(end) || st.Stats.HourlyRows != 2*6 {
		t.Fatalf("status after the clock came back = %+v", st)
	}
}

// TestFailedPassKeepsTheLastWatermarks: a pass that cannot even read the watermarks
// keeps the last good ones in its status (and the metrics).
func TestFailedPassKeepsTheLastWatermarks(t *testing.T) {
	f := newFixture(t, base.Add(day))
	if err := f.svc.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.svc.RunOnce(ctx); err == nil {
		t.Fatal("cancelled pass")
	}
	if st := f.svc.Status(); !st.HourlyDone.Equal(base.Add(day)) || st.Err != "canceled" {
		t.Errorf("status = %+v", st)
	}
}

// TestForwardClockStepDoesNotWipeTheHistory (review MEDIUM-1): the wall clock jumps 60
// days ahead while the app runs. The next pass prunes nothing, does not roll up the
// future, records the step; afterwards retention catches up at most twice real time.
// A new process (a restart with the clock still ahead) advances at most 3 hours.
func TestForwardClockStepDoesNotWipeTheHistory(t *testing.T) {
	end := base.Add(3 * day)
	f := newFixture(t, end)
	f.seed(t, "r1", base, end, 10*time.Minute)
	ctx := context.Background()
	if err := f.svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	before := f.svc.Status().Stats
	f.setNow(end.Add(time.Hour))
	f.jump(60 * day)
	if err := f.svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	st := f.svc.Status()
	if st.Stats.RawRows != before.RawRows || st.Stats.HourlyRows < before.HourlyRows ||
		!st.LastForwardJump.Equal(end.Add(time.Hour+60*day)) || !st.Clock.Equal(end.Add(2*time.Hour)) ||
		!st.HourlyDone.Equal(end.Add(time.Hour+60*day)) { // rollups follow the wall clock (they only add)
		t.Fatalf("after +60 d: %+v (before %+v)", st, before)
	}
	for i := 0; i < 5; i++ { // real hours pass with the wrong clock
		f.setNow(f.clock().Add(time.Hour))
		if err := f.svc.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if st = f.svc.Status(); !st.Clock.Equal(end.Add(12*time.Hour)) || st.Stats.RawRows != before.RawRows {
		t.Fatalf("catching up 2 h an hour: %+v", st)
	}
	again, err := New(Config{Writer: f.db.History(), Reader: f.ro.History(), Audit: f.ro.AuditSearch(),
		Retention: func() Retention { return f.ret }, Now: f.clock, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Boot: func() (store.BootMark, bool) { return store.BootMark{ID: "boot-2", Uptime: time.Minute}, true }})
	if err != nil {
		t.Fatal(err)
	}
	if err = again.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if st = again.Status(); !st.Clock.Equal(end.Add(15 * time.Hour)) {
		t.Fatalf("a new boot advances 3 h: %+v", st.Clock)
	}
	if lag, ok := Lagging(st, f.clock()); !ok || lag < 50*day {
		t.Errorf("Lagging = %v %v", lag, ok)
	}
}

// TestCrashLoopAfterAForwardStepGainsNothing (re-check MEDIUM-N2): the clock jumps 60
// days ahead and the app then restarts 40 times, 10 seconds apart, on the same boot. The
// kernel uptime bounds every restart's advance (2 × 10 s), so the retention clock moves
// minutes, not 40 × 3 hours, and nothing is pruned.
func TestCrashLoopAfterAForwardStepGainsNothing(t *testing.T) {
	end := base.Add(3 * day)
	f := newFixture(t, end)
	f.seed(t, "r1", base, end, 10*time.Minute)
	ctx := context.Background()
	if err := f.svc.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	rows := f.svc.Status().Stats.RawRows
	f.jump(60 * day)
	uptime := f.elapsed()
	var st Status
	for i := 0; i < 40; i++ {
		uptime += 10 * time.Second
		up := uptime
		svc, err := New(Config{Writer: f.db.History(), Reader: f.ro.History(), Audit: f.ro.AuditSearch(),
			Retention: func() Retention { return f.ret }, Now: f.clock, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
			Boot: func() (store.BootMark, bool) { return store.BootMark{ID: "boot-1", Uptime: up}, true }})
		if err != nil {
			t.Fatal(err)
		}
		if err = svc.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
		st = svc.Status()
	}
	if st.Clock.After(end.Add(15*time.Minute)) || st.Stats.RawRows != rows {
		t.Fatalf("after 40 restarts: clock %v (from %v), raw rows %d (were %d)", st.Clock, end, st.Stats.RawRows, rows)
	}
}

func TestParseBoot(t *testing.T) {
	if b, ok := parseBoot("6c1e7f3a-1b2c-4d5e-8f90-123456789abc\n", "12345.67 99.0\n"); !ok || b.Uptime != 12345670*time.Millisecond {
		t.Errorf("parse = %+v %v", b, ok)
	}
	for _, bad := range [][2]string{{"", "1 1"}, {"NOT A UUID", "1 1"}, {"abc", ""}, {"abc", "x 1"}, {"abc", "-5 1"},
		{"abc", "NaN 1"}, {"abc", "Inf 1"}, {"abc", "+Inf 1"}, {"abc", "1e5 1"}, {"abc", "0x10 1"}, {"abc", "1_000 1"},
		{"abc", "12345678901 1"}} {
		if _, ok := parseBoot(bad[0], bad[1]); ok {
			t.Errorf("parseBoot(%q, %q) accepted", bad[0], bad[1])
		}
	}
	if b, ok := ReadBoot(); ok && b.ID == "" {
		t.Error("ReadBoot without an ID")
	}
}
