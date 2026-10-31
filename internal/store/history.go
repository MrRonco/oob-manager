package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Sensor history (migration 0015, tech_doc §39): sensor_keys names each sampled sensor
// once; sensor_raw holds the polled values, sensor_hourly and sensor_daily their
// rollups. Every read and prune runs per key on a primary key.

// SensorKind is a sampled sensor family (the sensor_keys CHECK list).
type SensorKind string

// Sensor kinds.
const (
	SensorTemp   SensorKind = "temp"
	SensorFan    SensorKind = "fan"
	SensorPower  SensorKind = "power"
	SensorPSUIn  SensorKind = "psu_in"
	SensorPSUOut SensorKind = "psu_out"
	SensorVolt   SensorKind = "volt"
)

// SensorKinds returns every kind in display order (a fresh slice).
func SensorKinds() []SensorKind {
	return []SensorKind{SensorTemp, SensorFan, SensorPower, SensorPSUIn, SensorPSUOut, SensorVolt}
}

// SensorUnit is the unit a value is stored in: the BMC's own.
type SensorUnit string

// Sensor units.
const (
	UnitCelsius SensorUnit = "celsius"
	UnitRPM     SensorUnit = "rpm"
	UnitPercent SensorUnit = "percent"
	UnitWatts   SensorUnit = "watts"
	UnitVolts   SensorUnit = "volts"
)

// Tier is a storage resolution.
type Tier string

// Tiers, finest first.
const (
	TierRaw    Tier = "raw"
	TierHourly Tier = "hourly"
	TierDaily  Tier = "daily"
)

// Bucket sizes of the rollup tiers.
const (
	HourMS = int64(time.Hour / time.Millisecond)
	DayMS  = 24 * HourMS
)

// Bounds of the history tables.
const (
	MaxSensorKeyLen  = 160
	MaxSensorNameLen = 128
	// MaxKeysPerServer caps a server's sampled sensors (archived ones included): a BMC
	// that invents names cannot grow the keys table, or slow the shared writer, without
	// bound. New keys beyond it are refused and counted (InsertResult.Refused).
	MaxKeysPerServer = 512
	// MaxBuckets caps one Buckets answer (callers ask for far fewer).
	MaxBuckets = 5000
	// MaxRawPage caps one Raw page.
	MaxRawPage = 10_000
)

// SensorSample is one reading of one poll.
type SensorSample struct {
	Key   string // "temp:<member id>", "power:consumed"
	Kind  SensorKind
	Unit  SensorUnit
	Name  string // display name, stored when it changes
	Value float64
}

// SensorPoll is every reading of one server's poll, taken at TS.
type SensorPoll struct {
	ServerID string
	TS       time.Time
	Samples  []SensorSample
}

// InsertResult describes a stored poll.
type InsertResult struct {
	Inserted int
	// Refused counts samples of new keys refused because the server has MaxKeysPerServer.
	Refused int
	// Archived counts unit or kind changes: the old rows stay under an archived key
	// ("<key>#<old unit>#<id>") and the readings continue under an earlier archive of the
	// same unit and kind (swapped back in) or a new key.
	Archived int
	// Dropped counts archives deleted, rows included, because a sensor had
	// MaxArchivesPerKey of them (logged and counted by the fleet).
	Dropped int
	// Behind is true when TS is older than the newest stored sample of one of the keys:
	// the wall clock moved back (tech_doc §39, clock jumps).
	Behind bool
}

// SensorKey is one sampled sensor of a server.
type SensorKey struct {
	ID          int64
	ServerID    string
	Key         string
	Kind        SensorKind
	Name        string
	Unit        SensorUnit
	First, Last time.Time
}

// Bucket is the aggregate of one time bucket starting at Start.
type Bucket struct {
	Start         time.Time
	Min, Avg, Max float64
	N             int64
}

// RawPoint is one stored sample.
type RawPoint struct {
	TS    time.Time
	Value float64
}

// HistoryMeta is the rollup state.
type HistoryMeta struct {
	// HourlyDone and DailyDone: every hour (day) before them is rolled up.
	HourlyDone, DailyDone time.Time
	// LastClockJump is when the sampler last saw the clock move back (zero: never).
	LastClockJump time.Time
	// LastPassAt is the wall time of the janitor's last pass and JanitorClock the
	// retention clock it prunes by (both zero before the first pass); LastForwardJump is
	// when the janitor last saw the wall clock run ahead of real time (zero: never).
	LastPassAt, JanitorClock, LastForwardJump time.Time
	// Boot is the kernel boot at the last pass ("" ID: unknown).
	Boot BootMark
}

// BootMark is a kernel boot ID and the uptime at a pass: within one boot the uptime
// delta is real elapsed time, whatever the wall clock did.
type BootMark struct {
	ID     string
	Uptime time.Duration
}

// HistoryStats is the size of the history store.
type HistoryStats struct {
	Keys                           int64
	RawRows, HourlyRows, DailyRows int64
	// DBBytes is the whole database file (page_count × page_size); FreelistPages are
	// pages freed by prunes and reused by later inserts.
	DBBytes, FreelistPages int64
}

// SampleSink receives the sensor readings of each poll (the fleet's sampler).
type SampleSink interface {
	Insert(ctx context.Context, p SensorPoll) (InsertResult, error)
	// NoteClockJump records that the wall clock moved back at (shown on the History tab).
	NoteClockJump(ctx context.Context, at time.Time) error
}

// HistoryReader is the read side, served by the read-only connection (OpenReadOnly).
type HistoryReader interface {
	// Keys lists a server's sampled sensors ("" lists every server's).
	Keys(ctx context.Context, serverID string) ([]SensorKey, error)
	// Buckets aggregates tier rows of key in [from, to) into buckets of step (aligned to
	// multiples of step since the epoch), oldest first.
	Buckets(ctx context.Context, keyID int64, tier Tier, from, to time.Time, step time.Duration) ([]Bucket, error)
	// Raw returns up to limit samples of key with from <= ts < to and ts > after, oldest first.
	Raw(ctx context.Context, keyID int64, from, to, after time.Time, limit int) ([]RawPoint, error)
	// CountRaw counts key's samples with from <= ts < to (sizing an export).
	CountRaw(ctx context.Context, keyID int64, from, to time.Time) (int64, error)
	// Earliest is the oldest row of key in tier (false: none).
	Earliest(ctx context.Context, keyID int64, tier Tier) (time.Time, bool, error)
	Meta(ctx context.Context) (HistoryMeta, error)
	// Stats counts every table (a full read: the janitor calls it once an hour).
	Stats(ctx context.Context) (HistoryStats, error)
}

// HistoryRepository is the whole history store on the writer connection: the sampler's
// sink, the reads, and the janitor's rollups and prunes.
type HistoryRepository interface {
	SampleSink
	HistoryReader
	// RollupHourly (RollupDaily) recomputes the hourly (daily) rows of every bucket in
	// [from, to) from the raw (hourly) rows; idempotent. Returns the rows written.
	RollupHourly(ctx context.Context, from, to time.Time) (int64, error)
	RollupDaily(ctx context.Context, from, to time.Time) (int64, error)
	// SetWatermarks stores the rollup progress (hour- and day-aligned).
	SetWatermarks(ctx context.Context, hourlyDone, dailyDone time.Time) error
	// SetPass stores the janitor's pass: its wall time, its retention clock and the boot.
	SetPass(ctx context.Context, wall, clock time.Time, boot BootMark) error
	// NoteForwardJump records that the janitor saw the clock run ahead at at.
	NoteForwardJump(ctx context.Context, at time.Time) error
	// PruneBefore deletes key's rows of tier older than before, batch rows per statement.
	PruneBefore(ctx context.Context, keyID int64, tier Tier, before time.Time, batch int) (int64, error)
	// KeepNewest deletes key's oldest raw rows beyond the newest keep, batch per statement.
	KeepNewest(ctx context.Context, keyID int64, keep, batch int) (int64, error)
	// DeleteKey deletes a key and all its rows (rows in batches first).
	DeleteKey(ctx context.Context, keyID int64, batch int) error
	// DeleteIdleKeys deletes keys with no rows in any tier last sampled before before.
	DeleteIdleKeys(ctx context.Context, before time.Time) (int64, error)
}

var _ HistoryRepository = historyRepo{}

// History returns the sensor history on the writer connection.
func (d *DB) History() HistoryRepository { return historyRepo{d.sql} }

// History returns the sensor history bound to the transaction (bulk inserts: the e2e
// harness seeds days of samples in one transaction).
func (t *Tx) History() HistoryRepository { return historyRepo{t.tx} }

type historyRepo struct{ db querier }

// tierTable maps a tier to its table and time column (fixed strings, never input).
func tierTable(t Tier) (table, col string, err error) {
	switch t {
	case TierRaw:
		return "sensor_raw", "ts", nil
	case TierHourly:
		return "sensor_hourly", "bucket", nil
	case TierDaily:
		return "sensor_daily", "bucket", nil
	default:
		return "", "", fmt.Errorf("store: unknown history tier %q", t)
	}
}

func (r historyRepo) Meta(ctx context.Context) (HistoryMeta, error) {
	var (
		h, d, pass, clock, uptime int64
		jump, fwd                 sql.NullInt64
		bootID                    string
	)
	err := r.db.QueryRowContext(ctx, `SELECT hourly_done, daily_done, last_clock_jump, last_pass_at, janitor_clock,
		last_forward_jump, boot_id, boot_uptime_ms FROM history_meta WHERE id = 1`).
		Scan(&h, &d, &jump, &pass, &clock, &fwd, &bootID, &uptime)
	if err != nil {
		return HistoryMeta{}, mapErr("history meta", err)
	}
	m := HistoryMeta{HourlyDone: fromMS(h), DailyDone: fromMS(d), LastClockJump: fromNullMS(jump),
		LastForwardJump: fromNullMS(fwd), Boot: BootMark{ID: bootID, Uptime: time.Duration(uptime) * time.Millisecond}}
	if pass > 0 {
		m.LastPassAt, m.JanitorClock = fromMS(pass), fromMS(clock)
	}
	return m, nil
}

func (r historyRepo) SetPass(ctx context.Context, wall, clock time.Time, boot BootMark) error {
	return execOne(ctx, r.db, "history pass", `UPDATE history_meta SET last_pass_at = ?, janitor_clock = ?, boot_id = ?,
		boot_uptime_ms = ? WHERE id = 1`, toMS(wall), toMS(clock), boot.ID, boot.Uptime.Milliseconds())
}

func (r historyRepo) NoteForwardJump(ctx context.Context, at time.Time) error {
	return execOne(ctx, r.db, "history clock jump", `UPDATE history_meta SET last_forward_jump = ? WHERE id = 1`, toMS(at))
}

func (r historyRepo) SetWatermarks(ctx context.Context, hourlyDone, dailyDone time.Time) error {
	return execOne(ctx, r.db, "history watermarks", `UPDATE history_meta SET hourly_done = ?, daily_done = ? WHERE id = 1`,
		toMS(hourlyDone), toMS(dailyDone))
}

func (r historyRepo) NoteClockJump(ctx context.Context, at time.Time) error {
	return execOne(ctx, r.db, "history clock jump", `UPDATE history_meta SET last_clock_jump = ? WHERE id = 1`, toMS(at))
}

func (r historyRepo) Stats(ctx context.Context) (HistoryStats, error) {
	var s HistoryStats
	err := r.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM sensor_keys), (SELECT count(*) FROM sensor_raw),
		(SELECT count(*) FROM sensor_hourly), (SELECT count(*) FROM sensor_daily)`).
		Scan(&s.Keys, &s.RawRows, &s.HourlyRows, &s.DailyRows)
	if err != nil {
		return HistoryStats{}, mapErr("history stats", err)
	}
	var pages, size int64
	if err = r.db.QueryRowContext(ctx, `SELECT page_count, page_size, freelist_count
		FROM pragma_page_count(), pragma_page_size(), pragma_freelist_count()`).Scan(&pages, &size, &s.FreelistPages); err != nil {
		return HistoryStats{}, mapErr("history stats", err)
	}
	s.DBBytes = pages * size
	return s, nil
}
