package store

import (
	"cmp"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// knownKey is a stored key as the insert needs it.
type knownKey struct {
	id         int64
	from       string // archived_from: the live key this archive belonged to ("" live)
	name       string
	unit       SensorUnit
	kind       SensorKind
	lastTS     int64
	sampledNow bool
}

func validSample(s SensorSample) bool {
	return s.Key != "" && len(s.Key) <= MaxSensorKeyLen && utf8.ValidString(s.Key) && validKind(s.Kind) &&
		validUnit(s.Unit) && !math.IsNaN(s.Value) && !math.IsInf(s.Value, 0)
}

func validKind(k SensorKind) bool {
	for _, x := range SensorKinds() {
		if x == k {
			return true
		}
	}
	return false
}

func validUnit(u SensorUnit) bool {
	switch u {
	case UnitCelsius, UnitRPM, UnitPercent, UnitWatts, UnitVolts:
		return true
	}
	return false
}

// cleanName caps a display name on a rune boundary.
func cleanName(n string) string {
	n = strings.ToValidUTF8(n, "")
	for len(n) > MaxSensorNameLen {
		_, size := utf8.DecodeLastRuneInString(n)
		n = n[:len(n)-size]
	}
	return n
}

// Insert stores one poll in one transaction: new keys are created (at most
// MaxKeysPerServer per server), changed names updated, a key whose unit or kind changed
// archived, samples inserted (a duplicate timestamp is ignored) and each sampled key's
// first_ts and last_ts widened. Invalid samples (no key, NaN, unknown kind) are skipped.
func (r historyRepo) Insert(ctx context.Context, p SensorPoll) (InsertResult, error) {
	const op = "insert samples"
	if p.ServerID == "" || len(p.ServerID) > 64 {
		return InsertResult{}, invalid(op, "a server id of 1 to 64 bytes is required")
	}
	var res InsertResult
	err := inTx(ctx, r.db, op, func(q querier) error {
		keys, lerr := loadKnown(ctx, q, p.ServerID)
		if lerr != nil {
			return lerr
		}
		ins := &inserter{q: q, serverID: p.ServerID, ts: toMS(p.TS), keys: keys, total: len(keys)}
		for _, s := range p.Samples {
			if ierr := ins.sample(ctx, s, &res); ierr != nil {
				return ierr
			}
		}
		return nil
	})
	return res, err
}

// inserter is one poll's insert inside its transaction.
type inserter struct {
	q        querier
	serverID string
	ts       int64
	keys     map[string]*knownKey
	total    int // keys of the server, archived ones included
}

// sample stores one valid sample and accounts for it in res.
func (in *inserter) sample(ctx context.Context, s SensorSample, res *InsertResult) error {
	const op = "insert samples"
	if !validSample(s) {
		return nil
	}
	k, err := in.key(ctx, s, res)
	if err != nil || k == nil || k.sampledNow { // refused, or a key listed twice in one poll
		return err
	}
	k.sampledNow = true
	n, err := execCount(ctx, in.q, op, `INSERT OR IGNORE INTO sensor_raw (key_id, ts, value) VALUES (?, ?, ?)`, k.id, in.ts, s.Value)
	if err != nil {
		return err
	}
	if _, err = in.q.ExecContext(ctx, `UPDATE sensor_keys SET last_ts = max(last_ts, ?), first_ts = min(first_ts, ?)
		WHERE id = ?`, in.ts, in.ts, k.id); err != nil {
		return mapErr(op, err)
	}
	res.Inserted += int(n)
	res.Behind = res.Behind || in.ts < k.lastTS
	return nil
}

// key returns the stored key of s: the known one (its name updated, archived first when
// its unit or kind changed), a new one, or nil when the server is at MaxKeysPerServer.
func (in *inserter) key(ctx context.Context, s SensorSample, res *InsertResult) (*knownKey, error) {
	const op = "insert samples"
	name := cleanName(s.Name)
	k, ok := in.keys[s.Key]
	if ok && (k.unit != s.Unit || k.kind != s.Kind) {
		return in.switchUnit(ctx, s, k, name, res)
	}
	if ok {
		if k.name != name {
			if _, err := in.q.ExecContext(ctx, `UPDATE sensor_keys SET name = ? WHERE id = ?`, name, k.id); err != nil {
				return nil, mapErr(op, err)
			}
			k.name = name
		}
		return k, nil
	}
	return in.create(ctx, s, name, res)
}

// create stores a new key for s, or refuses it at MaxKeysPerServer.
func (in *inserter) create(ctx context.Context, s SensorSample, name string, res *InsertResult) (*knownKey, error) {
	const op = "insert samples"
	if in.total >= MaxKeysPerServer {
		res.Refused++
		return nil, nil
	}
	var id int64
	err := in.q.QueryRowContext(ctx, `INSERT INTO sensor_keys (server_id, key, kind, name, unit, first_ts, last_ts)
		VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id`, in.serverID, s.Key, string(s.Kind), name, string(s.Unit), in.ts, in.ts).Scan(&id)
	if err != nil {
		return nil, mapErr(op, err)
	}
	in.total++
	nk := &knownKey{id: id, name: name, unit: s.Unit, kind: s.Kind, lastTS: in.ts}
	in.keys[s.Key] = nk
	return nk, nil
}

// MaxArchivesPerKey is how many archived keys (earlier units or kinds) one sensor keeps.
// A sensor flipping between two units swaps two keys and deletes nothing; only a
// sensor cycling through more combinations than this loses its oldest archive.
const MaxArchivesPerKey = 4

// archiveSuffixRoom is the bytes kept for an archive's "#<unit>#<id>" suffix.
const archiveSuffixRoom = 32

// archiveBase is the part of key an archive name starts with: cut on a rune boundary to
// leave archiveSuffixRoom bytes. Names are for people; archives are matched by
// archived_from.
func archiveBase(key string) string {
	n := min(len(key), MaxSensorKeyLen-archiveSuffixRoom)
	for n > 0 && n < len(key) && !utf8.RuneStart(key[n]) {
		n--
	}
	return key[:n]
}

// switchUnit handles a sensor whose unit or kind changed: the live key k is archived and
// the readings continue under an archive of the same unit and kind when there is one
// (swapped back in: nothing is deleted), else under a new key, for which the oldest
// archive beyond MaxArchivesPerKey is dropped; at MaxKeysPerServer the change is refused
// and nothing is archived.
func (in *inserter) switchUnit(ctx context.Context, s SensorSample, k *knownKey, name string, res *InsertResult) (*knownKey, error) {
	arch := in.archivesOf(s.Key)
	for _, a := range arch {
		if a.k.unit == s.Unit && a.k.kind == s.Kind {
			if err := in.archive(ctx, s.Key, k); err != nil {
				return nil, err
			}
			res.Archived++
			return a.k, in.revive(ctx, s.Key, a, name)
		}
	}
	for len(arch) >= MaxArchivesPerKey {
		if _, err := in.q.ExecContext(ctx, `DELETE FROM sensor_keys WHERE id = ?`, arch[0].k.id); err != nil {
			return nil, mapErr("insert samples", err)
		}
		delete(in.keys, arch[0].name)
		in.total--
		res.Dropped++
		arch = arch[1:]
	}
	if in.total >= MaxKeysPerServer { // never archive a key whose replacement is refused
		res.Refused++
		return nil, nil
	}
	if err := in.archive(ctx, s.Key, k); err != nil {
		return nil, err
	}
	res.Archived++
	return in.create(ctx, s, name, res)
}

type archived struct {
	name string
	k    *knownKey
}

// archivesOf is key's archives, oldest first (matched by archived_from, exactly).
func (in *inserter) archivesOf(key string) []archived {
	var out []archived
	for name, k := range in.keys {
		if k.from == key {
			out = append(out, archived{name, k})
		}
	}
	slices.SortFunc(out, func(a, b archived) int { return cmp.Compare(a.k.id, b.k.id) })
	return out
}

// archive renames the live key to "<key>#<old unit>#<id>" (the key cut on a rune
// boundary) with archived_from = key, so its rows keep their unit and the key is free.
func (in *inserter) archive(ctx context.Context, key string, k *knownKey) error {
	name := archiveBase(key) + "#" + string(k.unit) + "#" + strconv.FormatInt(k.id, 10)
	if _, err := in.q.ExecContext(ctx, `UPDATE sensor_keys SET key = ?, archived_from = ? WHERE id = ?`,
		name, key, k.id); err != nil {
		return mapErr("insert samples", err)
	}
	delete(in.keys, key)
	k.from = key
	in.keys[name] = k
	return nil
}

// revive makes an archive the live key again.
func (in *inserter) revive(ctx context.Context, key string, a archived, name string) error {
	if _, err := in.q.ExecContext(ctx, `UPDATE sensor_keys SET key = ?, archived_from = NULL, name = ? WHERE id = ?`,
		key, name, a.k.id); err != nil {
		return mapErr("insert samples", err)
	}
	delete(in.keys, a.name)
	a.k.from, a.k.name = "", name
	in.keys[key] = a.k
	return nil
}

func loadKnown(ctx context.Context, q querier, serverID string) (map[string]*knownKey, error) {
	const op = "insert samples"
	rows, err := q.QueryContext(ctx, `SELECT key, id, name, unit, kind, last_ts, coalesce(archived_from, '')
		FROM sensor_keys WHERE server_id = ?`, serverID)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	out := map[string]*knownKey{}
	for rows.Next() {
		var (
			key        string
			k          knownKey
			unit, kind string
		)
		if err := rows.Scan(&key, &k.id, &k.name, &unit, &kind, &k.lastTS, &k.from); err != nil {
			return nil, mapErr(op, err)
		}
		k.unit, k.kind = SensorUnit(unit), SensorKind(kind)
		out[key] = &k
	}
	return out, mapErr(op, rows.Err())
}

func checkAligned(op string, from, to time.Time, size int64) error {
	f, t := toMS(from), toMS(to)
	if f%size != 0 || t%size != 0 || t < f || f < 0 {
		return invalid(op, "the range must be aligned to whole buckets")
	}
	return nil
}

// RollupHourly is one INSERT OR REPLACE … GROUP BY over the raw rows of [from, to),
// read per key on the primary key (key_id IN the key list, ts range).
func (r historyRepo) RollupHourly(ctx context.Context, from, to time.Time) (int64, error) {
	const op = "history rollup hourly"
	if err := checkAligned(op, from, to, HourMS); err != nil {
		return 0, err
	}
	return execCount(ctx, r.db, op, `INSERT OR REPLACE INTO sensor_hourly (key_id, bucket, min, avg, max, n)
		SELECT key_id, (ts / 3600000) * 3600000, MIN(value), AVG(value), MAX(value), COUNT(*)
		FROM sensor_raw WHERE key_id IN (SELECT id FROM sensor_keys) AND ts >= ? AND ts < ?
		GROUP BY key_id, ts / 3600000`, toMS(from), toMS(to))
}

// RollupDaily builds days from the hourly rows: min of mins, max of maxes and the
// n-weighted average.
func (r historyRepo) RollupDaily(ctx context.Context, from, to time.Time) (int64, error) {
	const op = "history rollup daily"
	if err := checkAligned(op, from, to, DayMS); err != nil {
		return 0, err
	}
	return execCount(ctx, r.db, op, `INSERT OR REPLACE INTO sensor_daily (key_id, bucket, min, avg, max, n)
		SELECT key_id, (bucket / 86400000) * 86400000, MIN(min), SUM(avg * n) / SUM(n), MAX(max), SUM(n)
		FROM sensor_hourly WHERE key_id IN (SELECT id FROM sensor_keys) AND bucket >= ? AND bucket < ?
		GROUP BY key_id, bucket / 86400000`, toMS(from), toMS(to))
}

// PruneBefore deletes in statements of at most batch rows, so the single writer
// connection is never held for long (an audit append waits for one batch at most).
func (r historyRepo) PruneBefore(ctx context.Context, keyID int64, tier Tier, before time.Time, batch int) (int64, error) {
	return r.pruneBelow(ctx, keyID, tier, toMS(before), batch)
}

func (r historyRepo) pruneBelow(ctx context.Context, keyID int64, tier Tier, below int64, batch int) (int64, error) {
	op := "history prune " + string(tier)
	table, col, err := tierTable(tier)
	if err != nil {
		return 0, err
	}
	if batch < 1 {
		return 0, invalid(op, "batch must be positive")
	}
	var total int64
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		var edge int64
		err := r.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT %[2]s FROM %[1]s WHERE key_id = ? AND %[2]s < ? ORDER BY %[2]s
			LIMIT 1 OFFSET ?`, table, col), keyID, below, batch).Scan(&edge)
		last := errors.Is(err, sql.ErrNoRows)
		if err != nil && !last {
			return total, mapErr(op, err)
		}
		if last {
			edge = below
		}
		n, err := execCount(ctx, r.db, op, fmt.Sprintf(`DELETE FROM %s WHERE key_id = ? AND %s < ?`, table, col), keyID, edge)
		total += n
		if err != nil || last {
			return total, err
		}
	}
}

func (r historyRepo) KeepNewest(ctx context.Context, keyID int64, keep, batch int) (int64, error) {
	const op = "history prune count"
	if keep < 1 {
		return 0, invalid(op, "keep must be positive")
	}
	var edge int64
	err := r.db.QueryRowContext(ctx, `SELECT ts FROM sensor_raw WHERE key_id = ? ORDER BY ts DESC LIMIT 1 OFFSET ?`,
		keyID, keep).Scan(&edge)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, mapErr(op, err)
	}
	return r.pruneBelow(ctx, keyID, TierRaw, edge+1, batch)
}

func (r historyRepo) DeleteKey(ctx context.Context, keyID int64, batch int) error {
	for _, t := range []Tier{TierRaw, TierHourly, TierDaily} {
		if _, err := r.pruneBelow(ctx, keyID, t, math.MaxInt64, batch); err != nil {
			return err
		}
	}
	_, err := execCount(ctx, r.db, "history delete key", `DELETE FROM sensor_keys WHERE id = ?`, keyID)
	return err
}

func (r historyRepo) DeleteIdleKeys(ctx context.Context, before time.Time) (int64, error) {
	return execCount(ctx, r.db, "history delete idle keys", `DELETE FROM sensor_keys WHERE last_ts < ?
		AND NOT EXISTS (SELECT 1 FROM sensor_raw WHERE key_id = sensor_keys.id)
		AND NOT EXISTS (SELECT 1 FROM sensor_hourly WHERE key_id = sensor_keys.id)
		AND NOT EXISTS (SELECT 1 FROM sensor_daily WHERE key_id = sensor_keys.id)`, toMS(before))
}
