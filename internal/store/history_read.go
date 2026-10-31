package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

func (r historyRepo) Keys(ctx context.Context, serverID string) ([]SensorKey, error) {
	const op = "history keys"
	q := `SELECT id, server_id, key, kind, name, unit, first_ts, last_ts FROM sensor_keys`
	args := []any{}
	if serverID != "" {
		q += ` WHERE server_id = ?`
		args = append(args, serverID)
	}
	rows, err := r.db.QueryContext(ctx, q+` ORDER BY server_id, kind, key`, args...)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []SensorKey
	for rows.Next() {
		var (
			k           SensorKey
			kind, unit  string
			first, last int64
		)
		if err := rows.Scan(&k.ID, &k.ServerID, &k.Key, &kind, &k.Name, &unit, &first, &last); err != nil {
			return nil, mapErr(op, err)
		}
		k.Kind, k.Unit, k.First, k.Last = SensorKind(kind), SensorUnit(unit), fromMS(first), fromMS(last)
		out = append(out, k)
	}
	return out, mapErr(op, rows.Err())
}

// bucketSQL is the aggregate per tier: raw rows are single values, rollup rows carry
// their own min, max, average and count (the average is weighted by the count).
func bucketSQL(t Tier) (string, error) {
	switch t {
	case TierRaw:
		return `SELECT (ts / ?) * ? AS b, MIN(value), AVG(value), MAX(value), COUNT(*) FROM sensor_raw
			WHERE key_id = ? AND ts >= ? AND ts < ? GROUP BY b ORDER BY b LIMIT ?`, nil
	case TierHourly, TierDaily:
		table, _, _ := tierTable(t)
		return fmt.Sprintf(`SELECT (bucket / ?) * ? AS b, MIN(min), SUM(avg * n) / SUM(n), MAX(max), SUM(n) FROM %s
			WHERE key_id = ? AND bucket >= ? AND bucket < ? GROUP BY b ORDER BY b LIMIT ?`, table), nil // #nosec G201 -- fixed table name
	default:
		return "", fmt.Errorf("store: unknown history tier %q", t)
	}
}

func (r historyRepo) Buckets(ctx context.Context, keyID int64, tier Tier, from, to time.Time,
	step time.Duration) ([]Bucket, error) {
	const op = "history buckets"
	stepMS := step.Milliseconds()
	if stepMS < 1000 || stepMS%1000 != 0 {
		return nil, invalid(op, "step must be a whole number of seconds")
	}
	q, err := bucketSQL(tier)
	if err != nil {
		return nil, err
	}
	rows, err := r.db.QueryContext(ctx, q, stepMS, stepMS, keyID, toMS(from), toMS(to), MaxBuckets)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []Bucket
	for rows.Next() {
		var (
			b     Bucket
			start int64
		)
		if err := rows.Scan(&start, &b.Min, &b.Avg, &b.Max, &b.N); err != nil {
			return nil, mapErr(op, err)
		}
		b.Start = fromMS(start)
		out = append(out, b)
	}
	return out, mapErr(op, rows.Err())
}

func (r historyRepo) Raw(ctx context.Context, keyID int64, from, to, after time.Time, limit int) ([]RawPoint, error) {
	const op = "history raw"
	if limit < 1 || limit > MaxRawPage {
		return nil, invalid(op, fmt.Sprintf("limit must be in [1, %d]", MaxRawPage))
	}
	lo := toMS(from)
	if !after.IsZero() && toMS(after) >= lo {
		lo = toMS(after) + 1
	}
	rows, err := r.db.QueryContext(ctx, `SELECT ts, value FROM sensor_raw WHERE key_id = ? AND ts >= ? AND ts < ?
		ORDER BY ts LIMIT ?`, keyID, lo, toMS(to), limit)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	out := make([]RawPoint, 0, min(limit, 1024))
	for rows.Next() {
		var (
			p  RawPoint
			ts int64
		)
		if err := rows.Scan(&ts, &p.Value); err != nil {
			return nil, mapErr(op, err)
		}
		p.TS = fromMS(ts)
		out = append(out, p)
	}
	return out, mapErr(op, rows.Err())
}

func (r historyRepo) CountRaw(ctx context.Context, keyID int64, from, to time.Time) (int64, error) {
	var n int64
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM sensor_raw WHERE key_id = ? AND ts >= ? AND ts < ?`,
		keyID, toMS(from), toMS(to)).Scan(&n)
	return n, mapErr("history count", err)
}

func (r historyRepo) Earliest(ctx context.Context, keyID int64, tier Tier) (time.Time, bool, error) {
	table, col, err := tierTable(tier)
	if err != nil {
		return time.Time{}, false, err
	}
	var ts sql.NullInt64
	err = r.db.QueryRowContext(ctx, fmt.Sprintf(`SELECT MIN(%s) FROM %s WHERE key_id = ?`, col, table), keyID).Scan(&ts) // #nosec G201 -- fixed names
	if err != nil {
		return time.Time{}, false, mapErr("history earliest", err)
	}
	return fromNullMS(ts), ts.Valid, nil
}
