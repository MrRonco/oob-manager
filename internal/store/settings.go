package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SettingRow is one runtime-managed setting saved from the browser (settings_kv).
type SettingRow struct {
	Key       string
	ValueJSON string
	UpdatedAt time.Time
	UpdatedBy string
}

// SettingsRepository stores the runtime-managed settings and their revision.
type SettingsRepository interface {
	// All returns every saved row, ordered by key.
	All(ctx context.Context) ([]SettingRow, error)
	// Put inserts or replaces one row.
	Put(ctx context.Context, row SettingRow) error
	// Delete removes a row (the value falls back to the file or the default).
	Delete(ctx context.Context, key string) error
	// Rev is the current settings revision.
	Rev(ctx context.Context) (int64, error)
	// BumpRev is compare-and-set: it moves the revision from expect to expect+1 and
	// returns the new one, or ErrConflict when someone else saved first.
	BumpRev(ctx context.Context, expect int64) (int64, error)
}

type settingsRepo struct{ db querier }

func (r settingsRepo) All(ctx context.Context) ([]SettingRow, error) {
	const op = "settings"
	rows, err := r.db.QueryContext(ctx, `SELECT key, value_json, updated_at, updated_by FROM settings_kv ORDER BY key`)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []SettingRow
	for rows.Next() {
		var row SettingRow
		var at int64
		if err := rows.Scan(&row.Key, &row.ValueJSON, &at, &row.UpdatedBy); err != nil {
			return nil, mapErr(op, err)
		}
		row.UpdatedAt = fromMS(at)
		out = append(out, row)
	}
	return out, mapErr(op, rows.Err())
}

func (r settingsRepo) Put(ctx context.Context, row SettingRow) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO settings_kv (key, value_json, updated_at, updated_by)
		VALUES (?, ?, ?, ?) ON CONFLICT (key) DO UPDATE SET value_json = excluded.value_json,
		updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		row.Key, row.ValueJSON, toMS(row.UpdatedAt), row.UpdatedBy)
	return mapErr("put setting", err)
}

func (r settingsRepo) Delete(ctx context.Context, key string) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM settings_kv WHERE key = ?`, key)
	return mapErr("delete setting", err)
}

func (r settingsRepo) Rev(ctx context.Context) (int64, error) {
	var rev int64
	err := r.db.QueryRowContext(ctx, `SELECT rev FROM settings_rev WHERE id = 1`).Scan(&rev)
	return rev, mapErr("settings rev", err)
}

func (r settingsRepo) BumpRev(ctx context.Context, expect int64) (int64, error) {
	var next int64
	err := r.db.QueryRowContext(ctx, `UPDATE settings_rev SET rev = rev + 1 WHERE id = 1 AND rev = ? RETURNING rev`,
		expect).Scan(&next)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("store: bump settings rev: %w: revision is not %d", ErrConflict, expect)
	}
	return next, mapErr("bump settings rev", err)
}

// UserPrefs is one user's display preferences; "" means "use the default".
type UserPrefs struct {
	UserID     string
	TimeZone   string
	Theme      string
	DateFormat string
	Clock      string
	TempUnit   string
	Density    string
	UpdatedAt  time.Time
}

// PrefsRepository stores per-user display preferences.
type PrefsRepository interface {
	// Get returns the user's preferences; a user who never saved any gets
	// UserPrefs{UserID: id} (all defaults), not ErrNotFound.
	Get(ctx context.Context, userID string) (UserPrefs, error)
	// Put replaces the user's preferences.
	Put(ctx context.Context, p UserPrefs) error
}

type prefsRepo struct{ db querier }

func (r prefsRepo) Get(ctx context.Context, userID string) (UserPrefs, error) {
	p := UserPrefs{UserID: userID}
	var zone, theme, date, clock, temp, density sql.NullString
	var at int64
	err := r.db.QueryRowContext(ctx, `SELECT time_zone, theme, date_format, clock, temp_unit, density, updated_at
		FROM user_prefs WHERE user_id = ?`, userID).Scan(&zone, &theme, &date, &clock, &temp, &density, &at)
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	if err != nil {
		return UserPrefs{}, mapErr("user prefs", err)
	}
	p.TimeZone, p.Theme, p.DateFormat = zone.String, theme.String, date.String
	p.Clock, p.TempUnit, p.Density, p.UpdatedAt = clock.String, temp.String, density.String, fromMS(at)
	return p, nil
}

func (r prefsRepo) Put(ctx context.Context, p UserPrefs) error {
	const op = "put user prefs"
	if p.UserID == "" {
		return invalid(op, "user_id is required")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO user_prefs (user_id, time_zone, theme, date_format, clock, temp_unit,
		density, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (user_id) DO UPDATE SET
		time_zone = excluded.time_zone, theme = excluded.theme, date_format = excluded.date_format,
		clock = excluded.clock, temp_unit = excluded.temp_unit, density = excluded.density,
		updated_at = excluded.updated_at`,
		p.UserID, nullString(p.TimeZone), nullString(p.Theme), nullString(p.DateFormat), nullString(p.Clock),
		nullString(p.TempUnit), nullString(p.Density), toMS(p.UpdatedAt))
	return mapErr(op, err)
}
