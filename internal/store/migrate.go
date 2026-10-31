package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"time"
)

// migrationName is NNNN_description.sql; NNNN is the version (> 0).
var migrationName = regexp.MustCompile(`^(\d{4})_[a-z0-9_]+\.sql$`)

type migration struct {
	version int
	name    string
	sql     string
}

// migrate applies every migration in fsys not yet recorded in schema_migrations, each
// in its own transaction. Files not ending in .sql are ignored.
func migrate(ctx context.Context, db *sql.DB, fsys fs.FS) error {
	all, err := readMigrations(fsys)
	if err != nil {
		return err
	}
	if _, err = db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL) STRICT`); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	applied, err := appliedVersions(ctx, db)
	if err != nil {
		return err
	}
	if err := checkNotNewer(applied, all); err != nil {
		return err
	}
	for _, m := range all {
		if applied[m.version] {
			continue
		}
		if err := applyMigration(ctx, db, m); err != nil {
			return err
		}
	}
	return nil
}

func readMigrations(fsys fs.FS) ([]migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("store: migrations: %w", err)
	}
	seen := map[int]string{}
	var out []migration
	for _, e := range entries {
		if e.IsDir() || len(e.Name()) < 4 || e.Name()[len(e.Name())-4:] != ".sql" {
			continue
		}
		m, err := parseMigration(fsys, e.Name())
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[m.version]; dup {
			return nil, fmt.Errorf("store: migrations %s and %s share version %d", prev, m.name, m.version)
		}
		seen[m.version] = m.name
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	return out, nil
}

func parseMigration(fsys fs.FS, name string) (migration, error) {
	match := migrationName.FindStringSubmatch(name)
	if match == nil {
		return migration{}, fmt.Errorf("store: migration file %q must be NNNN_name.sql", name)
	}
	v, err := strconv.Atoi(match[1])
	if err != nil || v == 0 {
		return migration{}, fmt.Errorf("store: migration %q: version must be > 0", name)
	}
	body, err := fs.ReadFile(fsys, name)
	if err != nil {
		return migration{}, fmt.Errorf("store: migration %q: %w", name, err)
	}
	return migration{version: v, name: name, sql: string(body)}, nil
}

func appliedVersions(ctx context.Context, db *sql.DB) (map[int]bool, error) {
	rows, err := db.QueryContext(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	defer rows.Close()
	applied := map[int]bool{}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("store: migrate: %w", err)
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func checkNotNewer(applied map[int]bool, known []migration) error {
	knownSet := map[int]bool{}
	for _, m := range known {
		knownSet[m.version] = true
	}
	for v := range applied {
		if !knownSet[v] {
			return fmt.Errorf("store: database has migration %d unknown to this binary (database is newer)", v)
		}
	}
	return nil
}

func applyMigration(ctx context.Context, db *sql.DB, m migration) (err error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: migration %s: %w", m.name, err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, tx.Rollback())
		}
	}()
	if _, err = tx.ExecContext(ctx, m.sql); err != nil {
		return fmt.Errorf("store: migration %s: %w", m.name, err)
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)`,
		m.version, m.name, time.Now().UnixMilli()); err != nil {
		return fmt.Errorf("store: migration %s: %w", m.name, err)
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("store: migration %s: %w", m.name, err)
	}
	return nil
}
