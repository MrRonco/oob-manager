// Package store is the SQLite persistence layer (modernc.org/sqlite, no cgo): embedded
// SQL migrations with a tiny runner, and repositories for the tech_doc §5 data model.
//
// Other packages should depend on the repository interfaces in repos.go; *DB hands out
// the SQLite implementations.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"modernc.org/sqlite"
	sqlite3 "modernc.org/sqlite/lib"
)

//go:embed migrations/*.sql
var embeddedMigrations embed.FS

// DB is an open, migrated database.
type DB struct {
	sql *sql.DB
}

// Open opens (creating if needed) the database at the absolute path and applies all
// pending migrations. It fails if the database schema is newer than this binary.
func Open(ctx context.Context, path string) (*DB, error) {
	db, err := openSQL(ctx, path)
	if err != nil {
		return nil, err
	}
	sub, err := fs.Sub(embeddedMigrations, "migrations")
	if err != nil {
		return nil, errors.Join(err, db.Close())
	}
	if err := migrate(ctx, db, sub); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return &DB{sql: db}, nil
}

func openSQL(ctx context.Context, path string) (*sql.DB, error) {
	if path == "" || !filepath.IsAbs(path) || strings.ContainsAny(path, "?#%") {
		return nil, fmt.Errorf("store: database path %q must be absolute without ?, # or %%", path)
	}
	dsn := "file:" + path +
		"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)" +
		"&_pragma=journal_size_limit(67108864)" + // the WAL shrinks back to 64 MiB after checkpoints (tech_doc §39)
		// BEGIN IMMEDIATE: a transaction takes the write lock when it begins, so a second
		// process (a CLI command beside serve) waits on busy_timeout instead of failing
		// with SQLITE_BUSY when its read turns into a write after another writer committed.
		"&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// One connection serialises writers (the audit chain relies on it) and avoids
	// SQLITE_BUSY between our own connections. Load is a handful of requests a minute.
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("store: open %s: %w", path, err), db.Close())
	}
	return db, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.sql.Close() }

// Ping checks the database is reachable (for /readyz).
func (d *DB) Ping(ctx context.Context) error { return d.sql.PingContext(ctx) }

// SchemaVersion returns the highest applied migration version.
func (d *DB) SchemaVersion(ctx context.Context) (int, error) {
	var v int
	err := d.sql.QueryRowContext(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	if err != nil {
		return 0, fmt.Errorf("store: schema version: %w", err)
	}
	return v, nil
}

// Users returns the user repository.
func (d *DB) Users() UserRepository { return userRepo{d.sql} }

// Sessions returns the session repository.
func (d *DB) Sessions() SessionRepository { return sessionRepo{d.sql} }

// Tokens returns the API token repository.
func (d *DB) Tokens() TokenRepository { return tokenRepo{d.sql} }

// Audit returns the audit log repository.
func (d *DB) Audit() AuditRepository { return auditRepo{d.sql} }

// AuditSearch returns the audit viewer queries.
func (d *DB) AuditSearch() AuditSearcher { return auditRepo{d.sql} }

// Accounts returns the guarded account changes.
func (d *DB) Accounts() AccountRepository { return accountRepo{d.sql} }

// Enrolments returns the enrolment link repository.
func (d *DB) Enrolments() EnrolmentRepository { return enrolmentRepo{d.sql} }

// Leases returns the fan lease repository.
func (d *DB) Leases() LeaseRepository { return leaseRepo{d.sql} }

// Lockouts returns the login failure repository.
func (d *DB) Lockouts() LockoutRepository { return lockoutRepo{d.sql} }

// Settings returns the runtime-managed settings repository.
func (d *DB) Settings() SettingsRepository { return settingsRepo{d.sql} }

// Prefs returns the per-user display preferences repository.
func (d *DB) Prefs() PrefsRepository { return prefsRepo{d.sql} }

// Capabilities returns the capability repository.
func (d *DB) Capabilities() CapabilityRepository { return capabilityRepo{d.sql} }

// Servers returns the browser-managed server repository.
func (d *DB) Servers() ServerRepository { return serverRepo{d.sql} }

// Credentials returns the sealed BMC credential repository.
func (d *DB) Credentials() CredentialRepository { return credentialRepo{d.sql} }

// mapErr translates SQLite constraint errors to the package sentinels.
func mapErr(op string, err error) error {
	if err == nil {
		return nil
	}
	var se *sqlite.Error
	if errors.As(err, &se) {
		switch se.Code() {
		case sqlite3.SQLITE_CONSTRAINT_UNIQUE, sqlite3.SQLITE_CONSTRAINT_PRIMARYKEY:
			return fmt.Errorf("store: %s: %w: %w", op, ErrConflict, err)
		case sqlite3.SQLITE_CONSTRAINT_CHECK, sqlite3.SQLITE_CONSTRAINT_FOREIGNKEY,
			sqlite3.SQLITE_CONSTRAINT_NOTNULL, sqlite3.SQLITE_CONSTRAINT_DATATYPE:
			return fmt.Errorf("store: %s: %w: %w", op, ErrInvalid, err)
		}
	}
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: %s: %w", op, ErrNotFound)
	}
	return fmt.Errorf("store: %s: %w", op, err)
}

func invalid(op, msg string) error { return fmt.Errorf("store: %s: %w: %s", op, ErrInvalid, msg) }

// execOne runs a statement that must affect exactly one row.
func execOne(ctx context.Context, db querier, op, q string, args ...any) error {
	res, err := db.ExecContext(ctx, q, args...)
	if err != nil {
		return mapErr(op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return mapErr(op, err)
	}
	if n == 0 {
		return fmt.Errorf("store: %s: %w", op, ErrNotFound)
	}
	return nil
}

func execCount(ctx context.Context, db querier, op, q string, args ...any) (int64, error) {
	res, err := db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, mapErr(op, err)
	}
	n, err := res.RowsAffected()
	return n, mapErr(op, err)
}

func toMS(t time.Time) int64 { return t.UnixMilli() }

func fromMS(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

// nullMS stores a zero time as NULL.
func nullMS(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixMilli()
}

func fromNullMS(n sql.NullInt64) time.Time {
	if !n.Valid {
		return time.Time{}
	}
	return fromMS(n.Int64)
}

func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
