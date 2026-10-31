package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// readOnlyConns is the read-only pool's size: chart pages and CSV exports run beside
// each other and beside the writer (WAL lets readers run while it writes).
const readOnlyConns = 2

// ReadDB is a read-only view of the database for the long reads of the history (charts
// and CSV exports) and their audit markers, so they never hold the single writer
// connection the audit chain relies on. Open the writer (Open) first: it creates the
// file, applies the migrations and switches it to WAL.
type ReadDB struct {
	sql *sql.DB
}

// OpenReadOnly opens path read-only (mode=ro, query_only, the writer's busy_timeout).
// The -wal and -shm files next to it must stay writable (they are, under /data).
func OpenReadOnly(ctx context.Context, path string) (*ReadDB, error) {
	if path == "" || !filepath.IsAbs(path) || strings.ContainsAny(path, "?#%") {
		return nil, fmt.Errorf("store: database path %q must be absolute without ?, # or %%", path)
	}
	// trusted_schema(0): a copy opened to verify it may come from anywhere, so functions
	// named in its schema (views, triggers, defaults) are not trusted (plan 06 review L5).
	dsn := "file:" + path + "?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(5000)&_pragma=trusted_schema(0)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open read-only: %w", err)
	}
	db.SetMaxOpenConns(readOnlyConns)
	if err := db.PingContext(ctx); err != nil {
		return nil, errors.Join(fmt.Errorf("store: open %s read-only: %w", path, err), db.Close())
	}
	return &ReadDB{sql: db}, nil
}

// Close closes the read-only pool.
func (d *ReadDB) Close() error { return d.sql.Close() }

// History returns the history reads on the read-only connection.
func (d *ReadDB) History() HistoryReader { return historyRepo{d.sql} }

// AuditSearch returns the audit viewer queries on the read-only connection.
func (d *ReadDB) AuditSearch() AuditSearcher { return auditRepo{d.sql} }
