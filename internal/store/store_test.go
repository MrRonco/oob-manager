package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "oob.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return db
}

func TestOpenMigratesEmptyDB(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	v, err := db.SchemaVersion(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if v < 1 {
		t.Fatalf("schema version = %d", v)
	}
	for _, table := range []string{"users", "sessions", "api_tokens", "audit_log", "fan_leases",
		"capabilities", "sensor_keys", "sensor_raw", "sensor_hourly", "sensor_daily", "history_meta", "console_sessions", "schema_migrations", "servers", "bmc_credentials"} {
		var n int
		err := db.sql.QueryRowContext(ctx,
			`SELECT count(*) FROM sqlite_schema WHERE type='table' AND name=?`, table).Scan(&n)
		if err != nil || n != 1 {
			t.Errorf("table %s missing (n=%d err=%v)", table, n, err)
		}
	}
	if err := db.Ping(ctx); err != nil {
		t.Errorf("Ping: %v", err)
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oob.db")
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		db, err := Open(ctx, path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOpenRejectsBadPath(t *testing.T) {
	ctx := context.Background()
	for _, p := range []string{"", "relative.db", "/tmp/x?mode=ro", filepath.Join(t.TempDir(), "no", "such", "dir", "x.db")} {
		if _, err := Open(ctx, p); err == nil {
			t.Errorf("Open(%q) succeeded", p)
		}
	}
}

func TestMigrateRunner(t *testing.T) {
	ctx := context.Background()
	good := fstest.MapFS{
		"0001_a.sql": {Data: []byte("CREATE TABLE a (x INTEGER) STRICT;")},
		"0002_b.sql": {Data: []byte("CREATE TABLE b (x INTEGER) STRICT; INSERT INTO b VALUES (1);")},
		"README":     {Data: []byte("ignored")},
	}
	fresh := openRaw(t)
	if err := migrate(ctx, fresh, good); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := migrate(ctx, fresh, good); err != nil {
		t.Fatalf("re-migrate: %v", err)
	}
	cases := map[string]fstest.MapFS{
		"bad sql":      {"0001_x.sql": {Data: []byte("CREATE TABLE")}},
		"bad name":     {"x_0001.sql": {Data: []byte("SELECT 1;")}},
		"zero version": {"0000_x.sql": {Data: []byte("SELECT 1;")}},
		"dup version":  {"0001_a.sql": {Data: []byte("SELECT 1;")}, "0001_b.sql": {Data: []byte("SELECT 1;")}},
	}
	for name, fsys := range cases {
		t.Run(name, func(t *testing.T) {
			if err := migrate(ctx, openRaw(t), fsys); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	t.Run("db newer than binary", func(t *testing.T) {
		older := fstest.MapFS{"0001_a.sql": good["0001_a.sql"]}
		err := migrate(ctx, fresh, older)
		if err == nil || !strings.Contains(err.Error(), "newer") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestBlankRequiredIDsRejected(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	errs := []error{
		db.Users().Create(ctx, User{}),
		db.Sessions().Create(ctx, Session{}),
		db.Tokens().Create(ctx, APIToken{}),
		db.Leases().Create(ctx, FanLease{}),
		db.Capabilities().Put(ctx, Capability{}),
	}
	for i, err := range errs {
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("case %d: err = %v, want ErrInvalid", i, err)
		}
	}
}

func TestClosedDBErrors(t *testing.T) {
	db, err := Open(context.Background(), filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := db.Users().ByID(ctx, "x"); err == nil {
		t.Error("query on closed DB succeeded")
	}
	if _, err := db.SchemaVersion(ctx); err == nil {
		t.Error("SchemaVersion on closed DB succeeded")
	}
	if _, _, err := db.Audit().Last(ctx); err == nil {
		t.Error("audit Last on closed DB succeeded")
	}
	if _, err := db.Audit().Append(ctx, func(AuditRecord, bool) (AuditRecord, error) {
		return AuditRecord{}, nil
	}); err == nil {
		t.Error("audit Append on closed DB succeeded")
	}
}

func openRaw(t *testing.T) *sql.DB {
	t.Helper()
	db, err := openSQL(context.Background(), filepath.Join(t.TempDir(), "raw.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}
