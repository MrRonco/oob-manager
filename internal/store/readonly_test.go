package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openPair(t *testing.T) (*DB, *ReadDB) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "oob.db")
	ctx := context.Background()
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	ro, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := ro.Close(); err != nil {
			t.Error(err)
		}
		if err := db.Close(); err != nil {
			t.Error(err)
		}
	})
	return db, ro
}

func TestOpenReadOnlyRefusesBadPaths(t *testing.T) {
	for _, p := range []string{"", "relative.db", "/tmp/x.db?mode=rw", "/tmp/x#y"} {
		if _, err := OpenReadOnly(context.Background(), p); err == nil {
			t.Errorf("OpenReadOnly(%q) accepted", p)
		}
	}
}

// TestReadOnlyConnectionCannotWrite: query_only refuses every write, whatever the SQL.
func TestReadOnlyConnectionCannotWrite(t *testing.T) {
	_, ro := openPair(t)
	ctx := context.Background()
	for _, q := range []string{`UPDATE history_meta SET hourly_done = 0`, `DELETE FROM sensor_keys`,
		`CREATE TABLE x (a INTEGER)`} {
		if _, err := ro.sql.ExecContext(ctx, q); err == nil {
			t.Errorf("read-only connection ran %q", q)
		}
	}
	if err := (historyRepo{ro.sql}).NoteClockJump(ctx, t0); err == nil {
		t.Error("a write method worked on the read-only connection")
	}
}

// TestReadOnlyReadsBesideTheWriter: the read-only pool sees the writer's commits, and
// a read left open (a slow CSV download) does not hold the writer: an audit append
// and a sample insert complete well inside busy_timeout.
func TestReadOnlyReadsBesideTheWriter(t *testing.T) {
	db, ro := openPair(t)
	ctx := context.Background()
	h := db.History()
	seedMinutes(t, h, "r1", t0, 50, func(i int) float64 { return float64(i) })
	id := keyID(t, ro.History(), "r1", "temp:1")
	rows, err := ro.sql.QueryContext(ctx, `SELECT ts, value FROM sensor_raw WHERE key_id = ? ORDER BY ts`, id)
	if err != nil {
		t.Fatal(err)
	}
	if !rows.Next() {
		t.Fatal("no rows")
	}
	wctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	started := time.Now()
	if _, err = db.Audit().Append(wctx, func(AuditRecord, bool) (AuditRecord, error) { return auditRow(1, strings.Repeat("0", 64)), nil }); err != nil {
		t.Fatalf("audit append beside an open read: %v", err)
	}
	if _, err = h.Insert(wctx, poll("r1", t0.Add(time.Hour), temp("1", 1))); err != nil {
		t.Fatalf("insert beside an open read: %v", err)
	}
	if took := time.Since(started); took > time.Second {
		t.Errorf("writes waited %v for the reader", took)
	}
	if err = rows.Close(); err != nil {
		t.Fatal(err)
	}
	pts, err := ro.History().Raw(ctx, id, t0, t0.Add(2*time.Hour), time.Time{}, 100)
	if err != nil || len(pts) != 51 {
		t.Errorf("read-only sees %d rows, %v; want 51", len(pts), err)
	}
	if _, err := ro.AuditSearch().Search(ctx, AuditFilter{Limit: 10}); err != nil {
		t.Errorf("audit search on the read-only connection: %v", err)
	}
	if m, err := ro.History().Meta(ctx); err != nil || m.HourlyDone.UnixMilli() != 0 {
		t.Errorf("meta = %+v, %v", m, err)
	}
}

// TestTwoWritersWaitInsteadOfFailing: a second process on the same file (a CLI command
// beside serve) whose transaction reads and then writes never fails with SQLITE_BUSY
// because the other process committed in between: transactions begin IMMEDIATE, so
// the other writer waits on busy_timeout.
func TestTwoWritersWaitInsteadOfFailing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oob.db")
	ctx := context.Background()
	a, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = a.Close() }()
	b, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	other := make(chan error, 1)
	err = a.WithTx(ctx, func(tx *Tx) error {
		if _, _, lerr := tx.Audit().Last(ctx); lerr != nil { // the read
			return lerr
		}
		go func() { // the other process writes meanwhile
			_, ierr := b.History().Insert(ctx, poll("r1", t0, temp("1", 1)))
			other <- ierr
		}()
		time.Sleep(150 * time.Millisecond)
		_, aerr := tx.Audit().Append(ctx, func(AuditRecord, bool) (AuditRecord, error) {
			return auditRow(1, strings.Repeat("0", 64)), nil
		})
		return aerr // the write
	})
	if err != nil {
		t.Fatalf("the reading transaction could not write: %v", err)
	}
	if err = <-other; err != nil {
		t.Fatalf("the other writer failed instead of waiting: %v", err)
	}
}
