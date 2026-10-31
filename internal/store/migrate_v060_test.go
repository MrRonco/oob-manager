package store

import (
	"context"
	"path/filepath"
	"testing"
)

// v060Schema is the migration level of the v0.6 integration (0001–0010).
const v060Schema = 10

// TestUpgradeFromV060Schema migrates a database at schema 0010 to head: the maintenance
// window, its reminder, a note and an event acknowledgement survive, and the security
// check tables (0011) start empty and usable.
func TestUpgradeFromV060Schema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oob.db")
	old, err := openSQL(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate(ctx, old, migrationsUpTo(t, v060Schema)); err != nil {
		t.Fatalf("migrate to %d: %v", v060Schema, err)
	}
	for _, q := range []string{
		`INSERT INTO server_maintenance (server_id, starts_at, reason, created_by, created_at, started_notified, reminded_at)
			VALUES ('lab1', 1000, 'rack move', 'morgan', 1000, 1, 2000)`,
		`INSERT INTO server_notes (server_id, body, author_id, author, created_at, updated_at) VALUES ('lab1', 'PSU2 swapped', 'u1', 'morgan', 1, 1)`,
		`INSERT INTO event_acks (server_id, log, entry_id, created_ms, acked_by, acked_at) VALUES ('lab1', 'sel', '7', 5, 'morgan', 6)`,
	} {
		if _, err = old.ExecContext(ctx, q); err != nil {
			t.Fatalf("seed %q: %v", q, err)
		}
	}
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("upgrade to head: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if v, verr := db.SchemaVersion(ctx); verr != nil || v != headSchema {
		t.Fatalf("schema = %d, %v; want %d", v, verr, headSchema)
	}
	ws, err := db.Maint().Windows(ctx)
	if err != nil || len(ws) != 1 || ws[0].RemindedAt.UnixMilli() != 2000 {
		t.Fatalf("window %+v %v", ws, err)
	}
	notes, nerr := db.Maint().Notes(ctx)
	acks, aerr := db.Maint().Acks(ctx)
	if nerr != nil || aerr != nil || len(notes) != 1 || len(acks) != 1 {
		t.Fatalf("notes %+v %v acks %+v %v", notes, nerr, acks, aerr)
	}
	accepts, aerr := db.Security().Accepts(ctx)
	notified, nerr := db.Security().Notified(ctx)
	if aerr != nil || nerr != nil || len(accepts) != 0 || len(notified) != 0 {
		t.Fatalf("new tables %v %v", aerr, nerr)
	}
	if err := db.Security().PutAccept(ctx, SecurityAcceptRow{ServerID: "lab1", ServerAddr: "192.0.2.12:443", CheckID: "svc.ipmi",
		Result: "warn", Subject: "on", SubjectHash: hashA, Comment: "lab", AcceptedBy: "morgan", AcceptedAt: t0}); err != nil {
		t.Fatalf("security_accepts after upgrade: %v", err)
	}
}
