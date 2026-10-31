package store

import (
	"context"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMaintenanceWindows(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := db.Maint()
	w := MaintenanceRow{ServerID: "srv-a", StartsAt: t0, EndsAt: t0.Add(time.Hour), Reason: "PSU swap",
		CreatedBy: "alice", CreatedAt: t0}
	if err := r.PutWindow(ctx, w); err != nil {
		t.Fatal(err)
	}
	open := MaintenanceRow{ServerID: "srv-b", StartsAt: t0, Reason: "rack move", CreatedBy: "bob", CreatedAt: t0}
	if err := r.PutWindow(ctx, open); err != nil {
		t.Fatal(err)
	}
	if err := r.MarkStarted(ctx, "srv-a"); err != nil {
		t.Fatal(err)
	}
	got, err := r.Windows(ctx)
	if err != nil || len(got) != 2 || !got[0].StartedNotified || !got[0].EndsAt.Equal(t0.Add(time.Hour)) ||
		!got[1].EndsAt.IsZero() || got[1].StartedNotified || got[1].Reason != "rack move" {
		t.Fatalf("windows %+v %v", got, err)
	}
	for _, bad := range []MaintenanceRow{
		{ServerID: "x", StartsAt: t0, EndsAt: t0, Reason: "r", CreatedBy: "a"}, // ends == starts
		{ServerID: "x", StartsAt: t0, Reason: "", CreatedBy: "a"},              // no reason
		{ServerID: "x", StartsAt: t0, Reason: strings.Repeat("r", 201), CreatedBy: "a"},
		{ServerID: "", StartsAt: t0, Reason: "r", CreatedBy: "a"},
	} {
		if err := r.PutWindow(ctx, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("CHECK let %+v through: %v", bad, err)
		}
	}
	if err := r.DeleteWindow(ctx, "srv-a"); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteWindow(ctx, "srv-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if err := r.MarkStarted(ctx, "srv-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mark missing: %v", err)
	}
	werr := db.WithTx(ctx, func(tx *Tx) error { return tx.Maint().DeleteWindow(ctx, "srv-b") })
	if got, _ := r.Windows(ctx); werr != nil || len(got) != 0 {
		t.Fatalf("delete in tx: %v %+v", werr, got)
	}
}

func TestServerNotes(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := db.Maint()
	add := func(server, body string, at time.Time) int64 {
		t.Helper()
		id, err := r.AddNote(ctx, NoteRow{ServerID: server, Body: body, AuthorID: "u1", Author: "alice",
			CreatedAt: at, UpdatedAt: at})
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := add("srv-a", "PSU2 cable loose", t0)
	second := add("srv-a", "replacement ordered", t0.Add(time.Minute))
	other := add("srv-b", "fine", t0)
	if err := r.SetPin(ctx, "srv-a", first); err != nil {
		t.Fatal(err)
	}
	if err := r.SetPin(ctx, "srv-a", second); err != nil { // moves the pin
		t.Fatal(err)
	}
	if err := r.SetPin(ctx, "srv-a", other); !errors.Is(err, ErrNotFound) { // another server's note
		t.Fatalf("pin of another server's note: %v", err)
	}
	if err := r.UpdateNote(ctx, first, "PSU2 cable reseated", t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	notes, err := r.Notes(ctx)
	if err != nil || len(notes) != 3 || notes[0].ID != second || !notes[0].Pinned || notes[1].Pinned ||
		notes[1].Body != "PSU2 cable reseated" || !notes[1].UpdatedAt.Equal(t0.Add(time.Hour)) || notes[2].ServerID != "srv-b" {
		t.Fatalf("notes %+v %v", notes, err)
	}
	if err := r.SetPin(ctx, "srv-a", 0); err != nil {
		t.Fatal(err)
	}
	if notes, _ = r.Notes(ctx); notes[0].Pinned {
		t.Fatal("unpin all left a pin")
	}
	if _, err := r.AddNote(ctx, NoteRow{ServerID: "srv-a", Body: strings.Repeat("é", 2049), AuthorID: "u", Author: "a"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("4 KiB byte cap: %v", err)
	}
	if _, err := r.AddNote(ctx, NoteRow{ServerID: "srv-a", Body: "", AuthorID: "u", Author: "a"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty note: %v", err)
	}
	if err := r.DeleteNote(ctx, first); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteNote(ctx, first); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if err := r.UpdateNote(ctx, first, "x", t0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update deleted: %v", err)
	}
}

func TestEventAcks(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := db.Maint()
	a := AckRow{ServerID: "srv-a", Log: "sel", EntryID: "12", CreatedMS: t0.UnixMilli(), Comment: "known",
		AckedBy: "alice", AckedAt: t0}
	if err := r.PutAck(ctx, a); err != nil {
		t.Fatal(err)
	}
	a.Comment, a.AckedBy = "re-acked", "bob"
	if err := r.PutAck(ctx, a); err != nil {
		t.Fatal(err)
	}
	same := a
	same.CreatedMS = 0 // a cleared log reusing id 12 is another entry
	same.AckedAt = t0.Add(48 * time.Hour)
	if err := r.PutAck(ctx, same); err != nil {
		t.Fatal(err)
	}
	acks, err := r.Acks(ctx)
	if err != nil || len(acks) != 2 || acks[0].Comment != "re-acked" || acks[0].AckedBy != "bob" {
		t.Fatalf("acks %+v %v", acks, err)
	}
	for _, bad := range []AckRow{
		{ServerID: "srv-a", Log: "other", EntryID: "1", AckedBy: "a"},
		{ServerID: "srv-a", Log: "sel", EntryID: "", AckedBy: "a"},
		{ServerID: "srv-a", Log: "sel", EntryID: "1", Comment: strings.Repeat("c", 501), AckedBy: "a"},
	} {
		if err := r.PutAck(ctx, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("CHECK let %+v through: %v", bad, err)
		}
	}
	if n, err := r.PruneAcks(ctx, t0.Add(time.Hour)); err != nil || n != 1 {
		t.Fatalf("prune: %d %v", n, err)
	}
	if err := r.DeleteAck(ctx, "srv-a", "sel", "12", 0); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteAck(ctx, "srv-a", "sel", "12", 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
}

// TestMutesBecomeMaintenanceWindows: 0009 turns each active notification mute into a
// maintenance window ending at the same time (already notified), drops expired mutes
// and the notify_mutes table.
func TestMutesBecomeMaintenanceWindows(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "oob.db")
	old, err := openSQL(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = migrate(ctx, old, migrationsUpTo(t, 8)); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(3 * time.Hour).UnixMilli()
	for _, q := range []string{
		`INSERT INTO notify_mutes (server_id, muted_until, updated_at, updated_by) VALUES ('srv-a', ` +
			strconv.FormatInt(future, 10) + `, 1000, 'alice')`,
		`INSERT INTO notify_mutes (server_id, muted_until, updated_at, updated_by) VALUES ('srv-old', 2000, 1000, 'bob')`,
	} {
		if _, err = old.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if err = old.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ws, err := db.Maint().Windows(ctx)
	if err != nil || len(ws) != 1 {
		t.Fatalf("windows %+v %v", ws, err)
	}
	w := ws[0]
	if w.ServerID != "srv-a" || w.EndsAt.UnixMilli() != future || w.StartsAt.UnixMilli() != 1000 ||
		w.CreatedBy != "alice" || !w.StartedNotified || !strings.Contains(w.Reason, "muted") {
		t.Fatalf("migrated window %+v", w)
	}
	var n int
	if err := db.sql.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE name = 'notify_mutes'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("notify_mutes still present (%d, %v)", n, err)
	}
}

// TestMaintenanceReminder: MarkReminded records when the last open-ended reminder went
// out; PutWindow and a fresh window leave it unset.
func TestMaintenanceReminder(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := db.Maint()
	open := MaintenanceRow{ServerID: "srv-b", StartsAt: t0, Reason: "rack move", CreatedBy: "bob", CreatedAt: t0,
		StartedNotified: true}
	if err := r.PutWindow(ctx, open); err != nil {
		t.Fatal(err)
	}
	if got, err := r.Windows(ctx); err != nil || len(got) != 1 || !got[0].RemindedAt.IsZero() {
		t.Fatalf("fresh window %+v %v", got, err)
	}
	at := t0.Add(25 * time.Hour)
	if err := r.MarkReminded(ctx, "srv-b", at); err != nil {
		t.Fatal(err)
	}
	if got, err := r.Windows(ctx); err != nil || len(got) != 1 || !got[0].RemindedAt.Equal(at) {
		t.Fatalf("reminded window %+v %v", got, err)
	}
	if err := r.MarkReminded(ctx, "nope", at); !errors.Is(err, ErrNotFound) {
		t.Fatalf("mark missing: %v", err)
	}
	// Replacing the window (a new one for the server) starts without a reminder.
	if err := r.PutWindow(ctx, open); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Windows(ctx); !got[0].RemindedAt.IsZero() {
		t.Fatalf("replaced window kept the reminder: %+v", got[0])
	}
}
