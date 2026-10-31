package maint

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNotesLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	first, err := e.svc.AddNote(ctx, alice, "srv-a", "PSU2 cable loose\r\nreplacement ordered  ")
	if err != nil {
		t.Fatal(err)
	}
	if first.Body != "PSU2 cable loose\nreplacement ordered" || first.Author != "alice" || first.ID == 0 {
		t.Fatalf("note %+v", first)
	}
	e.advance(time.Minute)
	second, err := e.svc.AddNote(ctx, bob, "srv-a", "decision 6: COM2 pending")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.PinNote(ctx, bob, "srv-a", first.ID); err != nil {
		t.Fatal(err)
	}
	notes := e.svc.Notes("srv-a")
	if len(notes) != 2 || notes[0].ID != first.ID || !notes[0].Pinned || notes[1].ID != second.ID {
		t.Fatalf("pinned first, then newest: %+v", notes)
	}
	// Only the author edits; an admin may delete anyone's note.
	if err := e.svc.EditNote(ctx, bob, "srv-a", first.ID, "mine now"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("edit of another's note: %v", err)
	}
	if err := e.svc.DeleteNote(ctx, bob, "srv-a", first.ID); !errors.Is(err, ErrForbidden) {
		t.Fatalf("operator delete of another's note: %v", err)
	}
	e.advance(time.Minute)
	if err := e.svc.EditNote(ctx, alice, "srv-a", first.ID, "PSU2 cable reseated"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.EditNote(ctx, alice, "srv-a", first.ID, "PSU2 cable reseated"); err != nil {
		t.Fatal(err) // unchanged: no-op, not audited
	}
	if n, _ := e.svc.Note("srv-a", first.ID); n.Body != "PSU2 cable reseated" || !n.Edited() || !n.Pinned {
		t.Fatalf("edited %+v", n)
	}
	if err := e.svc.EditNote(ctx, alice, "srv-b", first.ID, "x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("note of another server: %v", err)
	}
	if err := e.svc.DeleteNote(ctx, root, "srv-a", second.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteNote(ctx, alice, "srv-a", first.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.DeleteNote(ctx, alice, "srv-a", first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if err := e.svc.PinNote(ctx, alice, "srv-a", first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("pin of a deleted note: %v", err)
	}
	if err := e.svc.PinNote(ctx, alice, "srv-a", 0); err != nil {
		t.Fatal(err)
	}
	text := e.auditText()
	if strings.Contains(text, "PSU2") || strings.Contains(text, "COM2") {
		t.Fatalf("note text reached the audit log:\n%s", text)
	}
	for _, a := range []string{ActionNoteAdd, ActionNoteEdit, ActionNoteDelete, ActionNotePin} {
		if !strings.Contains(text, a) {
			t.Fatalf("audit lacks %s:\n%s", a, text)
		}
	}
	if n := strings.Count(text, ActionNoteEdit); n != 1 {
		t.Fatalf("%d edit rows, want 1", n)
	}
}

func TestNoteValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for name, body := range map[string]string{
		"empty":   " \n\t ",
		"control": "bell\a",
		"escape":  "esc\x1b[31m",
		"too big": strings.Repeat("é", MaxNoteBytes/2+1),
		"invalid": "\xff\xfe",
	} {
		if _, err := e.svc.AddNote(ctx, alice, "srv-a", body); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.AddNote(ctx, alice, "srv-a", strings.Repeat("x", MaxNoteBytes)); err != nil {
		t.Fatalf("exactly 4 KiB: %v", err)
	}
	if _, err := e.svc.AddNote(ctx, alice, "srv-a", "<script>alert(1)</script>\ttab"); err != nil {
		t.Fatalf("markup is plain text: %v", err) // escaped when rendered
	}
	if _, err := e.svc.AddNote(ctx, alice, "", "x"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no server: %v", err)
	}
	for range MaxNotesPerServer - 2 {
		if _, err := e.svc.AddNote(ctx, bob, "srv-a", "n"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.AddNote(ctx, bob, "srv-a", "one too many"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("note cap: %v", err)
	}
	if err := e.svc.EditNote(ctx, alice, "srv-a", 1, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("edit to empty: %v", err)
	}
}

func TestAcknowledgements(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	at := t0.Add(-time.Hour)
	fan := EventRef{ServerID: "srv-a", Log: LogSEL, EntryID: "12", Created: at}
	psu := EventRef{ServerID: "srv-a", Log: LogLifecycle, EntryID: "PSU0003", Created: at}
	n, err := e.svc.Ack(ctx, alice, "srv-a", []EventRef{fan, psu}, " known: fan 1 replaced ")
	if err != nil || n != 2 {
		t.Fatalf("ack: %d %v", n, err)
	}
	a, ok := e.svc.AckOf(fan)
	if !ok || a.By != "alice" || a.Comment != "known: fan 1 replaced" || !a.At.Equal(t0) {
		t.Fatalf("ack %+v", a)
	}
	if !e.svc.Acked("srv-a", LogSEL, "12", at) {
		t.Fatal("Acked")
	}
	// A new entry of the same kind is not acknowledged: another id, or the same id with
	// another timestamp (a cleared log reuses ids).
	if e.svc.Acked("srv-a", LogSEL, "13", at) || e.svc.Acked("srv-a", LogSEL, "12", at.Add(time.Second)) ||
		e.svc.Acked("srv-b", LogSEL, "12", at) {
		t.Fatal("ack leaked to another entry")
	}
	if got := e.svc.Acks("srv-a"); len(got) != 2 {
		t.Fatalf("acks %+v", got)
	}
	if _, ok := e.open().AckOf(psu); !ok {
		t.Fatal("ack not persisted")
	}
	if !strings.Contains(e.auditText(), `alice srv-a server.event.ack {"comment":"known: fan 1 replaced","count":2,"entries":["sel:12","lifecycle:PSU0003"]}`) {
		t.Fatalf("audit:\n%s", e.auditText())
	}
	// Re-acknowledging replaces the comment and the acknowledger.
	e.advance(time.Minute)
	if _, err := e.svc.Ack(ctx, bob, "srv-a", []EventRef{fan}, ""); err != nil {
		t.Fatal(err)
	}
	if a, _ := e.svc.AckOf(fan); a.By != "bob" || a.Comment != "" {
		t.Fatalf("re-ack %+v", a)
	}
	if err := e.svc.Unack(ctx, bob, fan); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Unack(ctx, bob, fan); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second unack: %v", err)
	}
	if e.svc.Acked("srv-a", LogSEL, "12", at) || !strings.Contains(e.auditText(), ActionUnack) {
		t.Fatal("unack")
	}
	noTime := EventRef{ServerID: "srv-a", Log: LogSEL, EntryID: "99"}
	if _, err := e.svc.Ack(ctx, alice, "srv-a", []EventRef{noTime}, ""); err != nil || !e.svc.Acked("srv-a", LogSEL, "99", time.Time{}) {
		t.Fatalf("entry without a timestamp: %v", err)
	}
}

func TestAckValidationAndPrune(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ok := EventRef{ServerID: "srv-a", Log: LogSEL, EntryID: "1", Created: t0}
	bad := map[string][]EventRef{
		"none":           nil,
		"other server":   {ok, {ServerID: "srv-b", Log: LogSEL, EntryID: "1"}},
		"unknown log":    {{ServerID: "srv-a", Log: "audit", EntryID: "1"}},
		"empty id":       {{ServerID: "srv-a", Log: LogSEL}},
		"control in id":  {{ServerID: "srv-a", Log: LogSEL, EntryID: "1\n2"}},
		"too many":       make([]EventRef, MaxAcksPerRequest+1),
		"long id":        {{ServerID: "srv-a", Log: LogSEL, EntryID: strings.Repeat("9", MaxEntryIDBytes+1)}},
		"no server name": {{Log: LogSEL, EntryID: "1"}},
	}
	for name, refs := range bad {
		if _, err := e.svc.Ack(ctx, alice, "srv-a", refs, ""); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.Ack(ctx, alice, "srv-a", []EventRef{ok}, strings.Repeat("c", MaxCommentBytes+1)); !errors.Is(err, ErrInvalid) {
		t.Errorf("long comment: %v", err)
	}
	if _, err := e.svc.Ack(ctx, alice, "srv-a", []EventRef{ok}, "two\nlines"); !errors.Is(err, ErrInvalid) {
		t.Errorf("multi-line comment: %v", err)
	}
	if err := e.svc.Unack(ctx, alice, EventRef{ServerID: "srv-a", Log: "x", EntryID: "1"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("unack bad ref: %v", err)
	}
	if _, err := e.svc.Ack(ctx, alice, "srv-a", []EventRef{ok}, ""); err != nil {
		t.Fatal(err)
	}
	e.advance(AckRetention + time.Hour)
	e.svc.prune(ctx, e.clock())
	if e.svc.Acked("srv-a", LogSEL, "1", t0) {
		t.Fatal("old acknowledgement not pruned")
	}
}
