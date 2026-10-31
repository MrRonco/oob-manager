package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func enrolToken(id, user, hash string, purpose EnrolPurpose) EnrolmentToken {
	return EnrolmentToken{ID: id, UserID: user, TokenHash: []byte(hash), Purpose: purpose, CreatedBy: "a1",
		CreatedAt: t0, ExpiresAt: t0.Add(24 * time.Hour)}
}

func TestEnrolmentTokenLifecycle(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mustCreateUser(t, db, "a1", "alice", RoleAdmin)
	mustCreateUser(t, db, "v1", "victor", RoleViewer)
	e := db.Enrolments()
	if err := e.Create(ctx, enrolToken("e1", "v1", "hash-1", EnrolPurposeEnrol)); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := e.ByHash(ctx, []byte("hash-1"))
	if err != nil || got.UserID != "v1" || got.Purpose != EnrolPurposeEnrol || !got.UsedAt.IsZero() {
		t.Fatalf("ByHash = %+v, %v", got, err)
	}
	if _, err = e.Consume(ctx, []byte("hash-1"), t0.Add(25*time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired consume err = %v", err)
	}
	used, err := e.Consume(ctx, []byte("hash-1"), t0.Add(time.Hour))
	if err != nil || used.ID != "e1" || used.UsedAt.IsZero() {
		t.Fatalf("Consume = %+v, %v", used, err)
	}
	if _, err := e.Consume(ctx, []byte("hash-1"), t0.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second consume err = %v (tokens are single-use)", err)
	}
	if _, err := e.ByHash(ctx, []byte("nope")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown hash err = %v", err)
	}
}

func TestEnrolmentTokenValidation(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mustCreateUser(t, db, "a1", "alice", RoleAdmin)
	e := db.Enrolments()
	bad := enrolToken("e1", "a1", "h", EnrolPurpose("other"))
	if err := e.Create(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad purpose err = %v", err)
	}
	noUser := enrolToken("e2", "ghost", "h2", EnrolPurposeReset)
	if err := e.Create(ctx, noUser); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown user err = %v", err)
	}
	backwards := enrolToken("e3", "a1", "h3", EnrolPurposeReset)
	backwards.ExpiresAt = t0
	if err := e.Create(ctx, backwards); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expiry before creation err = %v", err)
	}
	if err := e.Create(ctx, EnrolmentToken{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty token err = %v", err)
	}
}

func TestEnrolmentInvalidateAndPending(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mustCreateUser(t, db, "a1", "alice", RoleAdmin)
	mustCreateUser(t, db, "v1", "victor", RoleViewer)
	e := db.Enrolments()
	for _, tok := range []EnrolmentToken{enrolToken("e1", "v1", "h1", EnrolPurposeEnrol),
		enrolToken("e2", "v1", "h2", EnrolPurposeReset)} {
		if err := e.Create(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	pending, err := e.Pending(ctx, t0.Add(time.Hour))
	if err != nil || len(pending) != 2 {
		t.Fatalf("Pending = %+v, %v", pending, err)
	}
	if n, err := e.InvalidateForUser(ctx, "v1", t0.Add(time.Minute)); err != nil || n != 2 {
		t.Fatalf("InvalidateForUser = %d, %v", n, err)
	}
	if _, err := e.Consume(ctx, []byte("h2"), t0.Add(2*time.Minute)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("invalidated token consumed: %v", err)
	}
	if pending, _ := e.Pending(ctx, t0.Add(time.Hour)); len(pending) != 0 {
		t.Fatalf("pending after invalidate = %+v", pending)
	}
	if n, err := e.Prune(ctx, t0.Add(48*time.Hour)); err != nil || n != 2 {
		t.Fatalf("Prune = %d, %v", n, err)
	}
}
