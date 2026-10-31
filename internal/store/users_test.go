package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func testUser(id, name string) User {
	return User{ID: id, Username: name, Email: name + "@example.test", Role: RoleAdmin, //nolint:gosec // G101: dummy, unparseable test hash
		PwHash: "$argon2id$v=19$dummy", CreatedAt: t0}
}

func TestUserCRUD(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	users := db.Users()

	if n, err := users.Count(ctx); err != nil || n != 0 {
		t.Fatalf("Count = %d, %v", n, err)
	}
	u := testUser("u1", "morgan")
	if err := users.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := users.Create(ctx, testUser("u2", "morgan")); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate username err = %v", err)
	}
	noEmail := testUser("u3", "viewer")
	noEmail.Email, noEmail.Role = "", RoleViewer
	if err := users.Create(ctx, noEmail); err != nil {
		t.Fatalf("Create without email: %v", err)
	}
	other := testUser("u4", "other")
	other.Email = ""
	if err := users.Create(ctx, other); err != nil {
		t.Fatalf("two users without email must be allowed: %v", err)
	}
	bad := testUser("u5", "bad")
	bad.Role = "root"
	if err := users.Create(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad role err = %v", err)
	}

	got, err := users.ByUsername(ctx, "morgan")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != "u1" || got.Email != u.Email || !got.CreatedAt.Equal(t0) || got.Disabled {
		t.Errorf("ByUsername = %+v", got)
	}
	if _, err = users.ByID(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing err = %v", err)
	}
	list, err := users.List(ctx)
	if err != nil || len(list) != 3 || list[0].Username != "morgan" {
		t.Errorf("List = %v, %v", list, err)
	}
}

func TestUserMutators(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	users := db.Users()
	if err := users.Create(ctx, testUser("u1", "morgan")); err != nil {
		t.Fatal(err)
	}
	if err := users.SetPasswordHash(ctx, "u1", "$argon2id$new"); err != nil {
		t.Fatal(err)
	}
	if err := users.SetTOTPSecret(ctx, "u1", []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := users.SetDisabled(ctx, "u1", true); err != nil {
		t.Fatal(err)
	}
	if err := users.SetRole(ctx, "u1", RoleOperator); err != nil {
		t.Fatal(err)
	}
	got, _ := users.ByID(ctx, "u1")
	if got.PwHash != "$argon2id$new" || string(got.TOTPSecretEnc) != "\x01\x02\x03" || !got.Disabled ||
		got.Role != RoleOperator || got.TOTPLastStep != 0 {
		t.Errorf("after mutators = %+v", got)
	}
	for name, err := range map[string]error{
		"pw":       users.SetPasswordHash(ctx, "nope", "x"),
		"totp":     users.SetTOTPSecret(ctx, "nope", nil),
		"disabled": users.SetDisabled(ctx, "nope", false),
		"role":     users.SetRole(ctx, "nope", RoleViewer),
	} {
		if !errors.Is(err, ErrNotFound) {
			t.Errorf("%s on missing user: %v", name, err)
		}
	}
	if err := users.SetRole(ctx, "u1", "god"); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad role err = %v", err)
	}
}

func TestAdvanceTOTPStepRejectsReplay(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	users := db.Users()
	if err := users.Create(ctx, testUser("u1", "morgan")); err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		step int64
		want bool
	}{{100, true}, {100, false}, {99, false}, {101, true}}
	for _, s := range steps {
		ok, err := users.AdvanceTOTPStep(ctx, "u1", s.step)
		if err != nil || ok != s.want {
			t.Errorf("step %d: ok=%v err=%v want %v", s.step, ok, err, s.want)
		}
	}
	if err := users.SetTOTPSecret(ctx, "u1", []byte{9}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := users.AdvanceTOTPStep(ctx, "u1", 50); !ok {
		t.Error("new secret should reset the last step")
	}
}

func TestSessions(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := db.Users().Create(ctx, testUser("u1", "morgan")); err != nil {
		t.Fatal(err)
	}
	sessions := db.Sessions()
	s := Session{IDHash: []byte("hash-1"), UserID: "u1", CreatedAt: t0, LastSeen: t0, IP: "192.0.2.100", UA: "Safari"}
	if err := sessions.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	if err := sessions.Create(ctx, s); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate session err = %v", err)
	}
	orphan := Session{IDHash: []byte("hash-x"), UserID: "ghost", CreatedAt: t0, LastSeen: t0}
	if err := sessions.Create(ctx, orphan); !errors.Is(err, ErrInvalid) {
		t.Errorf("FK violation err = %v", err)
	}
	got, err := sessions.Get(ctx, []byte("hash-1"))
	if err != nil || got.UserID != "u1" || !got.StepUpAt.IsZero() || got.UA != "Safari" {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	later := t0.Add(10 * time.Minute)
	if err := sessions.Touch(ctx, s.IDHash, later); err != nil {
		t.Fatal(err)
	}
	if err := sessions.MarkStepUp(ctx, s.IDHash, later); err != nil {
		t.Fatal(err)
	}
	got, _ = sessions.Get(ctx, s.IDHash)
	if !got.LastSeen.Equal(later) || !got.StepUpAt.Equal(later) {
		t.Errorf("after touch/stepup = %+v", got)
	}
	if err := sessions.Touch(ctx, []byte("nope"), later); !errors.Is(err, ErrNotFound) {
		t.Errorf("touch missing = %v", err)
	}
	if err := sessions.MarkStepUp(ctx, []byte("nope"), later); !errors.Is(err, ErrNotFound) {
		t.Errorf("stepup missing = %v", err)
	}
	if err := sessions.Delete(ctx, s.IDHash); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Get(ctx, s.IDHash); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete = %v", err)
	}
	if err := sessions.Delete(ctx, s.IDHash); !errors.Is(err, ErrNotFound) {
		t.Errorf("double delete = %v", err)
	}
}

func TestSessionBulkDeletes(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := db.Users().Create(ctx, testUser("u1", "morgan")); err != nil {
		t.Fatal(err)
	}
	if err := db.Users().Create(ctx, testUser("u2", "other")); err != nil {
		t.Fatal(err)
	}
	sessions := db.Sessions()
	mk := func(id, user string, created, seen time.Time) {
		t.Helper()
		if err := sessions.Create(ctx, Session{IDHash: []byte(id), UserID: user, CreatedAt: created, LastSeen: seen}); err != nil {
			t.Fatal(err)
		}
	}
	mk("fresh", "u1", t0, t0)
	mk("idle", "u1", t0, t0.Add(-time.Hour))
	mk("old", "u2", t0.Add(-13*time.Hour), t0)
	mk("u2b", "u2", t0, t0)

	n, err := sessions.DeleteExpired(ctx, t0.Add(-30*time.Minute), t0.Add(-12*time.Hour))
	if err != nil || n != 2 {
		t.Errorf("DeleteExpired = %d, %v", n, err)
	}
	n, err = sessions.DeleteForUser(ctx, "u2")
	if err != nil || n != 1 {
		t.Errorf("DeleteForUser = %d, %v", n, err)
	}
	if _, err := sessions.Get(ctx, []byte("fresh")); err != nil {
		t.Errorf("fresh session gone: %v", err)
	}
}
