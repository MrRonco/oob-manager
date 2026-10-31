package authrepo

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/store"
)

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func openDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "oob.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func newAuth(t *testing.T, db *store.DB, c *clock) *auth.Authenticator {
	t.Helper()
	h, err := auth.NewPasswordHasher(auth.Argon2Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 2)
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := auth.NewAESGCMSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	r := New(db)
	a, err := auth.New(auth.Config{
		Users: r.Users, Sessions: r.Sessions, Lockouts: r.Lockouts, Hasher: h, Sealer: sealer,
		Now: c.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

const password = "correct horse battery staple"

// TestAuthFlowAgainstSQLite drives the real Authenticator through bootstrap, TOTP
// confirmation, login, step-up and logout with SQLite underneath.
func TestAuthFlowAgainstSQLite(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	c := &clock{now: t0}
	a := newAuth(t, db, c)

	enr, err := a.BootstrapAdmin(ctx, "morgan", password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.BootstrapAdmin(ctx, "second", password); !errors.Is(err, auth.ErrUsersExist) {
		t.Fatalf("second bootstrap: %v", err)
	}
	if _, err = a.BeginLogin(ctx, auth.LoginRequest{Username: "morgan", Password: password, IP: "192.0.2.100"}); err == nil {
		t.Fatal("login must be refused before TOTP is confirmed")
	}
	c.Advance(30 * time.Second)
	if err = a.ConfirmTOTP(ctx, "morgan", password, code(t, enr.Secret, c.Now()), "cli"); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	c.Advance(30 * time.Second)
	pending, err := a.BeginLogin(ctx, auth.LoginRequest{Username: "morgan", Password: password, IP: "192.0.2.100", UserAgent: "ua"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = a.Authenticate(ctx, pending); err == nil {
		t.Fatal("pending session must not authenticate")
	}
	tok, sess, err := a.CompleteLogin(ctx, pending, code(t, enr.Secret, c.Now()), "192.0.2.100", "ua")
	if err != nil {
		t.Fatalf("complete login: %v", err)
	}
	if _, _, err = a.CompleteLogin(ctx, pending, code(t, enr.Secret, c.Now()), "192.0.2.100", "ua"); err == nil {
		t.Fatal("pending token must be single-use (rotated away)")
	}
	id, err := a.Authenticate(ctx, tok)
	if err != nil || id.User.Role != authz.RoleAdmin || id.Session.Level != auth.LevelFull || !a.StepUpFresh(sess) {
		t.Fatalf("identity %+v err %v", id, err)
	}
	// The same TOTP step cannot be replayed for a step-up.
	if _, _, err = a.StepUp(ctx, tok, code(t, enr.Secret, c.Now())); err == nil {
		t.Fatal("replayed TOTP accepted")
	}
	c.Advance(30 * time.Second)
	tok2, _, err := a.StepUp(ctx, tok, code(t, enr.Secret, c.Now()))
	if err != nil {
		t.Fatalf("step-up: %v", err)
	}
	if _, err := a.Authenticate(ctx, tok); err == nil {
		t.Fatal("step-up must rotate the session ID")
	}
	if err := a.Logout(ctx, tok2); err != nil {
		t.Fatal(err)
	}
	if err := a.Logout(ctx, tok2); err != nil {
		t.Fatalf("second logout must be a no-op: %v", err)
	}
	if _, err := a.Authenticate(ctx, tok2); err == nil {
		t.Fatal("logged-out session still valid")
	}
}

func TestLockoutPersists(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	c := &clock{now: t0}
	a := newAuth(t, db, c)
	if _, err := a.BootstrapAdmin(ctx, "morgan", password); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, _ = a.BeginLogin(ctx, auth.LoginRequest{Username: "morgan", Password: "wrong password!!", IP: "192.0.2.9"})
	}
	// A fresh Authenticator over the same DB sees the counter (state is in SQLite).
	b := newAuth(t, db, c)
	_, err := b.BeginLogin(ctx, auth.LoginRequest{Username: "morgan", Password: password, IP: "192.0.2.9"})
	if !errors.Is(err, auth.ErrLockedOut) {
		t.Fatalf("want lockout, got %v", err)
	}
	st, err := New(db).Lockouts.Get(ctx, "acct:morgan")
	if err != nil || st.Failures < 5 {
		t.Fatalf("state %+v err %v", st, err)
	}
	if err := New(db).Lockouts.Reset(ctx, "acct:morgan"); err != nil {
		t.Fatal(err)
	}
}

func TestTokensAgainstSQLite(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	c := &clock{now: t0}
	a := newAuth(t, db, c)
	if _, err := a.BootstrapAdmin(ctx, "morgan", password); err != nil {
		t.Fatal(err)
	}
	u, err := New(db).Users.GetByUsername(ctx, "morgan")
	if err != nil {
		t.Fatal(err)
	}
	ts, err := auth.NewTokenService(New(db).Tokens, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	raw, tok, err := ts.Issue(ctx, "homepage", u.ID)
	if err != nil {
		t.Fatal(err)
	}
	c.Advance(time.Minute)
	got, p, err := ts.Verify(ctx, raw)
	if err != nil || got.ID != tok.ID || p.Kind != authz.KindToken || p.Role != authz.RoleViewer {
		t.Fatalf("verify %+v %+v %v", got, p, err)
	}
	stored, err := New(db).Tokens.GetByHash(ctx, tok.Hash)
	if err != nil || !stored.LastUsedAt.Equal(c.Now()) || stored.Scope != auth.ScopeRead {
		t.Fatalf("stored %+v err %v", stored, err)
	}
	if err := ts.Revoke(ctx, tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ts.Verify(ctx, raw); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("revoked token: %v", err)
	}
	if err := ts.Revoke(ctx, tok.ID); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("double revoke: %v", err)
	}
	if _, err := New(db).Tokens.GetByHash(ctx, []byte("nope")); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("missing token: %v", err)
	}
}

func TestUserAndSessionErrorsMap(t *testing.T) {
	ctx := context.Background()
	r := New(openDB(t))
	if _, err := r.Users.GetByID(ctx, "x"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("user by id: %v", err)
	}
	if _, err := r.Users.GetByUsername(ctx, "x"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("user by name: %v", err)
	}
	if err := r.Users.SetPasswordHash(ctx, "x", "h"); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("set hash: %v", err)
	}
	if ok, err := r.Users.AdvanceTOTPStep(ctx, "x", 5); ok || err != nil {
		t.Fatalf("advance on missing user: %v %v", ok, err)
	}
	if _, err := r.Sessions.Get(ctx, []byte("x")); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("session get: %v", err)
	}
	if err := r.Sessions.Touch(ctx, []byte("x"), t0); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("session touch: %v", err)
	}
	if err := r.Sessions.Replace(ctx, []byte("x"), auth.Session{IDHash: []byte("y"), UserID: "u"}); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("replace: %v", err)
	}
	if err := r.Sessions.DeleteForUser(ctx, "nobody"); err != nil {
		t.Fatalf("delete for user: %v", err)
	}
	if err := r.Users.CreateFirst(ctx, auth.User{}); errors.Is(err, auth.ErrUsersExist) || err == nil {
		t.Fatalf("invalid user: %v", err)
	}
}

func TestLevelMappingFailsClosed(t *testing.T) {
	if levelToStore(auth.Level(99)) != store.SessionPending || levelFromStore(store.SessionLevel(99)) != auth.LevelPending {
		t.Fatal("unknown levels must map to pending")
	}
	if levelFromStore(levelToStore(auth.LevelFull)) != auth.LevelFull {
		t.Fatal("full round trip")
	}
}

func TestExpiringTokensAndListAgainstSQLite(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	c := &clock{now: t0}
	a := newAuth(t, db, c)
	if _, err := a.BootstrapAdmin(ctx, "morgan", password); err != nil {
		t.Fatal(err)
	}
	u, err := New(db).Users.GetByUsername(ctx, "morgan")
	if err != nil {
		t.Fatal(err)
	}
	ts, err := auth.NewTokenService(New(db).Tokens, c.Now)
	if err != nil {
		t.Fatal(err)
	}
	raw, tok, err := ts.IssueExpiring(ctx, "dashboard", u.ID, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	list, err := New(db).Tokens.List(ctx)
	if err != nil || len(list) != 1 || !list[0].ExpiresAt.Equal(tok.ExpiresAt) || list[0].ID != tok.ID {
		t.Fatalf("List = %+v, %v", list, err)
	}
	c.Advance(2 * time.Hour)
	if _, _, err := ts.Verify(ctx, raw); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("expired token accepted: %v", err)
	}
}

func TestReEnrollTOTPAgainstSQLite(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	a := newAuth(t, db, &clock{now: t0})
	if _, err := a.BootstrapAdmin(ctx, "morgan", password); err != nil {
		t.Fatal(err)
	}
	users := New(db).Users
	u, err := users.GetByUsername(ctx, "morgan")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = users.AdvanceTOTPStep(ctx, u.ID, 99); err != nil {
		t.Fatal(err)
	}
	if err = users.SetTOTP(ctx, u.ID, u.TOTPSecretEnc, true); err != nil {
		t.Fatal(err)
	}
	if err = users.ReEnrollTOTP(ctx, u.ID, []byte("new-sealed-secret")); err != nil {
		t.Fatal(err)
	}
	got, err := users.GetByID(ctx, u.ID)
	if err != nil || got.TOTPConfirmed || got.TOTPLastStep != 0 || string(got.TOTPSecretEnc) != "new-sealed-secret" {
		t.Fatalf("after re-enrol %+v %v", got, err)
	}
	if err := users.ReEnrollTOTP(ctx, "missing", []byte("x")); !errors.Is(err, auth.ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
}
