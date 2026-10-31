package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/store"
	"oob-manager/internal/store/authrepo"
)

const testPassword = "correct horse battery staple"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// failingAudit wraps a real logger and fails RecordTx on demand.
type failingAudit struct {
	*audit.Logger
	fail bool
}

func (f *failingAudit) RecordTx(ctx context.Context, tx *store.Tx, e audit.Entry) (store.AuditRecord, error) {
	if f.fail {
		return store.AuditRecord{}, errors.New("audit store down")
	}
	return f.Logger.RecordTx(ctx, tx, e)
}

type fixture struct {
	t      *testing.T
	db     *store.DB
	svc    *Service
	authn  *auth.Authenticator
	tokens *auth.TokenService
	clk    *clock
	audit  *failingAudit
	admin  Actor
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "admin.db"))
	must(t, err)
	t.Cleanup(func() { _ = db.Close() })
	clk := &clock{t: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	hasher, err := auth.NewPasswordHasher(auth.Argon2Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}, 2)
	must(t, err)
	sealer, err := auth.NewAESGCMSealer(bytes.Repeat([]byte{3}, 32))
	must(t, err)
	repos := authrepo.New(db)
	authn, err := auth.New(auth.Config{Users: repos.Users, Sessions: repos.Sessions, Lockouts: repos.Lockouts,
		Hasher: hasher, Sealer: sealer, Now: clk.Now, Logger: quiet})
	must(t, err)
	tokens, err := auth.NewTokenService(repos.Tokens, clk.Now)
	must(t, err)
	fa := &failingAudit{Logger: audit.NewLogger(db.Audit(), nil, clk.Now, quiet)}
	svc, err := New(Config{DB: db, Audit: fa, Hasher: hasher, Sealer: sealer, Tokens: tokens,
		Now: clk.Now, Logger: quiet})
	must(t, err)
	f := &fixture{t: t, db: db, svc: svc, authn: authn, tokens: tokens, clk: clk, audit: fa}
	enr, err := authn.BootstrapAdmin(ctx, "alice", testPassword)
	must(t, err)
	must(t, authn.ConfirmTOTP(ctx, "alice", testPassword, f.code(enr.Secret), "192.0.2.1"))
	u, err := db.Users().ByUsername(ctx, "alice")
	must(t, err)
	f.admin = Actor{UserID: u.ID, Username: "alice", Role: authz.RoleAdmin, IP: "192.0.2.1", Method: "local"}
	return f
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// code returns the current TOTP and moves the clock past its step.
func (f *fixture) code(secret string) string {
	f.t.Helper()
	c, err := totp.GenerateCode(secret, f.clk.Now())
	must(f.t, err)
	f.clk.Advance(31 * time.Second)
	return c
}

// lastAudit returns the newest audit row and its decoded params.
func (f *fixture) lastAudit() (store.AuditRecord, map[string]any) {
	f.t.Helper()
	rec, ok, err := f.db.Audit().Last(context.Background())
	if err != nil || !ok {
		f.t.Fatalf("no audit row: %v", err)
	}
	var p map[string]any
	must(f.t, json.Unmarshal([]byte(rec.ParamsJSON), &p))
	return rec, p
}

func (f *fixture) expectAudit(action, result string) map[string]any {
	f.t.Helper()
	rec, p := f.lastAudit()
	if rec.Action != action || rec.Result != result {
		f.t.Fatalf("last audit = %s/%s, want %s/%s", rec.Action, rec.Result, action, result)
	}
	return p
}

func (f *fixture) auditCount() int64 {
	rec, _, _ := f.db.Audit().Last(context.Background())
	return rec.Seq
}

// noSecretInAudit fails if any audit row contains s.
func (f *fixture) noSecretInAudit(secrets ...string) {
	f.t.Helper()
	rows, err := f.db.Audit().List(context.Background(), 0, store.MaxAuditPage)
	must(f.t, err)
	for _, r := range rows {
		for _, s := range secrets {
			if s != "" && strings.Contains(r.ParamsJSON+r.ErrorClass+r.Principal, s) {
				f.t.Fatalf("audit row %d leaks a secret", r.Seq)
			}
		}
	}
	if _, err := audit.Verify(context.Background(), f.db.Audit(), 0); err != nil {
		f.t.Fatalf("audit chain broken: %v", err)
	}
}

// enrol redeems link with a password and confirms the authenticator, like a new user.
func (f *fixture) enrol(link Link, password string) string {
	f.t.Helper()
	ctx := context.Background()
	enr, user, err := f.svc.RedeemLink(ctx, link.Token, password, "192.0.2.9")
	must(f.t, err)
	must(f.t, f.authn.ConfirmTOTP(ctx, user, password, f.code(enr.Secret), "192.0.2.9"))
	return enr.Secret
}

func (f *fixture) userID(name string) string {
	f.t.Helper()
	u, err := f.db.Users().ByUsername(context.Background(), name)
	must(f.t, err)
	return u.ID
}
