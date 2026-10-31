package auth

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/authz"
)

const testPassword = "correct horse battery staple"

type harness struct {
	a        *Authenticator
	users    *fakeUsers
	sessions *fakeSessions
	locks    *fakeLockouts
	clk      *fakeClock
	logs     *bytes.Buffer
	secret   string // admin's TOTP secret
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{users: newFakeUsers(), sessions: newFakeSessions(), locks: newFakeLockouts(),
		clk: newFakeClock(), logs: &bytes.Buffer{}}
	sealer, _ := NewAESGCMSealer(bytes.Repeat([]byte{1}, 32))
	a, err := New(Config{
		Users: h.users, Sessions: h.sessions, Lockouts: h.locks,
		Hasher: newTestHasher(t), Sealer: sealer, Now: h.clk.Now,
		Logger: slog.New(slog.NewTextHandler(h.logs, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	h.a = a
	return h
}

// enrolledHarness bootstraps "morgan" and confirms TOTP, as the CLI will.
func enrolledHarness(t *testing.T) *harness {
	t.Helper()
	h := newHarness(t)
	ctx := context.Background()
	e, err := h.a.BootstrapAdmin(ctx, "morgan", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	h.secret = e.Secret
	if err := h.a.ConfirmTOTP(ctx, "morgan", testPassword, h.code(), "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	h.clk.Advance(30 * time.Second) // move past the step consumed by confirmation
	return h
}

func (h *harness) code() string {
	c, err := codeFor(h.secret, h.clk.Now())
	if err != nil {
		panic(err)
	}
	return c
}

func (h *harness) req(pw string) LoginRequest {
	return LoginRequest{Username: "morgan", Password: pw, IP: "192.0.2.100", UserAgent: "test"}
}

// login performs both stages and returns the full session token.
func (h *harness) login(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	pending, err := h.a.BeginLogin(ctx, h.req(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := h.a.CompleteLogin(ctx, pending, h.code(), "192.0.2.100", "test")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestFullLoginFlow(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	pending, err := h.a.BeginLogin(ctx, h.req(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = h.a.Authenticate(ctx, pending); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("pending session usable before TOTP: %v", err)
	}
	tok, sess, err := h.a.CompleteLogin(ctx, pending, h.code(), "192.0.2.100", "test")
	if err != nil {
		t.Fatal(err)
	}
	if tok == pending {
		t.Fatal("session ID not rotated on login")
	}
	if _, err = h.a.Authenticate(ctx, pending); !errors.Is(err, ErrSessionInvalid) {
		t.Fatal("pre-login session ID still valid after rotation")
	}
	id, err := h.a.Authenticate(ctx, tok)
	if err != nil {
		t.Fatal(err)
	}
	if id.User.Username != "morgan" || id.Principal() != (authz.Principal{Kind: authz.KindSession, Role: authz.RoleAdmin}) {
		t.Fatalf("identity = %+v", id)
	}
	if !h.a.StepUpFresh(sess) {
		t.Fatal("TOTP at login should count as a fresh step-up")
	}
	if h.sessions.count() != 1 {
		t.Fatalf("sessions = %d, want 1", h.sessions.count())
	}
}

func TestNoSecretsInLogs(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	_, _ = h.a.BeginLogin(ctx, h.req("wrong password value"))
	tok := h.login(t)
	logs := h.logs.String()
	for _, s := range []string{testPassword, "wrong password value", h.secret, tok, h.code()} {
		if strings.Contains(logs, s) {
			t.Fatalf("log contains secret %q:\n%s", s, logs)
		}
	}
}

func TestBeginLoginGenericErrors(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	cases := []LoginRequest{
		{Username: "morgan", Password: "wrong-password-1", IP: "192.0.2.201"},
		{Username: "nobody", Password: testPassword, IP: "192.0.2.202"},
		{Username: "", Password: testPassword, IP: "192.0.2.203"},
		{Username: strings.Repeat("a", 65), Password: testPassword, IP: "192.0.2.204"},
		{Username: "morgan", Password: strings.Repeat("a", MaxPasswordLen+1), IP: "192.0.2.205"},
	}
	for _, r := range cases {
		if _, err := h.a.BeginLogin(ctx, r); !errors.Is(err, ErrInvalidCredentials) {
			t.Errorf("BeginLogin(%q) err = %v, want ErrInvalidCredentials", r.Username, err)
		}
	}
}

func TestDisabledAndUnconfirmedUsersCannotLogin(t *testing.T) {
	h := enrolledHarness(t)
	u, _ := h.users.GetByUsername(context.Background(), "morgan")
	u.Disabled = true
	h.users.put(u)
	if _, err := h.a.BeginLogin(context.Background(), h.req(testPassword)); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("disabled user: %v", err)
	}

	h2 := newHarness(t)
	if _, err := h2.a.BootstrapAdmin(context.Background(), "morgan", testPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := h2.a.BeginLogin(context.Background(), h2.req(testPassword)); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unconfirmed TOTP user: %v", err)
	}
}

func TestBruteForceLockout(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	free := DefaultAccountLockout().FreeAttempts
	for i := range free {
		if _, err := h.a.BeginLogin(ctx, h.req("wrong-password-x")); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// Now locked: even the right password is refused, without revealing that it was right.
	_, err := h.a.BeginLogin(ctx, h.req(testPassword))
	var lo *LockedOutError
	if !errors.As(err, &lo) || !errors.Is(err, ErrLockedOut) || lo.RetryAfter <= 0 {
		t.Fatalf("expected lockout, got %v", err)
	}
	// Same account from another IP is still locked (per-account key).
	r := h.req(testPassword)
	r.IP = "192.0.2.200"
	if _, err := h.a.BeginLogin(ctx, r); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("account lockout bypassed from new IP: %v", err)
	}
	h.clk.Advance(lo.RetryAfter + time.Second)
	if _, err := h.a.BeginLogin(ctx, h.req(testPassword)); err != nil {
		t.Fatalf("after backoff: %v", err)
	}
}

func TestIPLockoutAcrossUsernames(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	free := DefaultIPLockout().FreeAttempts
	for i := range free {
		r := LoginRequest{Username: "user" + string(rune('a'+i)), Password: "wrong-password-x", IP: "198.51.100.9"}
		_, _ = h.a.BeginLogin(ctx, r)
	}
	r := h.req(testPassword)
	r.IP = "198.51.100.9"
	if _, err := h.a.BeginLogin(ctx, r); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("IP spraying not locked out: %v", err)
	}
}

func TestLockoutForgottenAfterWindow(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	for range DefaultAccountLockout().FreeAttempts - 1 {
		_, _ = h.a.BeginLogin(ctx, h.req("wrong-password-x"))
	}
	h.clk.Advance(DefaultAccountLockout().ForgetAfter + time.Minute)
	for range DefaultAccountLockout().FreeAttempts - 1 {
		_, _ = h.a.BeginLogin(ctx, h.req("wrong-password-x"))
	}
	if _, err := h.a.BeginLogin(ctx, h.req(testPassword)); err != nil {
		t.Fatalf("stale failures were not forgotten: %v", err)
	}
}

func TestTOTPReplayRejected(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	code := h.code()
	p1, _ := h.a.BeginLogin(ctx, h.req(testPassword))
	if _, _, err := h.a.CompleteLogin(ctx, p1, code, "ip", "ua"); err != nil {
		t.Fatal(err)
	}
	p2, _ := h.a.BeginLogin(ctx, h.req(testPassword))
	if _, _, err := h.a.CompleteLogin(ctx, p2, code, "ip", "ua"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("replayed TOTP accepted: %v", err)
	}
}

func TestCompleteLoginRejects(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	full := h.login(t)
	h.clk.Advance(30 * time.Second)
	if _, _, err := h.a.CompleteLogin(ctx, full, h.code(), "ip", "ua"); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("full session reused as pending: %v", err)
	}
	if _, _, err := h.a.CompleteLogin(ctx, "garbage", h.code(), "ip", "ua"); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("garbage pending token: %v", err)
	}
	p, _ := h.a.BeginLogin(ctx, h.req(testPassword))
	if _, _, err := h.a.CompleteLogin(ctx, p, "000000", "ip", "ua"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong code: %v", err)
	}
	h.clk.Advance(DefaultPendingTTL + time.Second)
	if _, _, err := h.a.CompleteLogin(ctx, p, h.code(), "ip", "ua"); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("expired pending session: %v", err)
	}
}

func TestTOTPBruteForceLocksAccount(t *testing.T) {
	h := enrolledHarness(t)
	ctx := context.Background()
	p, _ := h.a.BeginLogin(ctx, h.req(testPassword))
	for range DefaultAccountLockout().FreeAttempts {
		_, _, _ = h.a.CompleteLogin(ctx, p, "000000", "ip", "ua")
	}
	if _, _, err := h.a.CompleteLogin(ctx, p, h.code(), "ip", "ua"); !errors.Is(err, ErrLockedOut) {
		t.Fatalf("TOTP guessing not locked out: %v", err)
	}
}

func TestBootstrapAdmin(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, err := h.a.BootstrapAdmin(ctx, "morgan", "short"); err == nil {
		t.Fatal("weak password accepted")
	}
	if _, err := h.a.BootstrapAdmin(ctx, "bad user!", testPassword); err == nil {
		t.Fatal("bad username accepted")
	}
	e, err := h.a.BootstrapAdmin(ctx, "morgan", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := h.users.GetByUsername(ctx, "morgan")
	if u.Role != authz.RoleAdmin || u.TOTPConfirmed || len(u.ID) != 32 {
		t.Fatalf("bootstrap user = %+v", u)
	}
	if bytes.Contains(u.TOTPSecretEnc, []byte(e.Secret)) || strings.Contains(u.PasswordHash, testPassword) {
		t.Fatal("secret stored in clear")
	}
	if _, err := h.a.BootstrapAdmin(ctx, "second", testPassword); !errors.Is(err, ErrUsersExist) {
		t.Fatalf("second bootstrap: %v", err)
	}
}

func TestConfirmTOTP(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	e, _ := h.a.BootstrapAdmin(ctx, "morgan", testPassword)
	h.secret = e.Secret
	if err := h.a.ConfirmTOTP(ctx, "morgan", "wrong-password-x", h.code(), "ip"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if err := h.a.ConfirmTOTP(ctx, "morgan", testPassword, "000000", "ip"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong code: %v", err)
	}
	if err := h.a.ConfirmTOTP(ctx, "morgan", testPassword, h.code(), "ip"); err != nil {
		t.Fatal(err)
	}
	u, _ := h.users.GetByUsername(ctx, "morgan")
	if !u.TOTPConfirmed {
		t.Fatal("not confirmed")
	}
}

func TestRehashOnLogin(t *testing.T) {
	h := enrolledHarness(t)
	u, _ := h.users.GetByUsername(context.Background(), "morgan")
	p := testParams()
	p.Time = 2
	stronger, _ := NewPasswordHasher(p, 1)
	h.a.hasher = stronger
	h.login(t)
	u2, _ := h.users.GetByUsername(context.Background(), "morgan")
	if u2.PasswordHash == u.PasswordHash || !strings.Contains(u2.PasswordHash, "t=2") {
		t.Fatal("password not rehashed with new params")
	}
}

func TestNewValidatesConfig(t *testing.T) {
	h := newHarness(t)
	good := Config{Users: h.users, Sessions: h.sessions, Lockouts: h.locks,
		Hasher: newTestHasher(t), Sealer: h.a.sealer}
	mutate := []func(Config) Config{
		func(c Config) Config { c.Users = nil; return c },
		func(c Config) Config { c.Sessions = nil; return c },
		func(c Config) Config { c.Lockouts = nil; return c },
		func(c Config) Config { c.Hasher = nil; return c },
		func(c Config) Config { c.Sealer = nil; return c },
		func(c Config) Config { c.SessionIdle = time.Hour; c.SessionMax = time.Minute; return c },
	}
	for i, m := range mutate {
		if _, err := New(m(good)); err == nil {
			t.Errorf("config %d accepted", i)
		}
	}
	a, err := New(good)
	if err != nil || a.cfg.SessionIdle != DefaultSessionIdle || a.cfg.Issuer != DefaultIssuer {
		t.Fatalf("defaults not applied: %v", err)
	}
}
