package auth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

var errStoreDown = errors.New("store down")

// brokenLockouts fails every call: login must be denied, never waved through.
type brokenLockouts struct{ getErr, recErr, resetErr error }

func (b brokenLockouts) Get(context.Context, string) (LockoutState, error) {
	return LockoutState{}, b.getErr
}

func (b brokenLockouts) RecordFailure(context.Context, string, time.Time) (LockoutState, error) {
	return LockoutState{}, b.recErr
}
func (b brokenLockouts) Reset(context.Context, string) error { return b.resetErr }

// brokenSessions fails selected calls.
type brokenSessions struct {
	*fakeSessions
	getErr, createErr, replaceErr, touchErr error
}

func (b brokenSessions) Get(ctx context.Context, h []byte) (Session, error) {
	if b.getErr != nil {
		return Session{}, b.getErr
	}
	return b.fakeSessions.Get(ctx, h)
}

func (b brokenSessions) Create(ctx context.Context, s Session) error {
	if b.createErr != nil {
		return b.createErr
	}
	return b.fakeSessions.Create(ctx, s)
}

func (b brokenSessions) Replace(ctx context.Context, old []byte, s Session) error {
	if b.replaceErr != nil {
		return b.replaceErr
	}
	return b.fakeSessions.Replace(ctx, old, s)
}

func (b brokenSessions) Touch(ctx context.Context, h []byte, at time.Time) error {
	if b.touchErr != nil {
		return b.touchErr
	}
	return b.fakeSessions.Touch(ctx, h, at)
}

func TestLockoutRepoErrorsDeny(t *testing.T) {
	ctx := context.Background()
	h := enrolledHarness(t)
	h.a.locks.repo = brokenLockouts{getErr: errStoreDown}
	if _, err := h.a.BeginLogin(ctx, h.req(testPassword)); !errors.Is(err, errStoreDown) {
		t.Fatalf("lockout Get failure: %v", err)
	}
	h.a.locks.repo = brokenLockouts{recErr: errStoreDown}
	_, err := h.a.BeginLogin(ctx, h.req("wrong-password-x"))
	if !errors.Is(err, ErrInvalidCredentials) || !errors.Is(err, errStoreDown) {
		t.Fatalf("RecordFailure failure: %v", err)
	}
	h.a.locks.repo = brokenLockouts{resetErr: errStoreDown}
	p, err := h.a.BeginLogin(ctx, h.req(testPassword))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.a.CompleteLogin(ctx, p, h.code(), "ip", "ua"); !errors.Is(err, errStoreDown) {
		t.Fatalf("Reset failure must not complete login: %v", err)
	}
}

func TestStaleLockoutResetFailure(t *testing.T) {
	l := lockouts{repo: staleLockouts{brokenLockouts{resetErr: errStoreDown}}, now: time.Now}
	old := lockKey{key: "k", policy: LockoutPolicy{FreeAttempts: 1, ForgetAfter: time.Nanosecond}}
	if err := l.fail(context.Background(), old); !errors.Is(err, errStoreDown) {
		t.Fatalf("fail() = %v", err)
	}
}

type staleLockouts struct{ brokenLockouts }

func (staleLockouts) Get(context.Context, string) (LockoutState, error) {
	return LockoutState{Failures: 3, LastFailure: time.Unix(0, 0)}, nil
}

func TestSessionRepoErrors(t *testing.T) {
	ctx := context.Background()
	h := enrolledHarness(t)
	tok := h.login(t)
	base := h.sessions

	h.a.cfg.Sessions = brokenSessions{fakeSessions: base, getErr: errStoreDown}
	if _, err := h.a.Authenticate(ctx, tok); !errors.Is(err, errStoreDown) {
		t.Fatalf("Get failure: %v", err)
	}
	h.a.cfg.Sessions = brokenSessions{fakeSessions: base, touchErr: errStoreDown}
	if _, err := h.a.Authenticate(ctx, tok); !errors.Is(err, errStoreDown) {
		t.Fatalf("Touch failure: %v", err)
	}
	h.a.cfg.Sessions = brokenSessions{fakeSessions: base, createErr: errStoreDown}
	if _, err := h.a.BeginLogin(ctx, h.req(testPassword)); !errors.Is(err, errStoreDown) {
		t.Fatalf("Create failure: %v", err)
	}
	h.a.cfg.Sessions = brokenSessions{fakeSessions: base, replaceErr: errStoreDown}
	h.clk.Advance(30 * time.Second)
	if _, _, err := h.a.StepUp(ctx, tok, h.code()); !errors.Is(err, errStoreDown) {
		t.Fatalf("Replace failure: %v", err)
	}
}

func TestRotationAfterConcurrentLogout(t *testing.T) {
	ctx := context.Background()
	h := enrolledHarness(t)
	p, _ := h.a.BeginLogin(ctx, h.req(testPassword))
	h.a.cfg.Sessions = brokenSessions{fakeSessions: h.sessions, replaceErr: ErrNotFound}
	if _, _, err := h.a.CompleteLogin(ctx, p, h.code(), "ip", "ua"); !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("rotation of a vanished session: %v", err)
	}
}

func TestConcurrentTOTPReplaySingleWinner(t *testing.T) {
	ctx := context.Background()
	h := enrolledHarness(t)
	const n = 8
	pendings := make([]string, n)
	for i := range n {
		p, err := h.a.BeginLogin(ctx, h.req(testPassword))
		if err != nil {
			t.Fatal(err)
		}
		pendings[i] = p
	}
	code := h.code()
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for _, p := range pendings {
		wg.Go(func() {
			if _, _, err := h.a.CompleteLogin(ctx, p, code, "ip", "ua"); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("one TOTP code completed %d logins, want exactly 1", wins)
	}
}

func TestCorruptTOTPSecretDenies(t *testing.T) {
	ctx := context.Background()
	h := enrolledHarness(t)
	p, _ := h.a.BeginLogin(ctx, h.req(testPassword))
	u, _ := h.users.GetByUsername(ctx, "morgan")
	u.TOTPSecretEnc = []byte("garbage-garbage-garbage-garbage")
	h.users.put(u)
	_, _, err := h.a.CompleteLogin(ctx, p, h.code(), "ip", "ua")
	if err == nil || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("corrupt secret: %v (want an internal error, not a counted failure)", err)
	}
}

func TestBadStoredPasswordHashDenies(t *testing.T) {
	ctx := context.Background()
	h := enrolledHarness(t)
	u, _ := h.users.GetByUsername(ctx, "morgan")
	u.PasswordHash = "not-a-hash"
	h.users.put(u)
	if _, err := h.a.BeginLogin(ctx, h.req(testPassword)); !errors.Is(err, ErrBadHash) {
		t.Fatalf("bad stored hash: %v", err)
	}
}

func TestSessionCookieFor(t *testing.T) {
	h := enrolledHarness(t)
	tok := h.login(t)
	id, _ := h.a.Authenticate(context.Background(), tok)
	h.clk.Advance(time.Hour)
	c := h.a.SessionCookieFor(tok, id.Session)
	if want := int((DefaultSessionMax - time.Hour).Seconds()); c.MaxAge != want {
		t.Fatalf("MaxAge = %d, want %d (remaining absolute lifetime)", c.MaxAge, want)
	}
	h.clk.Advance(DefaultSessionMax)
	if h.a.SessionCookieFor(tok, id.Session).MaxAge != 0 {
		t.Fatal("expired session cookie should have MaxAge 0")
	}
}

func TestLockedOutErrorMessage(t *testing.T) {
	e := &LockedOutError{RetryAfter: 1500 * time.Millisecond}
	if !strings.Contains(e.Error(), "retry after 2s") {
		t.Fatalf("Error() = %q", e.Error())
	}
}

func TestEnrollmentValidation(t *testing.T) {
	if _, err := NewTOTPEnrollment("oob", ""); err == nil {
		t.Fatal("empty account accepted")
	}
}
