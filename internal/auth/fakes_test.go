package auth

import (
	"cmp"
	"context"
	"encoding/hex"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
)

// In-memory fakes of the repository interfaces. Each mirrors the documented contract,
// including the atomic operations, so the store package can reuse these tests' intent.

type fakeUsers struct {
	mu   sync.Mutex
	byID map[string]User
}

func newFakeUsers() *fakeUsers { return &fakeUsers{byID: map[string]User{}} }

func (f *fakeUsers) CreateFirst(_ context.Context, u User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.byID) > 0 {
		return ErrUsersExist
	}
	f.byID[u.ID] = u
	return nil
}

func (f *fakeUsers) GetByUsername(_ context.Context, name string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, u := range f.byID {
		if u.Username == name {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}

func (f *fakeUsers) GetByID(_ context.Context, id string) (User, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return u, nil
}

func (f *fakeUsers) update(id string, fn func(User) User) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return ErrNotFound
	}
	f.byID[id] = fn(u)
	return nil
}

func (f *fakeUsers) SetPasswordHash(_ context.Context, id, hash string) error {
	return f.update(id, func(u User) User { u.PasswordHash = hash; return u })
}

func (f *fakeUsers) SetTOTP(_ context.Context, id string, enc []byte, confirmed bool) error {
	return f.update(id, func(u User) User {
		u.TOTPSecretEnc, u.TOTPConfirmed = enc, confirmed
		return u
	})
}

func (f *fakeUsers) ReEnrollTOTP(_ context.Context, id string, enc []byte) error {
	return f.update(id, func(u User) User {
		u.TOTPSecretEnc, u.TOTPConfirmed, u.TOTPLastStep = enc, false, 0
		return u
	})
}

func (f *fakeUsers) AdvanceTOTPStep(_ context.Context, id string, step int64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	u, ok := f.byID[id]
	if !ok {
		return false, ErrNotFound
	}
	if step <= u.TOTPLastStep {
		return false, nil
	}
	u.TOTPLastStep = step
	f.byID[id] = u
	return true, nil
}

func (f *fakeUsers) put(u User) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.byID[u.ID] = u
}

type fakeSessions struct {
	mu sync.Mutex
	m  map[string]Session
	// failDeleteForUser, when set, is returned by DeleteForUser.
	failDeleteForUser error
}

func newFakeSessions() *fakeSessions { return &fakeSessions{m: map[string]Session{}} }

func key(h []byte) string { return hex.EncodeToString(h) }

func (f *fakeSessions) Create(_ context.Context, s Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[key(s.IDHash)] = s
	return nil
}

func (f *fakeSessions) Get(_ context.Context, h []byte) (Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.m[key(h)]
	if !ok {
		return Session{}, ErrNotFound
	}
	return s, nil
}

func (f *fakeSessions) Touch(_ context.Context, h []byte, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.m[key(h)]
	if !ok {
		return ErrNotFound
	}
	s.LastSeen = at
	f.m[key(h)] = s
	return nil
}

func (f *fakeSessions) Replace(_ context.Context, old []byte, s Session) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.m[key(old)]; !ok {
		return ErrNotFound
	}
	delete(f.m, key(old))
	f.m[key(s.IDHash)] = s
	return nil
}

func (f *fakeSessions) Delete(_ context.Context, h []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, key(h))
	return nil
}

func (f *fakeSessions) DeleteForUser(_ context.Context, userID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failDeleteForUser != nil {
		return f.failDeleteForUser
	}
	for k, s := range f.m {
		if s.UserID == userID {
			delete(f.m, k)
		}
	}
	return nil
}

func (f *fakeSessions) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.m)
}

type fakeLockouts struct {
	mu sync.Mutex
	m  map[string]LockoutState
}

func newFakeLockouts() *fakeLockouts { return &fakeLockouts{m: map[string]LockoutState{}} }

func (f *fakeLockouts) Get(_ context.Context, k string) (LockoutState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.m[k], nil
}

func (f *fakeLockouts) RecordFailure(_ context.Context, k string, at time.Time) (LockoutState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := LockoutState{Failures: f.m[k].Failures + 1, LastFailure: at}
	f.m[k] = s
	return s, nil
}

func (f *fakeLockouts) Reset(_ context.Context, k string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.m, k)
	return nil
}

type fakeTokens struct {
	mu sync.Mutex
	m  map[string]APIToken
}

func newFakeTokens() *fakeTokens { return &fakeTokens{m: map[string]APIToken{}} }

func (f *fakeTokens) Create(_ context.Context, t APIToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.m[t.ID] = t
	return nil
}

func (f *fakeTokens) GetByHash(_ context.Context, h []byte) (APIToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.m {
		if key(t.Hash) == key(h) {
			return t, nil
		}
	}
	return APIToken{}, ErrNotFound
}

func (f *fakeTokens) List(_ context.Context) ([]APIToken, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]APIToken, 0, len(f.m))
	for _, t := range f.m {
		out = append(out, t)
	}
	slices.SortFunc(out, func(a, b APIToken) int { return cmp.Or(a.CreatedAt.Compare(b.CreatedAt), strings.Compare(a.ID, b.ID)) })
	return out, nil
}

func (f *fakeTokens) MarkUsed(_ context.Context, id string, at time.Time) error {
	return f.set(id, func(t APIToken) APIToken { t.LastUsedAt = at; return t })
}

func (f *fakeTokens) Revoke(_ context.Context, id string, at time.Time) error {
	return f.set(id, func(t APIToken) APIToken { t.RevokedAt = at; return t })
}

func (f *fakeTokens) set(id string, fn func(APIToken) APIToken) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	t, ok := f.m[id]
	if !ok {
		return ErrNotFound
	}
	f.m[id] = fn(t)
	return nil
}

// fakeClock is a settable clock for deterministic expiry tests.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// codeFor is what an authenticator app would display at time at.
func codeFor(secret string, at time.Time) (string, error) {
	return totp.GenerateCodeCustom(secret, at, totpValidateOpts())
}
