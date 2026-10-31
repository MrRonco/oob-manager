package ui

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/bmc"
	"oob-manager/internal/store"
)

// clock is a settable test clock shared by auth and ui.
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

// In-memory auth repositories honouring the auth/repo.go contracts.

type memUsers struct {
	mu   sync.Mutex
	byID map[string]auth.User
}

func (m *memUsers) CreateFirst(_ context.Context, u auth.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.byID) > 0 {
		return auth.ErrUsersExist
	}
	m.byID[u.ID] = u
	return nil
}

func (m *memUsers) GetByUsername(_ context.Context, name string) (auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.byID {
		if u.Username == name {
			return u, nil
		}
	}
	return auth.User{}, auth.ErrNotFound
}

func (m *memUsers) GetByID(_ context.Context, id string) (auth.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return auth.User{}, auth.ErrNotFound
	}
	return u, nil
}

func (m *memUsers) SetPasswordHash(_ context.Context, id, hash string) error {
	return m.update(id, func(u auth.User) auth.User { u.PasswordHash = hash; return u })
}

func (m *memUsers) SetTOTP(_ context.Context, id string, enc []byte, confirmed bool) error {
	return m.update(id, func(u auth.User) auth.User { u.TOTPSecretEnc, u.TOTPConfirmed = enc, confirmed; return u })
}

func (m *memUsers) ReEnrollTOTP(_ context.Context, id string, enc []byte) error {
	return m.update(id, func(u auth.User) auth.User {
		u.TOTPSecretEnc, u.TOTPConfirmed, u.TOTPLastStep = enc, false, 0
		return u
	})
}

func (m *memUsers) AdvanceTOTPStep(_ context.Context, id string, step int64) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return false, auth.ErrNotFound
	}
	if step <= u.TOTPLastStep {
		return false, nil
	}
	u.TOTPLastStep = step
	m.byID[id] = u
	return true, nil
}

func (m *memUsers) update(id string, fn func(auth.User) auth.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.byID[id]
	if !ok {
		return auth.ErrNotFound
	}
	m.byID[id] = fn(u)
	return nil
}

func (m *memUsers) put(u auth.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byID[u.ID] = u
}

type memSessions struct {
	mu sync.Mutex
	m  map[string]auth.Session
}

func hk(h []byte) string { return hex.EncodeToString(h) }

func (m *memSessions) Create(_ context.Context, s auth.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.m[hk(s.IDHash)] = s
	return nil
}

func (m *memSessions) Get(_ context.Context, h []byte) (auth.Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.m[hk(h)]
	if !ok {
		return auth.Session{}, auth.ErrNotFound
	}
	return s, nil
}

func (m *memSessions) Touch(_ context.Context, h []byte, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.m[hk(h)]
	if !ok {
		return auth.ErrNotFound
	}
	s.LastSeen = at
	m.m[hk(h)] = s
	return nil
}

func (m *memSessions) Replace(_ context.Context, old []byte, s auth.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.m[hk(old)]; !ok {
		return auth.ErrNotFound
	}
	delete(m.m, hk(old))
	m.m[hk(s.IDHash)] = s
	return nil
}

func (m *memSessions) Delete(_ context.Context, h []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, hk(h))
	return nil
}

func (m *memSessions) DeleteForUser(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, s := range m.m {
		if s.UserID == id {
			delete(m.m, k)
		}
	}
	return nil
}

func (m *memSessions) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.m)
}

type memLockouts struct {
	mu sync.Mutex
	m  map[string]auth.LockoutState
}

func (m *memLockouts) Get(_ context.Context, k string) (auth.LockoutState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.m[k], nil
}

func (m *memLockouts) RecordFailure(_ context.Context, k string, at time.Time) (auth.LockoutState, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := auth.LockoutState{Failures: m.m[k].Failures + 1, LastFailure: at}
	m.m[k] = s
	return s, nil
}

func (m *memLockouts) Reset(_ context.Context, k string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.m, k)
	return nil
}

// fakeFleet serves fixed views and logs.
type fakeFleet struct {
	servers []ServerView
	logs    map[string]bmc.EventLog // key id/kind
	logErr  error
}

func (f *fakeFleet) Servers() []ServerView { return append([]ServerView(nil), f.servers...) }

func (f *fakeFleet) Server(id string) (ServerView, bool) {
	for _, s := range f.servers {
		if s.ID == id {
			return s, true
		}
	}
	return ServerView{}, false
}

func (f *fakeFleet) Events(_ context.Context, id string, kind LogKind) (bmc.EventLog, error) {
	if f.logErr != nil {
		return bmc.EventLog{}, f.logErr
	}
	l, ok := f.logs[id+"/"+string(kind)]
	if !ok {
		return bmc.EventLog{}, ErrLogUnavailable
	}
	return l, nil
}

// fakeAudit captures entries; fail makes Record return an error.
type fakeAudit struct {
	mu      sync.Mutex
	entries []audit.Entry
	fail    bool
}

func (f *fakeAudit) Record(_ context.Context, e audit.Entry) (store.AuditRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return store.AuditRecord{}, errors.New("audit store down")
	}
	f.entries = append(f.entries, e)
	return store.AuditRecord{Seq: int64(len(f.entries))}, nil
}

func (f *fakeAudit) find(action, result string) (audit.Entry, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.entries {
		if e.Action == action && e.Result == result {
			return e, true
		}
	}
	return audit.Entry{}, false
}

func (f *fakeAudit) setFail(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = v
}

// fakeEnroller returns a fixed enrollment for one username/password.
type fakeEnroller struct {
	user, pass string
	enr        auth.TOTPEnrollment
}

func (f fakeEnroller) RevealEnrollment(_ context.Context, u, p, _ string) (auth.TOTPEnrollment, error) {
	if u != f.user || p != f.pass {
		return auth.TOTPEnrollment{}, auth.ErrInvalidCredentials
	}
	return f.enr, nil
}
