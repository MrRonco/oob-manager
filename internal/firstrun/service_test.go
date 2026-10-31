package firstrun

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"oob-manager/internal/auth"
)

const testPW = "a long enough password"

type fakeUsers struct {
	mu    sync.Mutex
	n     int
	calls atomic.Int32
	fail  error
}

func (f *fakeUsers) count(context.Context) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n, nil
}

// bootstrap behaves like CreateFirst: only the first insert wins.
func (f *fakeUsers) bootstrap(_ context.Context, user, _ string) (auth.TOTPEnrollment, error) {
	f.calls.Add(1)
	if f.fail != nil {
		return auth.TOTPEnrollment{}, f.fail
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.n > 0 {
		return auth.TOTPEnrollment{}, auth.ErrUsersExist
	}
	f.n++
	return auth.TOTPEnrollment{Secret: "SECRET", URL: "otpauth://totp/x:" + user}, nil
}

func newService(t *testing.T, u *fakeUsers) (*Service, string) {
	t.Helper()
	setup, code, err := NewSetup(time.Now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &Service{Setup: setup, Users: u.count, Bootstrap: u.bootstrap}, code
}

func TestClaimCreatesTheFirstAdminOnce(t *testing.T) {
	u := &fakeUsers{}
	s, code := newService(t, u)
	ctx := context.Background()
	if !s.SetupOpen(ctx) {
		t.Fatal("setup closed on a fresh install")
	}
	if _, err := s.Claim(ctx, "AAAA-BBBB", "owner", testPW); !errors.Is(err, ErrSetupCode) {
		t.Fatalf("wrong code: %v", err)
	}
	if _, err := s.Claim(ctx, code, "Owner!", testPW); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad username: %v", err)
	}
	if _, err := s.Claim(ctx, code, "owner", "short"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("short password: %v", err)
	}
	enr, err := s.Claim(ctx, code, "owner", testPW)
	if err != nil || enr.Secret == "" {
		t.Fatalf("Claim = %+v, %v", enr, err)
	}
	if s.SetupOpen(ctx) {
		t.Error("setup still open after the admin was created")
	}
	if _, err := s.Claim(ctx, code, "second", testPW); !errors.Is(err, ErrSetupClosed) {
		t.Fatalf("second claim: %v", err)
	}
}

func TestConcurrentClaimsMakeOneAdmin(t *testing.T) {
	u := &fakeUsers{}
	s, code := newService(t, u)
	var wg sync.WaitGroup
	var ok atomic.Int32
	for range 16 {
		wg.Go(func() {
			if _, err := s.Claim(context.Background(), code, "owner", testPW); err == nil {
				ok.Add(1)
			}
		})
	}
	wg.Wait()
	if ok.Load() != 1 || u.n != 1 {
		t.Fatalf("%d claims succeeded, %d users created; want 1 and 1", ok.Load(), u.n)
	}
}

func TestClaimFailureKeepsTheCode(t *testing.T) {
	u := &fakeUsers{fail: errors.New("disk full")}
	s, code := newService(t, u)
	if _, err := s.Claim(context.Background(), code, "owner", testPW); err == nil {
		t.Fatal("expected the bootstrap error")
	}
	u.fail = nil
	if _, err := s.Claim(context.Background(), code, "owner", testPW); err != nil {
		t.Fatalf("retry after a failed creation: %v", err)
	}
}

// A panic while the first admin is created (a bug, recovered by the HTTP middleware)
// must not leave the code claimed: the administrator can try again without a restart.
func TestClaimPanicReleasesTheCode(t *testing.T) {
	u := &fakeUsers{}
	s, code := newService(t, u)
	good := s.Bootstrap
	s.Bootstrap = func(context.Context, string, string) (auth.TOTPEnrollment, error) { panic("boom") }
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("the panic did not propagate")
			}
		}()
		_, _ = s.Claim(context.Background(), code, "owner", testPW)
	}()
	s.Bootstrap = good
	if _, err := s.Claim(context.Background(), code, "owner", testPW); err != nil {
		t.Fatalf("claim after a recovered panic: %v (the code stayed claimed)", err)
	}
}

func TestSetupClosedWhenAccountsExist(t *testing.T) {
	u := &fakeUsers{n: 1}
	s, code := newService(t, u)
	if s.SetupOpen(context.Background()) {
		t.Fatal("setup open with an existing account")
	}
	if _, err := s.Claim(context.Background(), code, "owner", testPW); !errors.Is(err, ErrSetupClosed) {
		t.Fatalf("claim: %v", err)
	}
	if u.calls.Load() != 0 {
		t.Error("bootstrap called although an account exists")
	}
	var nilSvc *Service
	if nilSvc.SetupOpen(context.Background()) {
		t.Error("nil service open")
	}
	if _, ok := nilSvc.BackupPending(); ok {
		t.Error("nil service has a pending notice")
	}
}

func TestServiceBackupNotice(t *testing.T) {
	data := t.TempDir()
	if _, err := EnsureKeys(data, fresh(true)); err != nil {
		t.Fatal(err)
	}
	n := NewNotice(data)
	s := &Service{Notice: &n}
	path, ok := s.BackupPending()
	if !ok || path != KeyPathsIn(data).Identity {
		t.Fatalf("BackupPending = %q, %v", path, ok)
	}
	if err := s.DismissBackup(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.BackupPending(); ok {
		t.Error("still pending")
	}
}
