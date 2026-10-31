package store

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestCreateFirstUserIsAtomic(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	users := db.Users()
	var wg sync.WaitGroup
	errs := make([]error, 8)
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u := testUser(fmt.Sprintf("u%d", i), fmt.Sprintf("admin%d", i))
			u.Email = ""
			errs[i] = users.CreateFirst(ctx, u)
		}()
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrConflict):
			t.Fatalf("unexpected error %v", err)
		}
	}
	if n, _ := users.Count(ctx); ok != 1 || n != 1 {
		t.Fatalf("created %d users (%d ok); want exactly one", n, ok)
	}
}

func TestCreateFirstValidates(t *testing.T) {
	db := newTestDB(t)
	bad := testUser("", "x")
	if err := db.Users().CreateFirst(context.Background(), bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	bad = testUser("u1", "x")
	bad.Role = "root"
	if err := db.Users().CreateFirst(context.Background(), bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestSetTOTPKeepsLastStepAndConfirms(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	users := db.Users()
	if err := users.Create(ctx, testUser("u1", "morgan")); err != nil {
		t.Fatal(err)
	}
	if ok, err := users.AdvanceTOTPStep(ctx, "u1", 100); !ok || err != nil {
		t.Fatalf("advance %v %v", ok, err)
	}
	if err := users.SetTOTP(ctx, "u1", []byte("sealed"), true); err != nil {
		t.Fatal(err)
	}
	u, err := users.ByID(ctx, "u1")
	if err != nil || !u.TOTPConfirmed || string(u.TOTPSecretEnc) != "sealed" || u.TOTPLastStep != 100 {
		t.Fatalf("user %+v err %v", u, err)
	}
	if ok, _ := users.AdvanceTOTPStep(ctx, "u1", 100); ok {
		t.Fatal("step 100 must stay consumed after SetTOTP")
	}
	if err := users.SetTOTP(ctx, "ghost", nil, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user: %v", err)
	}
}

func TestSessionLevelAndReplace(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := db.Users().Create(ctx, testUser("u1", "morgan")); err != nil {
		t.Fatal(err)
	}
	sessions := db.Sessions()
	pending := Session{IDHash: []byte("old"), UserID: "u1", CreatedAt: t0, LastSeen: t0}
	if err := sessions.Create(ctx, pending); err != nil {
		t.Fatal(err)
	}
	got, _ := sessions.Get(ctx, []byte("old"))
	if got.Level != SessionPending {
		t.Fatalf("zero level must be stored as pending, got %d", got.Level)
	}
	full := Session{IDHash: []byte("new"), UserID: "u1", Level: SessionFull, CreatedAt: t0,
		LastSeen: t0.Add(time.Minute), StepUpAt: t0.Add(time.Minute)}
	if err := sessions.Replace(ctx, []byte("old"), full); err != nil {
		t.Fatal(err)
	}
	if _, err := sessions.Get(ctx, []byte("old")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old session survived: %v", err)
	}
	got, err := sessions.Get(ctx, []byte("new"))
	if err != nil || got.Level != SessionFull || !got.StepUpAt.Equal(full.StepUpAt) {
		t.Fatalf("new session %+v err %v", got, err)
	}
	// Replacing a session that no longer exists must not insert the new one.
	ghost := full
	ghost.IDHash = []byte("ghost")
	if err := sessions.Replace(ctx, []byte("old"), ghost); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replace of missing session: %v", err)
	}
	if _, err := sessions.Get(ctx, []byte("ghost")); !errors.Is(err, ErrNotFound) {
		t.Fatal("rotation resurrected a deleted session")
	}
	bad := full
	bad.IDHash, bad.Level = []byte("bad"), 7
	if err := sessions.Replace(ctx, []byte("new"), bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad level: %v", err)
	}
	if _, err := sessions.Get(ctx, []byte("new")); err != nil {
		t.Fatalf("failed replace must roll back the delete: %v", err)
	}
}

func TestLockouts(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	locks := db.Lockouts()
	if st, err := locks.Get(ctx, "acct:morgan"); err != nil || st.Failures != 0 || !st.LastFailure.IsZero() {
		t.Fatalf("absent key: %+v %v", st, err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := locks.RecordFailure(ctx, "acct:morgan", t0); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	st, err := locks.RecordFailure(ctx, "acct:morgan", t0.Add(time.Second))
	if err != nil || st.Failures != 11 || !st.LastFailure.Equal(t0.Add(time.Second)) {
		t.Fatalf("after 11 failures: %+v %v", st, err)
	}
	if got, _ := locks.Get(ctx, "acct:morgan"); got != st {
		t.Fatalf("get %+v want %+v", got, st)
	}
	if _, err = locks.RecordFailure(ctx, "ip:192.0.2.100", t0.Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	n, err := locks.Prune(ctx, t0.Add(-24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("prune %d %v", n, err)
	}
	if err := locks.Reset(ctx, "acct:morgan"); err != nil {
		t.Fatal(err)
	}
	if err := locks.Reset(ctx, "acct:morgan"); err != nil {
		t.Fatalf("reset of absent key must be a no-op: %v", err)
	}
	if st, _ := locks.Get(ctx, "acct:morgan"); st.Failures != 0 {
		t.Fatalf("after reset %+v", st)
	}
	if _, err := locks.RecordFailure(ctx, "", t0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty key: %v", err)
	}
}
