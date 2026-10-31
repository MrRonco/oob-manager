package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestSetRoleGuarded(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mustCreateUser(t, db, "a1", "alice", RoleAdmin)
	mustCreateUser(t, db, "v1", "victor", RoleViewer)
	acc := db.Accounts()

	if err := acc.SetRoleGuarded(ctx, "a1", "a1", RoleViewer); !errors.Is(err, ErrRefused) {
		t.Fatalf("self-demote err = %v", err)
	}
	if err := acc.SetRoleGuarded(ctx, "a1", "v1", RoleOperator); err != nil {
		t.Fatalf("promote viewer: %v", err)
	}
	if err := acc.SetRoleGuarded(ctx, "a1", "nobody", RoleViewer); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user err = %v", err)
	}
	if err := acc.SetRoleGuarded(ctx, "a1", "v1", Role("root")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad role err = %v", err)
	}
	// A second admin may be demoted by the first; the first then becomes the last admin.
	mustCreateUser(t, db, "a2", "bob", RoleAdmin)
	if err := acc.SetRoleGuarded(ctx, "a1", "a2", RoleOperator); err != nil {
		t.Fatalf("demote other admin: %v", err)
	}
	u, _ := db.Users().ByID(ctx, "a2")
	if u.Role != RoleOperator {
		t.Fatalf("role = %s", u.Role)
	}
}

func TestLastEnabledAdminCannotBeDemotedOrDisabled(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mustCreateUser(t, db, "a1", "alice", RoleAdmin)
	mustCreateUser(t, db, "a2", "bob", RoleAdmin)
	acc := db.Accounts()
	// bob is disabled: alice is then the only enabled admin, so nobody (not even
	// bob's session, were it alive) may demote or disable alice.
	if err := acc.SetDisabledGuarded(ctx, "a1", "a2", true); err != nil {
		t.Fatalf("disable bob: %v", err)
	}
	if err := acc.SetRoleGuarded(ctx, "a2", "a1", RoleViewer); !errors.Is(err, ErrRefused) {
		t.Fatalf("demote last admin err = %v", err)
	}
	if err := acc.SetDisabledGuarded(ctx, "a2", "a1", true); !errors.Is(err, ErrRefused) {
		t.Fatalf("disable last admin err = %v", err)
	}
	if err := acc.SetDisabledGuarded(ctx, "a1", "a1", true); !errors.Is(err, ErrRefused) {
		t.Fatalf("self-disable err = %v", err)
	}
	if err := acc.SetDisabledGuarded(ctx, "a1", "a2", false); err != nil {
		t.Fatalf("enable bob: %v", err)
	}
	if err := acc.SetDisabledGuarded(ctx, "a1", "ghost", true); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user err = %v", err)
	}
}

// Two admins demoting each other at the same time: the guard runs inside each UPDATE,
// so exactly one succeeds and an enabled admin always remains.
func TestConcurrentMutualDemotionLeavesOneAdmin(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mustCreateUser(t, db, "a1", "alice", RoleAdmin)
	mustCreateUser(t, db, "a2", "bob", RoleAdmin)
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, pair := range [][2]string{{"a1", "a2"}, {"a2", "a1"}} {
		wg.Go(func() {
			errs[i] = db.WithTx(ctx, func(tx *Tx) error {
				return tx.Accounts().SetRoleGuarded(ctx, pair[0], pair[1], RoleViewer)
			})
		})
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		if err == nil {
			ok++
		} else if !errors.Is(err, ErrRefused) {
			t.Fatalf("unexpected err %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d demotions succeeded, want exactly 1", ok)
	}
	n, err := db.Accounts().EnabledAdmins(ctx)
	if err != nil || n != 1 {
		t.Fatalf("enabled admins = %d, %v", n, err)
	}
}

func TestClearTOTPGuarded(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mustCreateUser(t, db, "a1", "alice", RoleAdmin)
	mustCreateUser(t, db, "v1", "victor", RoleViewer)
	if err := db.Users().SetTOTP(ctx, "v1", []byte("sealed"), true); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Users().AdvanceTOTPStep(ctx, "v1", 99); err != nil {
		t.Fatal(err)
	}
	acc := db.Accounts()
	if err := acc.ClearTOTP(ctx, "a1", "a1"); !errors.Is(err, ErrRefused) {
		t.Fatalf("self reset err = %v", err)
	}
	if err := acc.ClearTOTP(ctx, "a1", "v1"); err != nil {
		t.Fatalf("ClearTOTP: %v", err)
	}
	u, _ := db.Users().ByID(ctx, "v1")
	if u.TOTPSecretEnc != nil || u.TOTPConfirmed || u.TOTPLastStep != 0 {
		t.Fatalf("TOTP not cleared: %+v", u)
	}
	if err := acc.ClearTOTP(ctx, "a1", "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user err = %v", err)
	}
}

func TestSessionsListAndRevokeForUser(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mustCreateUser(t, db, "u1", "alice", RoleAdmin)
	mustCreateUser(t, db, "u2", "bob", RoleViewer)
	s := db.Sessions()
	for i, h := range []string{"h1", "h2"} {
		at := t0.Add(time.Duration(i) * time.Minute)
		if err := s.Create(ctx, Session{IDHash: []byte(h), UserID: "u1", Level: SessionFull, CreatedAt: at,
			LastSeen: at, IP: "192.0.2.1", UA: "ua"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Create(ctx, Session{IDHash: []byte("b1"), UserID: "u2", CreatedAt: t0, LastSeen: t0}); err != nil {
		t.Fatal(err)
	}
	list, err := s.ListForUser(ctx, "u1")
	if err != nil || len(list) != 2 || string(list[0].IDHash) != "h2" {
		t.Fatalf("ListForUser = %+v, %v (want newest first)", list, err)
	}
	if err = s.DeleteOwned(ctx, "u2", []byte("h1")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("revoking another user's session err = %v", err)
	}
	if err = s.DeleteOwned(ctx, "u1", []byte("h1")); err != nil {
		t.Fatalf("DeleteOwned: %v", err)
	}
	counts, err := s.CountByUser(ctx)
	if err != nil || counts["u1"] != 1 || counts["u2"] != 1 {
		t.Fatalf("CountByUser = %v, %v", counts, err)
	}
}
