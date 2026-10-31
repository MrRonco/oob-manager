package admin

import (
	"context"
	"errors"
	"testing"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
)

// TestRecoverAdmin: the break-glass path (settings_design.md §2, plan 06 drill 8)
// re-enables the account, makes it an admin, clears its login lockout and ends its
// sessions, in one transaction with its audit row.
func TestRecoverAdmin(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	link, err := f.svc.CreateUser(ctx, f.admin, "victor", authz.RoleViewer)
	must(t, err)
	secret := f.enrol(link, "victor's long password")
	vid := f.userID("victor")
	pending, err := f.authn.BeginLogin(ctx, auth.LoginRequest{Username: "victor", Password: "victor's long password", IP: "192.0.2.5"})
	must(t, err)
	_, _, err = f.authn.CompleteLogin(ctx, pending, f.code(secret), "192.0.2.5", "ua")
	must(t, err)
	must(t, f.svc.SetDisabled(ctx, f.admin, vid, true))
	for range 12 { // lock the account out with bad passwords
		_, _ = f.authn.BeginLogin(ctx, auth.LoginRequest{Username: "victor", Password: "wrong one", IP: "192.0.2.5"})
	}

	if st, _ := f.db.Lockouts().Get(ctx, "acct:victor"); st.Failures == 0 {
		t.Fatal("setup: no lockout recorded")
	}
	cli := Actor{Username: "cli", Method: "system"}
	must(t, f.svc.RecoverAdmin(ctx, cli, "victor", "root (uid 0)"))
	p := f.expectAudit("admin.recover", "ok")
	if p["target"] != "victor" || p["before_role"] != "viewer" || p["was_disabled"] != true || p["os_user"] != "root (uid 0)" {
		t.Fatalf("params = %v", p)
	}
	u, _ := f.svc.User(ctx, vid)
	if u.Disabled || u.Role != authz.RoleAdmin {
		t.Fatalf("after recover: disabled=%v role=%s", u.Disabled, u.Role)
	}
	if s, _ := f.svc.Sessions(ctx, vid); len(s) != 0 {
		t.Fatal("recover left sessions behind")
	}
	if st, _ := f.db.Lockouts().Get(ctx, "acct:victor"); st.Failures != 0 {
		t.Fatalf("lockout not cleared: %+v", st)
	}
	if _, err := f.authn.BeginLogin(ctx, auth.LoginRequest{Username: "victor", Password: "victor's long password",
		IP: "192.0.2.6"}); err != nil {
		t.Fatalf("login after recover (lockout should be cleared): %v", err)
	}
	if err := f.svc.RecoverAdmin(ctx, cli, "nobody", ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown user: %v", err)
	}
}
