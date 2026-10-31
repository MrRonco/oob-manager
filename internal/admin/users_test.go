package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/store"
)

func TestCreateUserIssuesOneTimeLinkAndAudits(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	link, err := f.svc.CreateUser(ctx, f.admin, "victor", authz.RoleViewer)
	must(t, err)
	if link.Username != "victor" || link.Purpose != store.EnrolPurposeEnrol ||
		!link.ExpiresAt.Equal(f.clk.Now().Add(DefaultLinkTTL)) || len(link.Token) != 43 {
		t.Fatalf("link = %+v", link)
	}
	p := f.expectAudit("admin.user.create", "ok")
	if p["target"] != "victor" || p["role"] != "viewer" {
		t.Fatalf("params = %v", p)
	}
	f.noSecretInAudit(link.Token)
	rows, err := f.svc.Users(ctx)
	must(t, err)
	if len(rows) != 2 || rows[1].Username != "victor" || rows[1].Enrolled || rows[1].PendingLink.IsZero() {
		t.Fatalf("users = %+v", rows)
	}
	// The placeholder password can never be used: the account has no authenticator.
	if _, err := f.authn.BeginLogin(ctx, auth.LoginRequest{Username: "victor", Password: testPassword,
		IP: "192.0.2.5"}); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("login before enrolment: %v", err)
	}
}

func TestCreateUserValidation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.svc.CreateUser(ctx, f.admin, "Bad Name", authz.RoleViewer); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad name err = %v", err)
	}
	if _, err := f.svc.CreateUser(ctx, f.admin, "victor", authz.Role("root")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad role err = %v", err)
	}
	if _, err := f.svc.CreateUser(ctx, f.admin, "alice", authz.RoleViewer); !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("duplicate err = %v", err)
	}
}

func TestChangeIsRolledBackWhenAuditFails(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	before := f.auditCount()
	f.audit.fail = true
	if _, err := f.svc.CreateUser(ctx, f.admin, "victor", authz.RoleViewer); err == nil {
		t.Fatal("create succeeded without its audit row")
	}
	if _, err := f.db.Users().ByUsername(ctx, "victor"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("user persisted without audit: %v", err)
	}
	if pending, _ := f.db.Enrolments().Pending(ctx, f.clk.Now()); len(pending) != 0 {
		t.Fatal("enrolment link persisted without audit")
	}
	if f.auditCount() != before {
		t.Fatal("audit row written for a rolled-back change")
	}
}

func TestSetRoleGuardsAreAuditedAsDenied(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	err := f.svc.SetRole(ctx, f.admin, f.admin.UserID, authz.RoleViewer)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("self-demote err = %v", err)
	}
	f.expectAudit("admin.user.role", "denied")
	link, err := f.svc.CreateUser(ctx, f.admin, "victor", authz.RoleViewer)
	must(t, err)
	_ = link
	vid := f.userID("victor")
	must(t, f.svc.SetRole(ctx, f.admin, vid, authz.RoleOperator))
	p := f.expectAudit("admin.user.role", "ok")
	if p["before"] != "viewer" || p["after"] != "operator" || p["target"] != "victor" {
		t.Fatalf("params = %v", p)
	}
	if err := f.svc.SetRole(ctx, f.admin, "missing", authz.RoleViewer); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing user err = %v", err)
	}
	if err := f.svc.SetRole(ctx, f.admin, vid, authz.Role("x")); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("bad role err = %v", err)
	}
}

func TestDisableEndsSessionsAndLinksEnableRestores(t *testing.T) {
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
	if s, _ := f.svc.Sessions(ctx, vid); len(s) != 1 {
		t.Fatalf("sessions before disable = %d", len(s))
	}
	if _, err := f.svc.ResetEnrolment(ctx, f.admin, vid); err != nil {
		t.Fatal(err)
	}
	must(t, f.svc.SetDisabled(ctx, f.admin, vid, true))
	f.expectAudit("admin.user.disable", "ok")
	if s, _ := f.svc.Sessions(ctx, vid); len(s) != 0 {
		t.Fatal("disable left sessions behind")
	}
	if p, _ := f.db.Enrolments().Pending(ctx, f.clk.Now()); len(p) != 0 {
		t.Fatal("disable left a usable enrolment link")
	}
	if err := f.svc.SetDisabled(ctx, f.admin, f.admin.UserID, true); !errors.Is(err, ErrRefused) {
		t.Fatalf("self-disable err = %v", err)
	}
	must(t, f.svc.SetDisabled(ctx, f.admin, vid, false))
	f.expectAudit("admin.user.enable", "ok")
	u, _ := f.svc.User(ctx, vid)
	if u.Disabled {
		t.Fatal("still disabled")
	}
	if _, err := f.svc.User(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("User(missing) err = %v", err)
	}
}

func TestResetEnrolmentForcesNewAuthenticator(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	link, err := f.svc.CreateUser(ctx, f.admin, "victor", authz.RoleViewer)
	must(t, err)
	oldSecret := f.enrol(link, "victor's long password")
	vid := f.userID("victor")
	reset, err := f.svc.ResetEnrolment(ctx, f.admin, vid)
	must(t, err)
	if reset.Purpose != store.EnrolPurposeReset {
		t.Fatalf("purpose = %s", reset.Purpose)
	}
	f.expectAudit("admin.user.reset_totp", "ok")
	u, _ := f.db.Users().ByID(ctx, vid)
	if u.TOTPConfirmed || u.TOTPSecretEnc != nil {
		t.Fatal("authenticator not cleared")
	}
	newSecret := f.enrol(reset, "victor's new long password")
	if newSecret == oldSecret {
		t.Fatal("reset re-used the old secret")
	}
	if _, err := f.svc.ResetEnrolment(ctx, f.admin, f.admin.UserID); !errors.Is(err, ErrRefused) {
		t.Fatalf("self reset err = %v", err)
	}
	f.noSecretInAudit(link.Token, reset.Token, oldSecret, newSecret, "victor's new long password")
}

func TestSessionsListAndRevoke(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	link, err := f.svc.CreateUser(ctx, f.admin, "victor", authz.RoleViewer)
	must(t, err)
	secret := f.enrol(link, "victor's long password")
	vid := f.userID("victor")
	for range 2 {
		pend, lerr := f.authn.BeginLogin(ctx, auth.LoginRequest{Username: "victor", Password: "victor's long password", IP: "192.0.2.5"})
		must(t, lerr)
		_, _, lerr = f.authn.CompleteLogin(ctx, pend, f.code(secret), "192.0.2.5", "ua")
		must(t, lerr)
	}
	list, err := f.svc.Sessions(ctx, vid)
	must(t, err)
	if len(list) != 2 || len(list[0].ID) != 64 || list[0].IP != "192.0.2.5" {
		t.Fatalf("sessions = %+v", list)
	}
	must(t, f.svc.RevokeSession(ctx, f.admin, vid, list[0].ID))
	f.expectAudit("admin.session.revoke", "ok")
	if err = f.svc.RevokeSession(ctx, f.admin, vid, "zz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("bad sid err = %v", err)
	}
	if err = f.svc.RevokeSession(ctx, f.admin, f.admin.UserID, list[1].ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other user's sid err = %v", err)
	}
	n, err := f.svc.RevokeSessions(ctx, f.admin, vid)
	if err != nil || n != 1 {
		t.Fatalf("RevokeSessions = %d, %v", n, err)
	}
	p := f.expectAudit("admin.session.revoke_all", "ok")
	if p["count"] != float64(1) {
		t.Fatalf("params = %v", p)
	}
	f.clk.Advance(time.Second)
}
