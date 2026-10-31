package admin

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
)

func TestRedeemLinkSetsPasswordAndShowsSecretOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	link, err := f.svc.CreateUser(ctx, f.admin, "victor", authz.RoleOperator)
	must(t, err)
	info, err := f.svc.LookupLink(ctx, link.Token)
	if err != nil || info.Username != "victor" || !info.ExpiresAt.Equal(link.ExpiresAt) {
		t.Fatalf("LookupLink = %+v, %v", info, err)
	}
	if _, _, err = f.svc.RedeemLink(ctx, link.Token, "short", "192.0.2.9"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("weak password err = %v", err)
	}
	enr, user, err := f.svc.RedeemLink(ctx, link.Token, "victor's long password", "192.0.2.9")
	if err != nil || user != "victor" || enr.Secret == "" {
		t.Fatalf("RedeemLink = %v, %q, %v", enr, user, err)
	}
	rec, p := f.lastAudit()
	if rec.Action != "auth.enrol" || rec.Principal != "victor" || p["purpose"] != "enrol" || rec.SrcIP != "192.0.2.9" {
		t.Fatalf("audit %+v %v", rec, p)
	}
	if _, _, err = f.svc.RedeemLink(ctx, link.Token, "victor's long password", "192.0.2.9"); !errors.Is(err, ErrLinkInvalid) {
		t.Fatalf("second redemption err = %v", err)
	}
	if _, err = f.svc.LookupLink(ctx, link.Token); !errors.Is(err, ErrLinkInvalid) {
		t.Fatalf("lookup of used link err = %v", err)
	}
	must(t, f.authn.ConfirmTOTP(ctx, "victor", "victor's long password", f.code(enr.Secret), "192.0.2.9"))
	pending, err := f.authn.BeginLogin(ctx, auth.LoginRequest{Username: "victor", Password: "victor's long password", IP: "192.0.2.9"})
	must(t, err)
	if _, _, err := f.authn.CompleteLogin(ctx, pending, f.code(enr.Secret), "192.0.2.9", "ua"); err != nil {
		t.Fatalf("login after enrolment: %v", err)
	}
	f.noSecretInAudit(link.Token, enr.Secret, "victor's long password")
}

func TestLinkRejections(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, raw := range []string{"", "not-a-token", "../../etc/passwd"} {
		if _, err := f.svc.LookupLink(ctx, raw); !errors.Is(err, ErrLinkInvalid) {
			t.Errorf("LookupLink(%q) err = %v", raw, err)
		}
	}
	unknown, _ := auth.NewLinkToken()
	if _, _, err := f.svc.RedeemLink(ctx, unknown, "victor's long password", "ip"); !errors.Is(err, ErrLinkInvalid) {
		t.Fatalf("unknown link err = %v", err)
	}
	link, err := f.svc.CreateUser(ctx, f.admin, "victor", authz.RoleViewer)
	must(t, err)
	f.clk.Advance(DefaultLinkTTL + time.Second)
	if _, _, err = f.svc.RedeemLink(ctx, link.Token, "victor's long password", "ip"); !errors.Is(err, ErrLinkInvalid) {
		t.Fatalf("expired link err = %v", err)
	}
	fresh, err := f.svc.ResetEnrolment(ctx, f.admin, f.userID("victor"))
	must(t, err)
	must(t, f.svc.SetDisabled(ctx, f.admin, f.userID("victor"), true))
	if _, err := f.svc.LookupLink(ctx, fresh.Token); !errors.Is(err, ErrLinkInvalid) {
		t.Fatalf("link of disabled user err = %v", err)
	}
}

// Two browsers racing to redeem one link: exactly one wins.
func TestConcurrentRedemptionSucceedsOnce(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	link, err := f.svc.CreateUser(ctx, f.admin, "victor", authz.RoleViewer)
	must(t, err)
	var wg sync.WaitGroup
	errs := make([]error, 4)
	for i := range errs {
		wg.Go(func() { _, _, errs[i] = f.svc.RedeemLink(ctx, link.Token, "victor's long password", "ip") })
	}
	wg.Wait()
	ok := 0
	for _, err := range errs {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, ErrLinkInvalid):
			t.Fatalf("unexpected err %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d redemptions succeeded", ok)
	}
}
