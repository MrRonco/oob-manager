package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"oob-manager/internal/auth"
)

func TestTokenCreateListRevoke(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	raw, tok, err := f.svc.CreateToken(ctx, f.admin, f.admin.UserID, "dashboard", 30*24*time.Hour)
	must(t, err)
	p := f.expectAudit("token.create", "ok")
	if p["token_id"] != tok.ID || p["name"] != "dashboard" || p["owner"] != "alice" || p["expires"] == "never" {
		t.Fatalf("params = %v", p)
	}
	if _, _, err = f.tokens.Verify(ctx, raw); err != nil {
		t.Fatalf("new token does not verify: %v", err)
	}
	list, err := f.svc.Tokens(ctx)
	must(t, err)
	if len(list) != 1 || list[0].Owner != "alice" || list[0].Status != auth.TokenActive || list[0].Hash != nil {
		t.Fatalf("list = %+v", list)
	}
	must(t, f.svc.RevokeToken(ctx, f.admin, tok.ID))
	f.expectAudit("token.revoke", "ok")
	if _, _, err := f.tokens.Verify(ctx, raw); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("revoked token verifies: %v", err)
	}
	if err := f.svc.RevokeToken(ctx, f.admin, tok.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second revoke err = %v", err)
	}
	f.noSecretInAudit(raw)
}

func TestTokenCreateValidationAndAuditFailure(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, _, err := f.svc.CreateToken(ctx, f.admin, f.admin.UserID, "", 0); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("empty name err = %v", err)
	}
	if _, _, err := f.svc.CreateToken(ctx, f.admin, f.admin.UserID, "x", time.Minute); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("short lifetime err = %v", err)
	}
	if _, _, err := f.svc.CreateToken(ctx, f.admin, "ghost", "x", 0); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unknown owner err = %v", err)
	}
	f.audit.fail = true
	if _, _, err := f.svc.CreateToken(ctx, f.admin, f.admin.UserID, "x", 0); err == nil {
		t.Fatal("token created without audit")
	}
	if list, _ := f.svc.Tokens(ctx); len(list) != 0 {
		t.Fatal("token persisted without its audit row")
	}
}
