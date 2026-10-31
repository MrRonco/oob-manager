package store

import (
	"context"
	"testing"
	"time"
)

func TestTokenExpiryRoundTrips(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := db.Users().Create(ctx, testUser("u1", "admin")); err != nil {
		t.Fatal(err)
	}
	exp := t0.Add(90 * 24 * time.Hour)
	cases := []APIToken{
		{ID: "t1", Name: "dash", TokenHash: []byte("h1"), Scope: ScopeRead, CreatedBy: "u1", CreatedAt: t0, ExpiresAt: exp},
		{ID: "t2", Name: "forever", TokenHash: []byte("h2"), Scope: ScopeRead, CreatedBy: "u1", CreatedAt: t0},
	}
	for _, tok := range cases {
		if err := db.Tokens().Create(ctx, tok); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.Tokens().ByHash(ctx, []byte("h1"))
	if err != nil || !got.ExpiresAt.Equal(exp) {
		t.Fatalf("expiring token = %+v, %v", got, err)
	}
	list, err := db.Tokens().List(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("List = %+v, %v", list, err)
	}
	for _, tok := range list {
		if tok.ID == "t2" && !tok.ExpiresAt.IsZero() {
			t.Fatalf("non-expiring token got expiry %v", tok.ExpiresAt)
		}
	}
}

func TestTokenExpiredAt(t *testing.T) {
	tok := APIToken{ExpiresAt: t0}
	if tok.ExpiredAt(t0.Add(-time.Second)) || !tok.ExpiredAt(t0) || (APIToken{}).ExpiredAt(t0) {
		t.Fatal("ExpiredAt boundaries wrong")
	}
}
