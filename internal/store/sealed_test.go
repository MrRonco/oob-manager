package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestHoldsSealedData(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	// On an empty DB every table in sealedTables is queried, so a renamed table fails here.
	got, err := db.HoldsSealedData(ctx)
	if err != nil || got {
		t.Fatalf("empty DB: %v, %v", got, err)
	}
	if cerr := db.Users().Create(ctx, testUser("u1", "owner")); cerr != nil {
		t.Fatal(cerr)
	}
	if got, err = db.HoldsSealedData(ctx); err != nil || !got {
		t.Fatalf("DB with a user: %v, %v", got, err)
	}
}

func TestHoldsSealedDataReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oob.db")
	ctx := context.Background()
	db, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if cerr := db.Users().Create(ctx, testUser("u1", "owner")); cerr != nil {
		t.Fatal(cerr)
	}
	ro, err := OpenReadOnly(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close(); _ = db.Close() }()
	if got, herr := ro.HoldsSealedData(ctx); herr != nil || !got {
		t.Fatalf("read-only: %v, %v", got, herr)
	}
}
