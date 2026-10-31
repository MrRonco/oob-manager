package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWithTxCommitsAndRunsAfterCommitHooks(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	ran := 0
	err := db.WithTx(ctx, func(tx *Tx) error {
		if err := tx.Users().Create(ctx, testUser("u1", "alice")); err != nil {
			return err
		}
		if _, err := tx.Audit().Append(ctx, chainBuilder(t0)); err != nil {
			return err
		}
		tx.AfterCommit(func() { ran++ })
		if ran != 0 {
			t.Error("hook ran before commit")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}
	if ran != 1 {
		t.Fatalf("after-commit hook ran %d times", ran)
	}
	if _, err := db.Users().ByID(ctx, "u1"); err != nil {
		t.Fatalf("user not committed: %v", err)
	}
	if _, ok, _ := db.Audit().Last(ctx); !ok {
		t.Fatal("audit row not committed")
	}
}

func TestWithTxRollsBackEverythingOnError(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	boom := errors.New("boom")
	ran := false
	err := db.WithTx(ctx, func(tx *Tx) error {
		if err := tx.Users().Create(ctx, testUser("u1", "alice")); err != nil {
			return err
		}
		if _, err := tx.Audit().Append(ctx, chainBuilder(t0)); err != nil {
			return err
		}
		tx.AfterCommit(func() { ran = true })
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if ran {
		t.Error("after-commit hook ran on rollback")
	}
	if _, err := db.Users().ByID(ctx, "u1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("user survived rollback: %v", err)
	}
	if _, ok, _ := db.Audit().Last(ctx); ok {
		t.Error("audit row survived rollback")
	}
}

func TestWithTxRejectsNilFunc(t *testing.T) {
	if err := newTestDB(t).WithTx(context.Background(), nil); err == nil {
		t.Fatal("nil fn accepted")
	}
}

func TestTxSessionReplaceRunsInsideOuterTx(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mustCreateUser(t, db, "u1", "alice", RoleAdmin)
	old := Session{IDHash: []byte("old"), UserID: "u1", CreatedAt: t0, LastSeen: t0}
	if err := db.Sessions().Create(ctx, old); err != nil {
		t.Fatal(err)
	}
	err := db.WithTx(ctx, func(tx *Tx) error {
		return tx.Sessions().Replace(ctx, []byte("old"), Session{IDHash: []byte("new"), UserID: "u1",
			CreatedAt: t0, LastSeen: t0})
	})
	if err != nil {
		t.Fatalf("Replace in tx: %v", err)
	}
	if _, err := db.Sessions().Get(ctx, []byte("new")); err != nil {
		t.Fatalf("new session missing: %v", err)
	}
}

// chainBuilder links the next audit record correctly (the audit package normally does).
func chainBuilder(at time.Time) AuditBuilder {
	return func(last AuditRecord, ok bool) (AuditRecord, error) {
		r := AuditRecord{TS: at, CorrelationID: "c", Principal: "p", Action: "a", ParamsJSON: "{}",
			Result: "ok", Seq: 1, PrevHash: "genesis"}
		if ok {
			r.Seq, r.PrevHash = last.Seq+1, last.RowHash
		}
		r.RowHash = "h" + time.Duration(r.Seq).String()
		return r, nil
	}
}

func mustCreateUser(t *testing.T, db *DB, id, name string, role Role) {
	t.Helper()
	u := testUser(id, name)
	u.Email, u.Role = "", role
	if err := db.Users().Create(context.Background(), u); err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
}
