package audit

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"oob-manager/internal/store"
)

func openStore(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestRecordTxCommitsWithTheChangeAndShipsAfterCommit(t *testing.T) {
	db := openStore(t)
	sink := &captureSink{}
	lg := NewLogger(db.Audit(), sink, fixedClock(), quietLogger())
	ctx := context.Background()
	if _, err := lg.Record(ctx, entry(1)); err != nil {
		t.Fatal(err)
	}
	var rec store.AuditRecord
	err := db.WithTx(ctx, func(tx *store.Tx) error {
		var err error
		rec, err = lg.RecordTx(ctx, tx, entry(2))
		if len(sink.msgs) != 1 {
			t.Error("GELF copy enqueued before commit")
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if rec.Seq != 2 || len(sink.msgs) != 2 || sink.msgs[1].Fields["audit_seq"] != int64(2) {
		t.Fatalf("rec %+v, shipped %d", rec, len(sink.msgs))
	}
	if res, err := Verify(ctx, db.Audit(), 0); err != nil || res.Count != 2 {
		t.Fatalf("chain after RecordTx: %+v, %v", res, err)
	}
}

func TestRecordTxRollsBackWithTheChange(t *testing.T) {
	db := openStore(t)
	sink := &captureSink{}
	lg := NewLogger(db.Audit(), sink, fixedClock(), quietLogger())
	ctx := context.Background()
	boom := errors.New("change failed")
	err := db.WithTx(ctx, func(tx *store.Tx) error {
		if _, err := lg.RecordTx(ctx, tx, entry(1)); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
	if _, ok, _ := db.Audit().Last(ctx); ok || len(sink.msgs) != 0 {
		t.Fatalf("audit row or GELF copy survived a rollback (shipped %d)", len(sink.msgs))
	}
}

func TestRecordTxValidates(t *testing.T) {
	db := openStore(t)
	lg := NewLogger(db.Audit(), nil, fixedClock(), quietLogger())
	err := db.WithTx(context.Background(), func(tx *store.Tx) error {
		_, err := lg.RecordTx(context.Background(), tx, Entry{Action: "x"})
		return err
	})
	if !errors.Is(err, ErrInvalidEntry) {
		t.Fatalf("err = %v", err)
	}
}

// Secrets must never reach the chain, whatever a caller puts in Params.
func TestParamsAreRedacted(t *testing.T) {
	repo := &memRepo{}
	lg := NewLogger(repo, nil, fixedClock(), quietLogger())
	e := Entry{Principal: "admin", Action: "admin.user.create", Result: ResultOK, Params: map[string]any{ //nolint:gosec // G101: fake secrets that must be redacted
		"target": "victor", "password": "hunter2-secret", "totp_secret": "JBSWY3DP", "token": "oobk_raw",
		"link": "https://x/enroll/abc", "code": "123456", "token_id": "t1",
		"nested": map[string]any{"new_password": "p2"},
	}}
	rec, err := lg.Record(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{"hunter2-secret", "JBSWY3DP", "oobk_raw", "enroll/abc", "123456", `"p2"`} {
		if strings.Contains(rec.ParamsJSON, leak) {
			t.Errorf("params leak %q: %s", leak, rec.ParamsJSON)
		}
	}
	for _, keep := range []string{`"target":"victor"`, `"token_id":"t1"`, `"password":"[redacted]"`} {
		if !strings.Contains(rec.ParamsJSON, keep) {
			t.Errorf("params lack %s: %s", keep, rec.ParamsJSON)
		}
	}
	if e.Params["password"] != "hunter2-secret" {
		t.Error("Record mutated the caller's params")
	}
}

func TestViewer(t *testing.T) {
	db := openStore(t)
	lg := NewLogger(db.Audit(), nil, fixedClock(), quietLogger())
	ctx := context.Background()
	for i := range 3 {
		if _, err := lg.Record(ctx, entry(i)); err != nil {
			t.Fatal(err)
		}
	}
	v := NewViewer(db.Audit(), db.AuditSearch())
	rows, err := v.Search(ctx, store.AuditFilter{Limit: 2})
	if err != nil || len(rows) != 2 || rows[0].Seq != 3 {
		t.Fatalf("Search = %+v, %v", rows, err)
	}
	if acts, err := v.Actions(ctx); err != nil || len(acts) != 1 {
		t.Fatalf("Actions = %v, %v", acts, err)
	}
	if res, err := v.Verify(ctx); err != nil || res.Count != 3 || res.Head != rows[0].RowHash {
		t.Fatalf("Verify = %+v, %v", res, err)
	}
}
