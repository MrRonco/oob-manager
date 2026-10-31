package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/store"
)

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 123456789, time.UTC)

// memRepo is an in-memory store.AuditRepository whose rows tests may tamper with.
type memRepo struct {
	mu        sync.Mutex
	recs      []store.AuditRecord
	appendErr error
	listErr   error
}

func (m *memRepo) Append(_ context.Context, build store.AuditBuilder) (store.AuditRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.appendErr != nil {
		return store.AuditRecord{}, m.appendErr
	}
	var last store.AuditRecord
	ok := len(m.recs) > 0
	if ok {
		last = m.recs[len(m.recs)-1]
	}
	rec, err := build(last, ok)
	if err != nil {
		return store.AuditRecord{}, err
	}
	m.recs = append(m.recs, rec)
	return rec, nil
}

func (m *memRepo) Last(context.Context) (store.AuditRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.recs) == 0 {
		return store.AuditRecord{}, false, nil
	}
	return m.recs[len(m.recs)-1], true, nil
}

func (m *memRepo) List(_ context.Context, after int64, limit int) ([]store.AuditRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listErr != nil {
		return nil, m.listErr
	}
	var out []store.AuditRecord
	for _, r := range m.recs {
		if r.Seq > after && len(out) < limit {
			out = append(out, r)
		}
	}
	return out, nil
}

func fixedClock() func() time.Time {
	var mu sync.Mutex
	n := 0
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		n++
		return t0.Add(time.Duration(n) * time.Second)
	}
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func entry(i int) Entry {
	return Entry{CorrelationID: fmt.Sprint("corr-", i), Principal: "morgan", AuthMethod: "local", Role: "admin",
		SrcIP: "192.0.2.100", ServerID: "r240", Action: "power.GracefulRestart",
		Params: map[string]any{"confirm": true, "n": i}, Result: ResultOK, BMCStatus: "204"}
}

func buildChain(t *testing.T, repo store.AuditRepository, n int) {
	t.Helper()
	lg := NewLogger(repo, nil, fixedClock(), quietLogger())
	for i := 0; i < n; i++ {
		if _, err := lg.Record(context.Background(), entry(i)); err != nil {
			t.Fatalf("Record %d: %v", i, err)
		}
	}
}

func TestHashCoversEveryField(t *testing.T) {
	base := store.AuditRecord{Seq: 1, TS: t0, CorrelationID: "c", Principal: "p", AuthMethod: "a", Role: "r",
		SrcIP: "s", ServerID: "sv", Action: "ac", ParamsJSON: "{}", Result: "ok", BMCStatus: "b",
		ErrorClass: "e", PrevHash: GenesisHash}
	h := Hash(base)
	if h != Hash(base) || len(h) != 64 {
		t.Fatalf("hash not deterministic or wrong length: %s", h)
	}
	mutations := []func(r *store.AuditRecord){
		func(r *store.AuditRecord) { r.Seq = 2 },
		func(r *store.AuditRecord) { r.TS = r.TS.Add(time.Millisecond) },
		func(r *store.AuditRecord) { r.CorrelationID = "x" },
		func(r *store.AuditRecord) { r.Principal = "x" },
		func(r *store.AuditRecord) { r.AuthMethod = "x" },
		func(r *store.AuditRecord) { r.Role = "x" },
		func(r *store.AuditRecord) { r.SrcIP = "x" },
		func(r *store.AuditRecord) { r.ServerID = "x" },
		func(r *store.AuditRecord) { r.Action = "x" },
		func(r *store.AuditRecord) { r.ParamsJSON = `{"a":1}` },
		func(r *store.AuditRecord) { r.Result = "x" },
		func(r *store.AuditRecord) { r.BMCStatus = "x" },
		func(r *store.AuditRecord) { r.ErrorClass = "x" },
		func(r *store.AuditRecord) { r.PrevHash = "x" },
		// field boundary shift must not collide
		func(r *store.AuditRecord) { r.Principal, r.AuthMethod = "pa", "" },
	}
	for i, mut := range mutations {
		c := base
		mut(&c)
		if Hash(c) == h {
			t.Errorf("mutation %d did not change the hash", i)
		}
	}
	withHash := base
	withHash.RowHash = "ignored"
	if Hash(withHash) != h {
		t.Error("RowHash must not be an input to its own hash")
	}
}

func TestVerifyIntactChain(t *testing.T) {
	repo := &memRepo{}
	buildChain(t, repo, 7)
	res, err := Verify(context.Background(), repo, 3)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Count != 7 || res.Head != repo.recs[6].RowHash {
		t.Errorf("result = %+v", res)
	}
	empty, err := Verify(context.Background(), &memRepo{}, 0)
	if err != nil || empty.Count != 0 || empty.Head != GenesisHash {
		t.Errorf("empty = %+v, %v", empty, err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	cases := map[string]func(recs []store.AuditRecord) []store.AuditRecord{
		"edited field": func(r []store.AuditRecord) []store.AuditRecord { r[2].Result = "denied"; return r },
		"edited and rehashed row": func(r []store.AuditRecord) []store.AuditRecord {
			r[2].Principal = "mallory"
			r[2].RowHash = Hash(r[2])
			return r
		},
		"deleted middle row": func(r []store.AuditRecord) []store.AuditRecord { return append(r[:2], r[3:]...) },
		"deleted first row":  func(r []store.AuditRecord) []store.AuditRecord { return r[1:] },
		"forged genesis": func(r []store.AuditRecord) []store.AuditRecord {
			r[0].PrevHash = "f00d"
			return r
		},
		"renumbered after delete": func(r []store.AuditRecord) []store.AuditRecord {
			r = append(r[:2], r[3:]...)
			for i := range r {
				r[i].Seq = int64(i + 1)
			}
			return r
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			repo := &memRepo{}
			buildChain(t, repo, 5)
			repo.recs = tamper(repo.recs)
			_, err := Verify(context.Background(), repo, 2)
			if !errors.Is(err, ErrTampered) {
				t.Fatalf("err = %v, want ErrTampered", err)
			}
			var te *TamperError
			if !errors.As(err, &te) || te.Seq == 0 || te.Reason == "" {
				t.Errorf("TamperError = %+v", te)
			}
		})
	}
}

func TestVerifyListError(t *testing.T) {
	repo := &memRepo{listErr: errors.New("disk gone")}
	if _, err := Verify(context.Background(), repo, 10); err == nil || errors.Is(err, ErrTampered) {
		t.Errorf("err = %v", err)
	}
}

func TestVerifyAgainstSQLite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oob.db")
	ctx := context.Background()
	db, err := store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	buildChain(t, db.Audit(), 4)
	if _, err = Verify(ctx, db.Audit(), DefaultVerifyPage); err != nil {
		t.Fatalf("intact chain: %v", err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}

	// An attacker with file access drops the trigger and edits a row.
	raw, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP TRIGGER audit_log_no_update`, `UPDATE audit_log SET principal='mallory' WHERE seq=2`} {
		if _, err = raw.ExecContext(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err = raw.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = store.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = Verify(ctx, db.Audit(), DefaultVerifyPage)
	var te *TamperError
	if !errors.As(err, &te) || te.Seq != 2 {
		t.Fatalf("err = %v, want tamper at seq 2", err)
	}
}

// TestHashDomainIsPinned freezes the row hash of a known record. hashDomain keeps the
// pre-rename project name (oob-console) on purpose: every stored row_hash includes it,
// so a new domain would make Verify report the whole existing chain as tampered.
func TestHashDomainIsPinned(t *testing.T) {
	if hashDomain != "oob-console/audit/v1" {
		t.Fatalf("hashDomain changed: %q", hashDomain)
	}
	r := store.AuditRecord{Seq: 1, TS: t0, CorrelationID: "c", Principal: "p", AuthMethod: "a", Role: "r",
		SrcIP: "s", ServerID: "sv", Action: "ac", ParamsJSON: "{}", Result: "ok", BMCStatus: "b",
		ErrorClass: "e", PrevHash: GenesisHash}
	if got := Hash(r); got != "64d5a42f6cfbc22fe65d00b80aa24b0b84a1709c0a7aed0e14ca29fc7ceb556a" {
		t.Fatalf("row hash of a known record changed: %s", got)
	}
}
