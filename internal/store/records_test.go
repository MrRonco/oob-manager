package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestTokens(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := db.Users().Create(ctx, testUser("u1", "morgan")); err != nil {
		t.Fatal(err)
	}
	tokens := db.Tokens()
	tok := APIToken{ID: "t1", Name: "homepage", TokenHash: []byte("th1"), Scope: ScopeRead, CreatedBy: "u1", CreatedAt: t0}
	if err := tokens.Create(ctx, tok); err != nil {
		t.Fatal(err)
	}
	dup := tok
	dup.ID = "t2"
	if err := tokens.Create(ctx, dup); !errors.Is(err, ErrConflict) {
		t.Errorf("dup hash err = %v", err)
	}
	write := APIToken{ID: "t3", Name: "evil", TokenHash: []byte("th3"), Scope: "write", CreatedBy: "u1", CreatedAt: t0}
	if err := tokens.Create(ctx, write); !errors.Is(err, ErrInvalid) {
		t.Errorf("write scope err = %v", err)
	}
	got, err := tokens.ByHash(ctx, []byte("th1"))
	if err != nil || got.ID != "t1" || got.Revoked() || !got.LastUsedAt.IsZero() {
		t.Fatalf("ByHash = %+v, %v", got, err)
	}
	if _, err = tokens.ByHash(ctx, []byte("nope")); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
	later := t0.Add(time.Hour)
	if err = tokens.Touch(ctx, "t1", later); err != nil {
		t.Fatal(err)
	}
	if err = tokens.Revoke(ctx, "t1", later); err != nil {
		t.Fatal(err)
	}
	if err = tokens.Revoke(ctx, "t1", later.Add(time.Hour)); !errors.Is(err, ErrNotFound) {
		t.Errorf("double revoke = %v", err)
	}
	if err = tokens.Touch(ctx, "nope", later); !errors.Is(err, ErrNotFound) {
		t.Errorf("touch missing = %v", err)
	}
	list, err := tokens.List(ctx)
	if err != nil || len(list) != 1 || !list[0].Revoked() || !list[0].LastUsedAt.Equal(later) || !list[0].RevokedAt.Equal(later) {
		t.Errorf("List = %+v, %v", list, err)
	}
}

func testLease(id, server string) FanLease {
	return FanLease{LeaseID: id, ServerID: server, Mode: LeaseBoost, Pct: 55, IssuedAt: t0,
		ExpiresAt: t0.Add(30 * time.Minute), RequestedBy: "morgan", State: LeasePending, UpdatedAt: t0}
}

func TestLeases(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	leases := db.Leases()
	l := testLease("L1", "r730xd")
	if err := leases.Create(ctx, l); err != nil {
		t.Fatal(err)
	}
	if err := leases.Create(ctx, testLease("L2", "r730xd")); !errors.Is(err, ErrConflict) {
		t.Errorf("second active lease err = %v", err)
	}
	r240 := testLease("L3", "r240")
	r240.OriginalValue, r240.HasOriginal = 255, true
	if err := leases.Create(ctx, r240); err != nil {
		t.Fatal(err)
	}
	bad := testLease("L4", "x")
	bad.Pct = 140
	if err := leases.Create(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Errorf("pct 140 err = %v", err)
	}
	backwards := testLease("L5", "y")
	backwards.ExpiresAt = t0.Add(-time.Minute)
	if err := leases.Create(ctx, backwards); !errors.Is(err, ErrInvalid) {
		t.Errorf("expiry before issue err = %v", err)
	}

	got, err := leases.Active(ctx, "r240")
	if err != nil || !got.HasOriginal || got.OriginalValue != 255 || !got.ExpiresAt.Equal(r240.ExpiresAt) {
		t.Fatalf("Active = %+v, %v", got, err)
	}
	if _, err := leases.Active(ctx, "none"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Active missing = %v", err)
	}
}

func TestLeaseTransitions(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	leases := db.Leases()
	for _, l := range []FanLease{testLease("L1", "r730xd"), testLease("L3", "r240")} {
		if err := leases.Create(ctx, l); err != nil {
			t.Fatal(err)
		}
	}
	if err := leases.Transition(ctx, "L1", LeasePending, LeaseApplied, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := leases.Transition(ctx, "L1", LeasePending, LeaseEnded, t0); !errors.Is(err, ErrConflict) {
		t.Errorf("stale from-state err = %v", err)
	}
	if err := leases.Transition(ctx, "L1", LeaseEnded, LeasePending, t0); !errors.Is(err, ErrInvalid) {
		t.Errorf("terminal from-state err = %v", err)
	}
	if err := leases.Transition(ctx, "L1", LeaseApplied, "bogus", t0); !errors.Is(err, ErrInvalid) {
		t.Errorf("bogus to-state err = %v", err)
	}
	open, err := leases.ListByStates(ctx, LeasePending, LeaseApplied)
	if err != nil || len(open) != 2 {
		t.Errorf("ListByStates = %v, %v", open, err)
	}
	if err = leases.Transition(ctx, "L1", LeaseApplied, LeaseExpired, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = leases.Create(ctx, testLease("L6", "r730xd")); err != nil {
		t.Errorf("new lease after expiry: %v", err)
	}
	hist, err := leases.ListByServer(ctx, "r730xd", 10)
	if err != nil || len(hist) != 2 || hist[0].LeaseID != "L6" {
		t.Errorf("ListByServer = %+v, %v", hist, err)
	}
	one, err := leases.Get(ctx, "L1")
	if err != nil || one.State != LeaseExpired || !one.UpdatedAt.Equal(t0.Add(time.Hour)) {
		t.Errorf("Get = %+v, %v", one, err)
	}
	if _, err := leases.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Get missing = %v", err)
	}
	if _, err := leases.ListByStates(ctx); !errors.Is(err, ErrInvalid) {
		t.Errorf("no states err = %v", err)
	}
}

func TestCapabilities(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	caps := db.Capabilities()
	if err := caps.Put(ctx, Capability{ServerID: "r240", ProbedAt: t0, JSON: `{"kvm":true}`}); err != nil {
		t.Fatal(err)
	}
	if err := caps.Put(ctx, Capability{ServerID: "r240", ProbedAt: t0.Add(time.Hour), JSON: `{"kvm":false}`}); err != nil {
		t.Fatal(err)
	}
	got, err := caps.Get(ctx, "r240")
	if err != nil || got.JSON != `{"kvm":false}` || !got.ProbedAt.Equal(t0.Add(time.Hour)) {
		t.Errorf("Get = %+v, %v", got, err)
	}
	if _, err := caps.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
	if err := caps.Put(ctx, Capability{ServerID: "x", ProbedAt: t0, JSON: "not json"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("bad json err = %v", err)
	}
}

func auditRow(seq int64, prev string) AuditRecord {
	return AuditRecord{Seq: seq, TS: t0.Add(time.Duration(seq) * time.Second), CorrelationID: fmt.Sprint("c", seq),
		Principal: "morgan", AuthMethod: "local", Role: "admin", SrcIP: "192.0.2.100", ServerID: "r240",
		Action: "power.GracefulRestart", ParamsJSON: "{}", Result: "ok", PrevHash: prev,
		RowHash: fmt.Sprintf("%064d", seq)}
}

func TestAuditAppendAndList(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	audit := db.Audit()
	if _, ok, err := audit.Last(ctx); err != nil || ok {
		t.Fatalf("Last on empty = %v, %v", ok, err)
	}
	prev := strings.Repeat("0", 64)
	for i := int64(1); i <= 5; i++ {
		rec, err := audit.Append(ctx, func(last AuditRecord, ok bool) (AuditRecord, error) {
			if ok != (i > 1) || (ok && last.Seq != i-1) {
				return AuditRecord{}, fmt.Errorf("unexpected last %d ok=%v", last.Seq, ok)
			}
			return auditRow(i, prev), nil
		})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		prev = rec.RowHash
	}
	last, ok, err := audit.Last(ctx)
	if err != nil || !ok || last.Seq != 5 || !last.TS.Equal(t0.Add(5*time.Second)) {
		t.Errorf("Last = %+v %v %v", last, ok, err)
	}
	page, err := audit.List(ctx, 2, 2)
	if err != nil || len(page) != 2 || page[0].Seq != 3 || page[1].Seq != 4 {
		t.Errorf("List = %+v, %v", page, err)
	}
	if _, err := audit.List(ctx, 0, 0); !errors.Is(err, ErrInvalid) {
		t.Errorf("limit 0 err = %v", err)
	}
	if _, err := audit.List(ctx, 0, MaxAuditPage+1); !errors.Is(err, ErrInvalid) {
		t.Errorf("limit too big err = %v", err)
	}
}

func TestAuditAppendGuards(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	audit := db.Audit()
	genesis := strings.Repeat("0", 64)
	cases := map[string]func(AuditRecord, bool) (AuditRecord, error){
		"builder error": func(AuditRecord, bool) (AuditRecord, error) { return AuditRecord{}, errors.New("boom") },
		"seq gap":       func(AuditRecord, bool) (AuditRecord, error) { return auditRow(2, genesis), nil },
	}
	for name, fn := range cases {
		if _, err := audit.Append(ctx, fn); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	if _, err := audit.Append(ctx, func(AuditRecord, bool) (AuditRecord, error) { return auditRow(1, genesis), nil }); err != nil {
		t.Fatal(err)
	}
	_, err := audit.Append(ctx, func(AuditRecord, bool) (AuditRecord, error) { return auditRow(2, "wrong"), nil })
	if !errors.Is(err, ErrConflict) {
		t.Errorf("broken prev_hash err = %v", err)
	}
}

func TestAuditIsAppendOnly(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if _, err := db.Audit().Append(ctx, func(AuditRecord, bool) (AuditRecord, error) {
		return auditRow(1, strings.Repeat("0", 64)), nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.sql.ExecContext(ctx, `UPDATE audit_log SET result='forged'`); err == nil {
		t.Error("UPDATE on audit_log succeeded")
	}
	if _, err := db.sql.ExecContext(ctx, `DELETE FROM audit_log`); err == nil {
		t.Error("DELETE on audit_log succeeded")
	}
}
