package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func seedAudit(t *testing.T, db *DB, rows []AuditRecord) {
	t.Helper()
	ctx := context.Background()
	for i, r := range rows {
		_, err := db.Audit().Append(ctx, func(last AuditRecord, ok bool) (AuditRecord, error) {
			r.Seq, r.PrevHash = 1, "g"
			if ok {
				r.Seq, r.PrevHash = last.Seq+1, last.RowHash
			}
			r.TS, r.CorrelationID, r.ParamsJSON = t0.Add(time.Duration(i)*time.Second), "c", "{}"
			r.RowHash = fmt.Sprintf("h%d", r.Seq)
			return r, nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditSearchFiltersAndKeysetPaging(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	seedAudit(t, db, []AuditRecord{
		{Principal: "alice", Action: "auth.login", Result: "ok"},
		{Principal: "bob", Action: "auth.login", Result: "denied"},
		{Principal: "alice", Action: "admin.user.create", Result: "ok"},
		{Principal: "alice", Action: "auth.login", Result: "ok", ServerID: "r1"},
		{Principal: "system", Action: "app.start", Result: "ok"},
	})
	s := db.AuditSearch()
	all, err := s.Search(ctx, AuditFilter{Limit: 2})
	if err != nil || len(all) != 2 || all[0].Seq != 5 || all[1].Seq != 4 {
		t.Fatalf("newest page = %+v, %v", all, err)
	}
	next, err := s.Search(ctx, AuditFilter{Limit: 2, BeforeSeq: all[1].Seq})
	if err != nil || len(next) != 2 || next[0].Seq != 3 {
		t.Fatalf("second page = %+v, %v", next, err)
	}
	logins, _ := s.Search(ctx, AuditFilter{Action: "auth.login", Principal: "alice", Limit: 10})
	if len(logins) != 2 || logins[0].Seq != 4 {
		t.Fatalf("alice logins = %+v", logins)
	}
	denied, _ := s.Search(ctx, AuditFilter{Result: "denied", Limit: 10})
	if len(denied) != 1 || denied[0].Principal != "bob" {
		t.Fatalf("denied = %+v", denied)
	}
	server, _ := s.Search(ctx, AuditFilter{ServerID: "r1", Limit: 10})
	if len(server) != 1 || server[0].Seq != 4 {
		t.Fatalf("server filter = %+v", server)
	}
	if _, err = s.Search(ctx, AuditFilter{Limit: 0}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("limit 0 err = %v", err)
	}
	actions, err := s.Actions(ctx)
	if err != nil || len(actions) != 3 || actions[0] != "admin.user.create" {
		t.Fatalf("Actions = %v, %v", actions, err)
	}
}

// TestAuditSearchActionsAndSince: the history overlay's filter (a list of actions and a
// lower time bound) composes with the other fields from fixed fragments.
func TestAuditSearchActionsAndSince(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	prev := strings.Repeat("0", 64)
	for i, a := range []string{"power.on", "fan.lease.create", "app.start", "power.on"} {
		seq := int64(i + 1)
		rec := auditRow(seq, prev)
		rec.Action, rec.ServerID = a, "r240"
		prev = rec.RowHash
		if _, err := db.Audit().Append(ctx, func(AuditRecord, bool) (AuditRecord, error) { return rec, nil }); err != nil {
			t.Fatal(err)
		}
	}
	got, err := db.AuditSearch().Search(ctx, AuditFilter{Actions: []string{"power.on", "fan.lease.create"},
		Since: t0.Add(2 * time.Second), ServerID: "r240", Limit: 10})
	if err != nil || len(got) != 2 || got[0].Seq != 4 || got[1].Seq != 2 {
		t.Fatalf("Search = %+v, %v", got, err)
	}
	if _, err = db.AuditSearch().Search(ctx, AuditFilter{Actions: make([]string, MaxAuditFilterActions+1), Limit: 1}); !errors.Is(err, ErrInvalid) {
		t.Errorf("too many actions: %v", err)
	}
	// Matches: action and result pairs (auditRow writes result "ok").
	got, err = db.AuditSearch().Search(ctx, AuditFilter{Matches: []AuditMatch{{"power.on", "started"}, {"app.start", "ok"}}, Limit: 10})
	if err != nil || len(got) != 1 || got[0].Action != "app.start" {
		t.Fatalf("Matches = %+v, %v", got, err)
	}
	if _, err = db.AuditSearch().Search(ctx, AuditFilter{Matches: make([]AuditMatch, MaxAuditFilterMatches+1), Limit: 1}); !errors.Is(err, ErrInvalid) {
		t.Errorf("too many pairs: %v", err)
	}
}
