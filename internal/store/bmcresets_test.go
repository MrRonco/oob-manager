package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func resetRow(id string, at time.Time) BMCResetRow {
	return BMCResetRow{ServerID: id, CorrelationID: "c-" + id, RequestedAt: at, SentAt: at.Add(time.Second),
		RequestedBy: "alice", ResetType: "GracefulRestart", Result: BMCResetSent, DeadlineAt: at.Add(5 * time.Minute)}
}

func TestBMCResetsLifecycle(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := db.BMCResets()
	a1, err := r.Insert(ctx, resetRow("srv-a", t0))
	if err != nil {
		t.Fatal(err)
	}
	a2, err := r.Insert(ctx, resetRow("srv-a", t0.Add(time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	b := resetRow("srv-b", t0.Add(2*time.Hour))
	b.Result, b.ErrorClass = BMCResetRefused, "auth"
	if _, err = r.Insert(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err = r.Finish(ctx, a1, BMCResetVerified, t0.Add(2*time.Minute), "", BMCResetUnchanged); err != nil {
		t.Fatal(err)
	}
	// Finishing twice (or a row that is not open) is a conflict: the first outcome stays.
	if err = r.Finish(ctx, a1, BMCResetTimeout, time.Time{}, "timeout", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("second finish: %v", err)
	}
	if err = r.Finish(ctx, 999, BMCResetTimeout, time.Time{}, "timeout", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("unknown row: %v", err)
	}
	if err = r.MarkUnconfirmed(ctx, a2); err != nil {
		t.Fatal(err)
	}
	if err = r.MarkUnconfirmed(ctx, a1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a finished row was marked: %v", err)
	}
	open, err := r.Open(ctx)
	if err != nil || len(open) != 1 || open[0].ID != a2 || !open[0].BackAt.IsZero() || !open[0].Unconfirmed ||
		!open[0].SentAt.Equal(t0.Add(time.Hour+time.Second)) {
		t.Fatalf("open %+v %v", open, err)
	}
	latest, err := r.Latest(ctx)
	if err != nil || len(latest) != 2 || latest[0].ID != a2 || latest[1].ServerID != "srv-b" ||
		latest[1].Result != BMCResetRefused || latest[1].ErrorClass != "auth" {
		t.Fatalf("latest %+v %v", latest, err)
	}
	none, err := r.LastVerified(ctx)
	if err != nil || len(none) != 0 {
		t.Fatalf("an unconfirmed return counts as a restart: %+v %v", none, err)
	}
	c, err := r.Insert(ctx, resetRow("srv-c", t0.Add(3*time.Hour)))
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Finish(ctx, c, BMCResetVerified, t0.Add(3*time.Hour+2*time.Minute), "", ""); err != nil {
		t.Fatal(err)
	}
	verified, err := r.LastVerified(ctx)
	if err != nil || len(verified) != 1 || verified[0].ID != c || verified[0].Detail != "" {
		t.Fatalf("verified %+v %v", verified, err)
	}
	n, err := r.Prune(ctx, t0.Add(30*time.Minute))
	if err != nil || n != 1 {
		t.Fatalf("prune %d %v", n, err)
	}
}

func TestBMCResetsRefuseBadRows(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := db.BMCResets()
	for name, edit := range map[string]func(*BMCResetRow){
		"force restart":   func(x *BMCResetRow) { x.ResetType = "ForceRestart" },
		"no server":       func(x *BMCResetRow) { x.ServerID = "" },
		"no requester":    func(x *BMCResetRow) { x.RequestedBy = "" },
		"unknown result":  func(x *BMCResetRow) { x.Result = "done" },
		"deadline":        func(x *BMCResetRow) { x.DeadlineAt = x.SentAt },
		"window > 15 min": func(x *BMCResetRow) { x.DeadlineAt = x.SentAt.Add(15*time.Minute + time.Millisecond) },
		"sent before":     func(x *BMCResetRow) { x.SentAt = x.RequestedAt.Add(-time.Second) },
		"detail":          func(x *BMCResetRow) { x.Detail = "free text" },
	} {
		row := resetRow("srv-a", t0)
		edit(&row)
		if _, err := r.Insert(ctx, row); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	id, err := r.Insert(ctx, resetRow("srv-a", t0))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Finish(ctx, id, BMCResetSent, time.Time{}, "", ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("finish as sent: %v", err)
	}
}
