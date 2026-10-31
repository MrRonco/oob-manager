package store

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// hashA and hashB are two SHA-256 hex digests (the subject hash of an acceptance).
var hashA, hashB = strings.Repeat("ab", 32), strings.Repeat("cd", 32)

func acceptRow(check string) SecurityAcceptRow {
	return SecurityAcceptRow{ServerID: "srv-a", ServerAddr: "192.0.2.10:443", CheckID: check, Result: "warn", Subject: "on",
		SubjectHash: hashA, Comment: "needed by the UPS", AcceptedBy: "alice", AcceptedAt: t0}
}

func TestSecurityAccepts(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := db.Security()
	a := acceptRow("svc.ipmi")
	if err := r.PutAccept(ctx, a); err != nil {
		t.Fatal(err)
	}
	// Accepting again replaces everything the admin saw: subject, hash, address, comment, who.
	a.Comment, a.AcceptedBy, a.Subject, a.SubjectHash, a.ServerAddr = "still needed", "bob", "on (again)", hashB, "192.0.2.10:8443"
	if err := r.PutAccept(ctx, a); err != nil {
		t.Fatal(err)
	}
	b := acceptRow("tls.cert_expiry")
	b.Result, b.Subject = "fail", strings.Repeat("ab", 32)
	if err := r.PutAccept(ctx, b); err != nil {
		t.Fatal(err)
	}
	got, err := r.Accepts(ctx)
	if err != nil || len(got) != 2 || got[0].CheckID != "svc.ipmi" || got[0].Comment != "still needed" || got[0].AcceptedBy != "bob" ||
		got[0].Subject != "on (again)" || got[0].SubjectHash != hashB || got[0].ServerAddr != "192.0.2.10:8443" ||
		!got[0].AcceptedAt.Equal(t0) || got[1].Result != "fail" || got[1].SubjectHash != hashA {
		t.Fatalf("accepts %+v %v", got, err)
	}
	for name, tweak := range map[string]func(*SecurityAcceptRow){
		"result":            func(x *SecurityAcceptRow) { x.Result = "pass" },
		"empty comment":     func(x *SecurityAcceptRow) { x.Comment = "" },
		"long comment":      func(x *SecurityAcceptRow) { x.Comment = strings.Repeat("c", 501) },
		"long subject":      func(x *SecurityAcceptRow) { x.Subject = strings.Repeat("s", 257) },
		"short hash":        func(x *SecurityAcceptRow) { x.SubjectHash = hashA[:63] },
		"empty hash":        func(x *SecurityAcceptRow) { x.SubjectHash = "" },
		"empty server addr": func(x *SecurityAcceptRow) { x.ServerAddr = "" },
		"long server addr":  func(x *SecurityAcceptRow) { x.ServerAddr = strings.Repeat("1", 65) },
		"empty server":      func(x *SecurityAcceptRow) { x.ServerID = "" },
		"empty who":         func(x *SecurityAcceptRow) { x.AcceptedBy = "" },
	} {
		bad := acceptRow("x.y")
		tweak(&bad)
		if err := r.PutAccept(ctx, bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: CHECK let %+v through: %v", name, bad, err)
		}
	}
	if err := r.DeleteAccept(ctx, "srv-a", "svc.ipmi"); err != nil {
		t.Fatal(err)
	}
	if err := r.DeleteAccept(ctx, "srv-a", "svc.ipmi"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	werr := db.WithTx(ctx, func(tx *Tx) error { return tx.Security().DeleteAccept(ctx, "srv-a", "tls.cert_expiry") })
	if got, _ := r.Accepts(ctx); werr != nil || len(got) != 0 {
		t.Fatalf("delete in tx: %v %+v", werr, got)
	}
}

func TestSecurityNotifiedIsReplacedPerServer(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := db.Security()
	rows := []SecurityNotifiedRow{
		{ServerID: "srv-a", Item: "f:svc.ipmi", Value: "warn|abc", NotifiedAt: t0},
		{ServerID: "srv-a", Item: "cert:443", Value: "def|14", NotifiedAt: t0},
	}
	if err := r.SetNotified(ctx, "srv-a", rows); err != nil {
		t.Fatal(err)
	}
	if err := r.SetNotified(ctx, "srv-b", []SecurityNotifiedRow{{ServerID: "srv-b", Item: "f:svc.telnet", Value: "fail|x", NotifiedAt: t0}}); err != nil {
		t.Fatal(err)
	}
	if err := r.SetNotified(ctx, "srv-a", rows[:1]); err != nil {
		t.Fatal(err)
	}
	got, err := r.Notified(ctx)
	if err != nil || len(got) != 2 || got[0].ServerID != "srv-a" || got[0].Item != "f:svc.ipmi" || got[1].ServerID != "srv-b" ||
		!got[0].NotifiedAt.Equal(t0) {
		t.Fatalf("notified %+v %v", got, err)
	}
	if err := r.SetNotified(ctx, "srv-a", []SecurityNotifiedRow{{ServerID: "srv-b", Item: "f:x", Value: "v"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("rows of another server: %v", err)
	}
	if err := r.SetNotified(ctx, "srv-a", []SecurityNotifiedRow{{ServerID: "srv-a", Item: "", Value: "v"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty item: %v", err)
	}
	if got, _ := r.Notified(ctx); len(got) != 2 {
		t.Fatalf("a refused replace changes nothing: %+v", got)
	}
	if err := r.SetNotified(ctx, "srv-a", nil); err != nil {
		t.Fatal(err)
	}
	if got, _ := r.Notified(ctx); len(got) != 1 || got[0].ServerID != "srv-b" {
		t.Fatalf("cleared %+v", got)
	}
}

// TestSecurityDeleteServer: removing a server drops its acceptances and notification
// state, in the caller's transaction, and leaves other servers' rows alone.
func TestSecurityDeleteServer(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := db.Security()
	for _, id := range []string{"srv-a", "srv-b"} {
		a := acceptRow("svc.ipmi")
		a.ServerID = id
		if err := r.PutAccept(ctx, a); err != nil {
			t.Fatal(err)
		}
		if err := r.SetNotified(ctx, id, []SecurityNotifiedRow{{ServerID: id, Item: "f:svc.ipmi", Value: "warn|x", NotifiedAt: t0}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.WithTx(ctx, func(tx *Tx) error { return tx.Security().DeleteServer(ctx, "srv-a") }); err != nil {
		t.Fatal(err)
	}
	accepts, _ := r.Accepts(ctx)
	notified, _ := r.Notified(ctx)
	if len(accepts) != 1 || accepts[0].ServerID != "srv-b" || len(notified) != 1 || notified[0].ServerID != "srv-b" {
		t.Fatalf("after delete: %+v %+v", accepts, notified)
	}
	if err := r.DeleteServer(ctx, "nobody"); err != nil {
		t.Fatalf("a server without rows: %v", err)
	}
}
