package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func serverRow(id string) ServerRow {
	return ServerRow{ID: id, Name: "Edge " + id, Tags: []string{"lab"}, Kind: "idrac9", Address: "192.0.2.12", Port: 443,
		TLSPin: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", FanMode: "none",
		ConsoleSerial: "none", ConsoleGraphical: "none", VNCPort: 5901, SSHPort: 22, PowerImpact: []string{},
		CreatedAt: t0, CreatedBy: "alice", UpdatedAt: t0, UpdatedBy: "alice"}
}

func TestServerRows(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	r := db.Servers()
	if rows, err := r.All(ctx); err != nil || len(rows) != 0 {
		t.Fatalf("empty: %v %v", rows, err)
	}
	a := serverRow("edge1")
	a.PowerImpact = []string{"Gateway: internet drops"}
	a.PollInterval = 90 * time.Second
	a.FanMode, a.FanSafeMinPct, a.FanMaxLease = "redfish-floor", 41, time.Hour
	if err := r.Insert(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := r.Insert(ctx, a); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate id: %v", err)
	}
	got, err := r.Get(ctx, "edge1")
	if err != nil || got.Rev != 1 || got.Enabled || got.PollInterval != 90*time.Second || got.FanMaxLease != time.Hour ||
		len(got.PowerImpact) != 1 || got.Tags[0] != "lab" || !got.CreatedAt.Equal(t0) {
		t.Fatalf("get = %+v %v", got, err)
	}
	got.Name, got.Enabled, got.UpdatedBy = "Edge one", true, "bob"
	if err = r.Update(ctx, got, 1); err != nil {
		t.Fatal(err)
	}
	if err = r.Update(ctx, got, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale rev: %v", err)
	}
	if err = r.Update(ctx, serverRow("ghost"), 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	again, _ := r.Get(ctx, "edge1")
	if again.Rev != 2 || again.Name != "Edge one" || !again.Enabled || again.UpdatedBy != "bob" || again.CreatedBy != "alice" {
		t.Fatalf("after update: %+v", again)
	}
	if _, err = r.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	if err = r.Insert(ctx, serverRow("edge0")); err != nil {
		t.Fatal(err)
	}
	if rows, _ := r.All(ctx); len(rows) != 2 || rows[0].ID != "edge0" {
		t.Fatalf("All order: %+v", rows)
	}
	if err = r.Delete(ctx, "edge1", 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("delete stale: %v", err)
	}
	if err = r.Delete(ctx, "edge1", 2); err != nil {
		t.Fatal(err)
	}
	if err = r.Delete(ctx, "edge1", 2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}

func TestServerRowRejects(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	for name, mut := range map[string]func(*ServerRow){
		"kind":      func(r *ServerRow) { r.Kind = "ilo" },
		"port":      func(r *ServerRow) { r.Port = 70000 },
		"pin":       func(r *ServerRow) { r.TLSPin = "abc" },
		"fan mode":  func(r *ServerRow) { r.FanMode = "turbo" },
		"fan floor": func(r *ServerRow) { r.FanSafeMinPct = 5 },
		"serial":    func(r *ServerRow) { r.ConsoleSerial = "telnet" },
		"author":    func(r *ServerRow) { r.CreatedBy = "" },
		"long id":   func(r *ServerRow) { r.ID = "a234567890123456789012345678901234" },
	} {
		row := serverRow("x1")
		mut(&row)
		if err := db.Servers().Insert(ctx, row); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestCredentialRows(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := db.Servers().Insert(ctx, serverRow("edge1")); err != nil {
		t.Fatal(err)
	}
	v, err := db.Servers().NextCredVersion(ctx, "edge1")
	if err != nil || v != 1 {
		t.Fatalf("version = %d %v", v, err)
	}
	if v, _ = db.Servers().NextCredVersion(ctx, "edge1"); v != 2 {
		t.Fatalf("second version = %d", v)
	}
	if _, err = db.Servers().NextCredVersion(ctx, "ghost"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ghost: %v", err)
	}
	c := db.Credentials()
	row := CredentialRow{ServerID: "edge1", Slot: "readonly", Version: 2, KeyID: "v1", SecretEnc: make([]byte, 40),
		CreatedAt: t0, CreatedBy: "alice"}
	if err = c.Put(ctx, row); err != nil {
		t.Fatal(err)
	}
	row.Version, row.CreatedBy = 3, "bob"
	if err = c.Put(ctx, row); err != nil {
		t.Fatal(err)
	}
	op := row
	op.Slot = "operator"
	if err = c.Put(ctx, op); err != nil {
		t.Fatal(err)
	}
	rows, err := c.List(ctx, "edge1")
	if err != nil || len(rows) != 2 || rows[0].Slot != "operator" || rows[1].Version != 3 || rows[1].CreatedBy != "bob" ||
		len(rows[1].SecretEnc) != 40 {
		t.Fatalf("list = %+v %v", rows, err)
	}
	if all, _ := c.All(ctx); len(all) != 2 {
		t.Fatalf("all = %d", len(all))
	}
	bad := row
	bad.Slot = "root"
	if err = c.Put(ctx, bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad slot: %v", err)
	}
	orphan := row
	orphan.ServerID = "ghost"
	if err = c.Put(ctx, orphan); !errors.Is(err, ErrInvalid) {
		t.Fatalf("orphan: %v", err)
	}
	if n, derr := c.DeleteAll(ctx, "edge1"); derr != nil || n != 2 {
		t.Fatalf("delete all = %d %v", n, derr)
	}
	// Deleting a server deletes its credentials (ON DELETE CASCADE).
	if err = c.Put(ctx, row); err != nil {
		t.Fatal(err)
	}
	if err = db.Servers().Delete(ctx, "edge1", 1); err != nil {
		t.Fatal(err)
	}
	if all, _ := c.All(ctx); len(all) != 0 {
		t.Fatalf("cascade left %d rows", len(all))
	}
}

func TestServersInTx(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	boom := errors.New("boom")
	err := db.WithTx(ctx, func(tx *Tx) error {
		if err := tx.Servers().Insert(ctx, serverRow("edge1")); err != nil {
			return err
		}
		if err := tx.Credentials().Put(ctx, CredentialRow{ServerID: "edge1", Slot: "vnc", Version: 1, KeyID: "v1",
			SecretEnc: make([]byte, 20), CreatedAt: t0, CreatedBy: "a"}); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if rows, _ := db.Servers().All(ctx); len(rows) != 0 {
		t.Fatal("rolled-back insert visible")
	}
}
