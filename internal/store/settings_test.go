package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSettingsRowsAndRev(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	s := db.Settings()
	if rows, err := s.All(ctx); err != nil || len(rows) != 0 {
		t.Fatalf("All on empty = %v, %v", rows, err)
	}
	if rev, err := s.Rev(ctx); err != nil || rev != 0 {
		t.Fatalf("Rev = %d, %v", rev, err)
	}
	row := SettingRow{Key: "ui.time_zone", ValueJSON: `"America/New_York"`, UpdatedAt: t0, UpdatedBy: "alice"}
	if err := s.Put(ctx, row); err != nil {
		t.Fatal(err)
	}
	row.ValueJSON = `"Europe/Paris"`
	if err := s.Put(ctx, row); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, SettingRow{Key: "auth.session_idle", ValueJSON: `"30m0s"`, UpdatedAt: t0, UpdatedBy: "alice"}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.All(ctx)
	if err != nil || len(rows) != 2 || rows[0].Key != "auth.session_idle" || rows[1].ValueJSON != `"Europe/Paris"` ||
		!rows[1].UpdatedAt.Equal(t0) || rows[1].UpdatedBy != "alice" {
		t.Fatalf("All = %+v, %v", rows, err)
	}
	if derr := s.Delete(ctx, "auth.session_idle"); derr != nil {
		t.Fatal(derr)
	}
	if rows, _ := s.All(ctx); len(rows) != 1 {
		t.Fatalf("after delete: %+v", rows)
	}
	next, err := s.BumpRev(ctx, 0)
	if err != nil || next != 1 {
		t.Fatalf("BumpRev = %d, %v", next, err)
	}
	if _, err := s.BumpRev(ctx, 0); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale rev err = %v", err)
	}
}

func TestSettingsRejects(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	s := db.Settings()
	for name, row := range map[string]SettingRow{
		"unknown key": {Key: "listen", ValueJSON: `":1"`, UpdatedAt: t0, UpdatedBy: "a"},
		"bad json":    {Key: "ui.theme", ValueJSON: `{`, UpdatedAt: t0, UpdatedBy: "a"},
		"no author":   {Key: "ui.theme", ValueJSON: `"nord"`, UpdatedAt: t0},
	} {
		if err := s.Put(ctx, row); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestSettingsInTx(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	boom := errors.New("boom")
	err := db.WithTx(ctx, func(tx *Tx) error {
		if err := tx.Settings().Put(ctx, SettingRow{Key: "ui.theme", ValueJSON: `"nord"`, UpdatedAt: t0, UpdatedBy: "a"}); err != nil {
			return err
		}
		if _, err := tx.Settings().BumpRev(ctx, 0); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if rows, _ := db.Settings().All(ctx); len(rows) != 0 {
		t.Fatal("rolled-back row persisted")
	}
	if rev, _ := db.Settings().Rev(ctx); rev != 0 {
		t.Fatal("rolled-back rev persisted")
	}
}

func TestUserPrefs(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	mustCreateUser(t, db, "u1", "alice", RoleViewer)
	p := db.Prefs()
	got, err := p.Get(ctx, "u1")
	if err != nil || got != (UserPrefs{UserID: "u1"}) {
		t.Fatalf("Get none = %+v, %v", got, err)
	}
	want := UserPrefs{UserID: "u1", TimeZone: "Asia/Tokyo", Theme: "nord", DateFormat: "us", Clock: "12h",
		TempUnit: "f", Density: "comfortable", UpdatedAt: t0}
	if perr := p.Put(ctx, want); perr != nil {
		t.Fatal(perr)
	}
	if got, err = p.Get(ctx, "u1"); err != nil || got != want {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	cleared := UserPrefs{UserID: "u1", UpdatedAt: t0.Add(time.Minute)}
	if err := db.WithTx(ctx, func(tx *Tx) error { return tx.Prefs().Put(ctx, cleared) }); err != nil {
		t.Fatal(err)
	}
	if got, _ = p.Get(ctx, "u1"); got != cleared {
		t.Fatalf("cleared = %+v", got)
	}
	if err := p.Put(ctx, UserPrefs{UserID: "u1", DateFormat: "eu", UpdatedAt: t0}); err == nil {
		t.Fatal("bad date format accepted by the CHECK")
	}
	if err := p.Put(ctx, UserPrefs{UserID: "ghost", UpdatedAt: t0}); err == nil {
		t.Fatal("prefs for a missing user accepted")
	}
	if err := p.Put(ctx, UserPrefs{UpdatedAt: t0}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing user id err = %v", err)
	}
}

func TestSettingsDisplayDefaultKeys(t *testing.T) {
	db := newTestDB(t)
	for _, k := range []string{"ui.clock_format", "ui.date_format", "ui.temperature_unit", "ui.density"} {
		if err := db.Settings().Put(context.Background(), SettingRow{Key: k, ValueJSON: `"x"`, UpdatedAt: t0, UpdatedBy: "a"}); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
}
