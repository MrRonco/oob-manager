package maint

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/notify"
	"oob-manager/internal/store"
)

var t0 = time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

var (
	alice = admin.Actor{UserID: "u-alice", Username: "alice", Role: authz.RoleOperator, IP: "192.0.2.5", Method: "local"}
	bob   = admin.Actor{UserID: "u-bob", Username: "bob", Role: authz.RoleOperator, IP: "192.0.2.6", Method: "local"}
	root  = admin.Actor{UserID: "u-root", Username: "root", Role: authz.RoleAdmin, IP: "192.0.2.7", Method: "local"}
)

type env struct {
	t    *testing.T
	db   *store.DB
	svc  *Service
	mu   sync.Mutex
	now  time.Time
	sent []notify.Event
	path string
}

func (e *env) clock() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }

func (e *env) advance(d time.Duration) { e.mu.Lock(); e.now = e.now.Add(d); e.mu.Unlock() }

func (e *env) events() []notify.Event {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]notify.Event(nil), e.sent...)
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, now: t0, path: filepath.Join(t.TempDir(), "m.db")}
	db, err := store.Open(context.Background(), e.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	e.db = db
	e.svc = e.open()
	return e
}

func (e *env) open() *Service {
	e.t.Helper()
	svc, err := New(context.Background(), Config{DB: e.db, Audit: audit.NewLogger(e.db.Audit(), nil, e.clock, quiet()),
		Emit:       func(ev notify.Event) { e.mu.Lock(); e.sent = append(e.sent, ev); e.mu.Unlock() },
		ServerName: func(id string) string { return map[string]string{"srv-a": "Storage node"}[id] },
		Logger:     quiet(), Now: e.clock})
	if err != nil {
		e.t.Fatal(err)
	}
	return svc
}

func (e *env) audit() []store.AuditRecord {
	e.t.Helper()
	rows, err := e.db.Audit().List(context.Background(), 0, store.MaxAuditPage)
	if err != nil {
		e.t.Fatal(err)
	}
	return rows
}

func (e *env) auditText() string {
	var b strings.Builder
	for _, r := range e.audit() {
		b.WriteString(r.Principal + " " + r.ServerID + " " + r.Action + " " + r.ParamsJSON + "\n")
	}
	return b.String()
}

func TestMaintenanceLifecycle(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	w, err := e.svc.Start(ctx, alice, "srv-a", StartRequest{Reason: "  PSU swap  ", Duration: 4 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if w.Reason != "PSU swap" || !w.EndsAt.Equal(t0.Add(4*time.Hour)) || !w.Notified || w.By != "alice" {
		t.Fatalf("window %+v", w)
	}
	if got, ok := e.svc.Active("srv-a"); !ok || got.Reason != "PSU swap" {
		t.Fatal("not active")
	}
	if !e.svc.InMaintenance("srv-a", t0) || e.svc.InMaintenance("srv-b", t0) || e.svc.InMaintenance("srv-a", t0.Add(5*time.Hour)) {
		t.Fatal("InMaintenance")
	}
	if _, err := e.svc.Start(ctx, bob, "srv-a", StartRequest{Reason: "again"}); !errors.Is(err, ErrExists) {
		t.Fatalf("second window: %v", err)
	}
	evs := e.events()
	if len(evs) != 1 || evs[0].Class != notify.ClassMaintenance || evs[0].Recovery || evs[0].ServerName != "Storage node" {
		t.Fatalf("started notification %+v", evs)
	}
	// Survives a restart.
	if w2, ok := e.open().Active("srv-a"); !ok || !w2.Notified || !w2.EndsAt.Equal(w.EndsAt) {
		t.Fatal("window not persisted")
	}
	if err := e.svc.End(ctx, bob, "srv-a"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.End(ctx, bob, "srv-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second end: %v", err)
	}
	if evs = e.events(); len(evs) != 2 || !evs[1].Recovery || !strings.Contains(evs[1].Message, "ended by bob") {
		t.Fatalf("ended notification %+v", evs)
	}
	text := e.auditText()
	for _, want := range []string{`alice srv-a server.maintenance.start {"minutes":240,"reason":"PSU swap","until":"2026-10-21T13:00:00Z"}`,
		`bob srv-a server.maintenance.end {"reason":"ended","window_reason":"PSU swap"}`} {
		if !strings.Contains(text, want) {
			t.Fatalf("audit lacks %s:\n%s", want, text)
		}
	}
}

func TestMaintenanceUntilEndedAndExpiry(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	open, err := e.svc.Start(ctx, alice, "srv-b", StartRequest{Reason: "rack move"})
	if err != nil || !open.UntilEnded() {
		t.Fatalf("until ended: %+v %v", open, err)
	}
	if _, err := e.svc.Start(ctx, alice, "srv-a", StartRequest{Reason: "short", Duration: 30 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	e.advance(31 * time.Minute)
	if _, ok := e.svc.Window("srv-a"); ok {
		t.Fatal("expired window still returned before Run")
	}
	if e.svc.InMaintenance("srv-a", e.clock()) {
		t.Fatal("expired window suppresses")
	}
	e.svc.Tick(ctx)
	e.svc.Tick(ctx) // idempotent
	evs := e.events()
	if len(evs) != 3 || !evs[2].Recovery || !strings.Contains(evs[2].Message, "expired") {
		t.Fatalf("expiry notification %+v", evs)
	}
	if !strings.Contains(e.auditText(), `system srv-a server.maintenance.end {"reason":"expired","window_reason":"short"}`) {
		t.Fatalf("expiry audit:\n%s", e.auditText())
	}
	e.advance(30 * 24 * time.Hour)
	e.svc.Tick(ctx)
	if _, ok := e.svc.Active("srv-b"); !ok {
		t.Fatal("an until-ended window expired")
	}
}

func TestScheduledWindow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	w, err := e.svc.Start(ctx, alice, "srv-a", StartRequest{Reason: "firmware", Duration: time.Hour, StartsAt: t0.Add(2 * time.Hour)})
	if err != nil || w.Notified || !w.ScheduledAt(t0) || !w.EndsAt.Equal(t0.Add(3*time.Hour)) {
		t.Fatalf("scheduled %+v %v", w, err)
	}
	if _, ok := e.svc.Active("srv-a"); ok || e.svc.InMaintenance("srv-a", t0) {
		t.Fatal("scheduled window active early")
	}
	if !strings.Contains(e.auditText(), `"starts":"2026-10-21T11:00:00Z"`) {
		t.Fatalf("schedule audit:\n%s", e.auditText())
	}
	e.svc.Tick(ctx)
	if len(e.events()) != 0 {
		t.Fatal("notified before the start")
	}
	e.advance(2 * time.Hour)
	e.svc.Tick(ctx)
	e.svc.Tick(ctx)
	if evs := e.events(); len(evs) != 1 || evs[0].Recovery {
		t.Fatalf("start notification %+v", evs)
	}
	if w, ok := e.open().Active("srv-a"); !ok || !w.Notified {
		t.Fatal("start not recorded")
	}
	// A scheduled window removed before it began is cancelled, without a message.
	if _, err := e.svc.Start(ctx, alice, "srv-c", StartRequest{Reason: "later", StartsAt: e.clock().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.End(ctx, bob, "srv-c"); err != nil {
		t.Fatal(err)
	}
	if len(e.events()) != 1 || !strings.Contains(e.auditText(), `"reason":"cancelled"`) {
		t.Fatalf("cancel: %+v\n%s", e.events(), e.auditText())
	}
}

func TestStartReplacesExpiredWindow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if _, err := e.svc.Start(ctx, alice, "srv-a", StartRequest{Reason: "one", Duration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	e.advance(2 * time.Hour) // Run has not seen the expiry yet
	if _, err := e.svc.Start(ctx, bob, "srv-a", StartRequest{Reason: "two", Duration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(e.auditText(), "server.maintenance.end"); n != 1 || len(e.events()) != 3 {
		t.Fatalf("expired window not closed first (%d ends, %d events)", n, len(e.events()))
	}
}

func TestStartValidation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for name, req := range map[string]StartRequest{
		"no reason":   {Reason: "  "},
		"multi-line":  {Reason: "a\nb"},
		"long reason": {Reason: strings.Repeat("é", 201)},
		"too short":   {Reason: "r", Duration: time.Minute},
		"too long":    {Reason: "r", Duration: 8 * 24 * time.Hour},
		"in the past": {Reason: "r", StartsAt: t0.Add(-time.Hour)},
		"too far":     {Reason: "r", StartsAt: t0.Add(31 * 24 * time.Hour)},
	} {
		if _, err := e.svc.Start(ctx, alice, "srv-a", req); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := e.svc.Start(ctx, alice, "", StartRequest{Reason: "r"}); !errors.Is(err, ErrInvalid) {
		t.Errorf("no server: %v", err)
	}
	if _, err := e.svc.Start(ctx, alice, "srv-a", StartRequest{Reason: strings.Repeat("é", 200), Duration: MaxWindow}); err != nil {
		t.Errorf("limits are inclusive: %v", err)
	}
	if len(e.audit()) != 1 {
		t.Fatal("refused input was audited")
	}
}

func TestSyncServersRemovesWindowsOfDeletedServers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for _, id := range []string{"srv-a", "srv-b"} {
		if _, err := e.svc.Start(ctx, alice, id, StartRequest{Reason: "work", Duration: time.Hour}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.AddNote(ctx, alice, "srv-b", "kept"); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.SyncServers(ctx, []string{"srv-a", "srv-b"}); err != nil || len(e.audit()) != 3 {
		t.Fatalf("no-op sync: %v", err)
	}
	if err := e.svc.SyncServers(ctx, []string{"srv-a"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := e.svc.Window("srv-b"); ok {
		t.Fatal("removed server still in maintenance")
	}
	if _, ok := e.svc.Window("srv-a"); !ok {
		t.Fatal("known server lost its window")
	}
	if len(e.svc.Notes("srv-b")) != 1 {
		t.Fatal("notes of a removed server are kept")
	}
	if !strings.Contains(e.auditText(), `system srv-b server.maintenance.end {"reason":"server_removed"}`) {
		t.Fatalf("audit:\n%s", e.auditText())
	}
}

func TestWithoutDatabase(t *testing.T) {
	svc, err := New(context.Background(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if svc.Available() {
		t.Fatal("available without a DB")
	}
	if _, err := svc.Start(ctx, alice, "srv-a", StartRequest{Reason: "r"}); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("start: %v", err)
	}
	if _, err := svc.AddNote(ctx, alice, "srv-a", "n"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("note: %v", err)
	}
	svc.Tick(ctx)
	if err := svc.SyncServers(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := New(ctx, Config{DB: &store.DB{}}); err == nil {
		t.Fatal("DB without audit accepted")
	}
}

func TestRunEndsExpiredWindows(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	if _, err := e.svc.Start(ctx, alice, "srv-a", StartRequest{Reason: "r", Duration: time.Hour}); err != nil {
		t.Fatal(err)
	}
	e.advance(2 * time.Hour)
	e.svc.cfg.Every = time.Millisecond
	done := make(chan struct{})
	go func() { e.svc.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(e.events()) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
	if len(e.events()) != 2 {
		t.Fatalf("Run did not end the window: %+v", e.events())
	}
}
