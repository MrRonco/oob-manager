package notify

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/fleet"
	"oob-manager/internal/store"
)

var alice = admin.Actor{UserID: "u1", Username: "alice", Role: authz.RoleAdmin, IP: "192.0.2.5", Method: "local"}

type svcEnv struct {
	svc *Service
	db  *store.DB
	log *syncBuf
	now time.Time
	mu  sync.Mutex
}

func (e *svcEnv) clock() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now }

func (e *svcEnv) advance(d time.Duration) { e.mu.Lock(); e.now = e.now.Add(d); e.mu.Unlock() }

func newSvcEnv(t *testing.T, r *receiver, mod func(*Config)) *svcEnv {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	lg, buf := logBuffer()
	env := &svcEnv{db: db, log: buf, now: fixedNow}
	cfg := Config{DB: db, Audit: audit.NewLogger(db.Audit(), nil, env.clock, lg), Sealer: testSealer(t),
		Logger: lg, Now: env.clock, WatchEvery: time.Hour,
		Dispatch: DispatchConfig{Attempts: 1, RateBurst: 100}}
	if r != nil {
		cfg.Dispatch.Transport = transportFor(r)
	}
	if mod != nil {
		mod(&cfg)
	}
	env.svc, err = New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// run starts the service until the test ends.
func (e *svcEnv) run(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.svc.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

func (e *svcEnv) auditRows(t *testing.T) []store.AuditRecord {
	t.Helper()
	rows, err := e.db.Audit().List(context.Background(), 0, store.MaxAuditPage)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func (e *svcEnv) auditText(t *testing.T) string {
	var b strings.Builder
	for _, r := range e.auditRows(t) {
		b.WriteString(r.Action + " " + r.Result + " " + r.ErrorClass + " " + r.ParamsJSON + "\n")
	}
	return b.String()
}

func TestCreateUpdateDeleteAudited(t *testing.T) {
	r := newReceiver(t, true)
	env := newSvcEnv(t, r, nil)
	ctx := context.Background()
	tg := target(KindPushover, r.srv.URL+"/1/messages.json?app=topic-secret-part")
	tg.ID = "pager"
	if err := env.svc.Create(ctx, alice, tg, sec("APP-TOKEN-SECRET", "USER-KEY-SECRET", "")); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.Create(ctx, alice, tg, sec("x", "y", "")); !errors.Is(err, ErrExists) {
		t.Fatalf("duplicate: %v", err)
	}
	v, ok := env.svc.Target("pager")
	if !ok || !v.HasSecret || v.Target.SecretVersion != 1 || v.Target.Source != SourceDB {
		t.Fatalf("view: %+v", v)
	}
	// Blank secret fields keep the stored ones.
	tg.Name = "Pager duty"
	if err := env.svc.Update(ctx, alice, tg, Secrets{}, false); err != nil {
		t.Fatal(err)
	}
	if v, _ := env.svc.Target("pager"); v.Target.SecretVersion != 1 || v.Target.Name != "Pager duty" {
		t.Fatalf("after rename: %+v", v.Target)
	}
	// Replacing one secret bumps the version.
	if err := env.svc.Update(ctx, alice, tg, sec("NEW-APP-TOKEN", "", ""), false); err != nil {
		t.Fatal(err)
	}
	if v, _ := env.svc.Target("pager"); v.Target.SecretVersion != 2 {
		t.Fatalf("version %d", v.Target.SecretVersion)
	}
	// No change, no write.
	before := len(env.auditRows(t))
	if err := env.svc.Update(ctx, alice, tg, Secrets{}, false); err != nil || len(env.auditRows(t)) != before {
		t.Fatalf("no-op wrote: %v", err)
	}
	if err := env.svc.Delete(ctx, alice, "pager"); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.Delete(ctx, alice, "pager"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	text := env.auditText(t)
	for _, want := range []string{ActionTargetCreate, ActionTargetUpdate, ActionTargetDelete, `"[redacted] v1"`, `"field":"secrets"`} {
		if !strings.Contains(text, want) {
			t.Errorf("audit lacks %q:\n%s", want, text)
		}
	}
	assertNoLeak(t, env, text, "APP-TOKEN-SECRET", "USER-KEY-SECRET", "NEW-APP-TOKEN", "topic-secret-part")
}

func assertNoLeak(t *testing.T, env *svcEnv, auditText string, secrets ...string) {
	t.Helper()
	for _, s := range secrets {
		if strings.Contains(auditText, s) || strings.Contains(env.log.String(), s) {
			t.Errorf("%q reached the audit log or the app log", s)
		}
	}
	rows, err := env.db.Notify().Targets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		for _, s := range secrets {
			if strings.Contains(string(row.SecretEnc)+row.OptionsJSON+row.SubsJSON, s) {
				t.Errorf("%q stored in plaintext", s)
			}
		}
	}
}

func TestURLChangeRequiresSecretsAgain(t *testing.T) {
	r := newReceiver(t, true)
	env := newSvcEnv(t, r, nil)
	ctx := context.Background()
	tg := target(KindGotify, r.srv.URL+"/gotify")
	if err := env.svc.Create(ctx, alice, tg, sec("GOTIFY-TOKEN", "", "")); err != nil {
		t.Fatal(err)
	}
	moved := tg
	moved.URL = "https://push.example.net/gotify"
	if err := env.svc.Update(ctx, alice, moved, Secrets{}, false); !errors.Is(err, ErrInvalid) {
		t.Fatalf("secret carried to a new URL: %v", err)
	}
	if err := env.svc.Update(ctx, alice, moved, sec("OTHER-TOKEN", "", ""), false); err != nil {
		t.Fatal(err)
	}
	text := env.auditText(t)
	if !strings.Contains(text, "push.example.net") || strings.Contains(text, "/gotify") {
		t.Fatalf("destination change audit: %s", text)
	}
	// Optional secrets can be cleared.
	wh := target(KindWebhook, r.srv.URL+"/h")
	wh.ID = "hook"
	if err := env.svc.Create(ctx, alice, wh, sec("HMAC-KEY", "", "")); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.Update(ctx, alice, wh, Secrets{}, true); err != nil {
		t.Fatal(err)
	}
	if v, _ := env.svc.Target("hook"); v.HasSecret || v.Target.SecretVersion != 2 {
		t.Fatalf("cleared: %+v", v)
	}
}

func TestFileTargetsAreReadOnlyAndShadow(t *testing.T) {
	r := newReceiver(t, true)
	file := target(KindNtfy, r.srv.URL+"/file-topic")
	file.ID = "phone"
	env := newSvcEnv(t, r, func(c *Config) { c.File = []FileTarget{{Target: file, Secrets: sec("FILE-TOKEN", "", "")}} })
	ctx := context.Background()
	if err := env.svc.Update(ctx, alice, file, Secrets{}, false); !errors.Is(err, ErrLocked) {
		t.Fatalf("file target updated: %v", err)
	}
	if err := env.svc.Delete(ctx, alice, "phone"); !errors.Is(err, ErrLocked) {
		t.Fatalf("file target deleted: %v", err)
	}
	if err := env.svc.Create(ctx, alice, file, Secrets{}); !errors.Is(err, ErrExists) {
		t.Fatalf("shadowing create: %v", err)
	}
	if !strings.Contains(env.auditText(t), "denied locked") {
		t.Fatal("refusal not audited")
	}
	// A DB row with a file target's id (saved before the file gained it) is shadowed.
	row, _ := toRow(Target{ID: "phone", Name: "Old", Kind: KindNtfy, URL: "https://x.example.net/t", MinSeverity: SeverityInfo}, nil)
	row.CreatedAt, row.UpdatedAt, row.UpdatedBy = fixedNow, fixedNow, "alice"
	if err := env.db.Notify().PutTarget(ctx, row); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.reload(ctx); err != nil {
		t.Fatal(err)
	}
	if got := env.svc.Shadowed(); len(got) != 1 || got[0] != "phone" {
		t.Fatalf("shadowed %v", got)
	}
	if v, _ := env.svc.Target("phone"); v.Target.Source != SourceFile {
		t.Fatal("DB row won over the file")
	}
	locked := newSvcEnv(t, r, func(c *Config) { c.Locked = true })
	if err := locked.svc.Create(ctx, alice, target(KindNtfy, r.srv.URL+"/t"), Secrets{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked section: %v", err)
	}
}

func TestSendTestAuditsOutcome(t *testing.T) {
	r := newReceiver(t, true, 200, 401)
	env := newSvcEnv(t, r, nil)
	ctx := context.Background()
	tg := target(KindNtfy, r.srv.URL+"/t")
	if err := env.svc.Create(ctx, alice, tg, sec("TEST-TOKEN", "", "")); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.SendTest(ctx, alice, tg.ID); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.SendTest(ctx, alice, tg.ID); ErrorClass(err) != classHTTP4xx {
		t.Fatalf("second test: %v", err)
	}
	if err := env.svc.SendTest(ctx, alice, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	text := env.auditText(t)
	if !strings.Contains(text, ActionTargetTest+" ok") || !strings.Contains(text, ActionTargetTest+" error http_4xx") {
		t.Fatalf("audit:\n%s", text)
	}
	if v, _ := env.svc.Target(tg.ID); v.Status.LastError != classHTTP4xx || v.Status.LastSuccess.IsZero() {
		t.Fatalf("status %+v", v.Status)
	}
	if !strings.Contains(string(r.requests()[0].Body), "alice") {
		t.Fatal("test message does not name the sender")
	}
	assertNoLeak(t, env, text, "TEST-TOKEN")
}

func TestUnsealableSecretsAreReported(t *testing.T) {
	r := newReceiver(t, true)
	env := newSvcEnv(t, r, nil)
	ctx := context.Background()
	tg := target(KindNtfy, r.srv.URL+"/t")
	if err := env.svc.Create(ctx, alice, tg, sec("TOK", "", "")); err != nil {
		t.Fatal(err)
	}
	// Simulate a row moved to another URL behind the app's back.
	rows, _ := env.db.Notify().Targets(ctx)
	rows[0].URL = r.srv.URL + "/other"
	if err := env.db.Notify().PutTarget(ctx, rows[0]); err != nil {
		t.Fatal(err)
	}
	if err := env.svc.reload(ctx); err != nil {
		t.Fatal(err)
	}
	v, _ := env.svc.Target(tg.ID)
	if !v.SecretError || !v.HasSecret {
		t.Fatalf("view %+v", v)
	}
	if err := env.svc.SendTest(ctx, alice, tg.ID); ErrorClass(err) != classSecrets || r.count() != 0 {
		t.Fatalf("send with unopened secrets: %v", err)
	}
}

// fakeFleet serves fixed states.
type fakeFleet struct {
	mu     sync.Mutex
	states []fleet.ServerState
}

func (f *fakeFleet) set(s ...fleet.ServerState) { f.mu.Lock(); f.states = s; f.mu.Unlock() }
func (f *fakeFleet) Servers() []fleet.ServerState {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]fleet.ServerState(nil), f.states...)
}
func (f *fakeFleet) Server(string) (fleet.ServerState, bool) { return fleet.ServerState{}, false }
func (f *fakeFleet) Polled() bool                            { return true }

func TestSubscriptionFilter(t *testing.T) {
	tg := Target{ID: "x", Enabled: true, Classes: []Class{ClassHealth}, MinSeverity: SeverityCritical}
	e := testEvent()
	if !tg.Wants(e) {
		t.Fatal("subscribed class at severity refused")
	}
	e.Severity = SeverityWarning
	if tg.Wants(e) {
		t.Fatal("below minimum severity accepted")
	}
	e.Severity, e.Recovery = SeverityCritical, true
	if !tg.Wants(e) {
		t.Fatal("recovery of a critical problem refused")
	}
	e.Class = ClassPower
	if tg.Wants(e) {
		t.Fatal("unsubscribed class accepted")
	}
	tg.Enabled = false
	if tg.Wants(testEvent()) {
		t.Fatal("disabled target accepted")
	}
}

func TestWatchLoopAndSelfAlert(t *testing.T) {
	good := newReceiver(t, true)
	bad := newReceiver(t, true, http500)
	ff := &fakeFleet{}
	env := newSvcEnv(t, good, func(c *Config) {
		c.Fleet, c.WatchEvery, c.Debounce = ff, 5*time.Millisecond, time.Nanosecond
		c.Dispatch.Transport.TLS.RootCAs.AddCert(bad.srv.Certificate())
		c.Dispatch.FailAfter = 1
	})
	ctx := context.Background()
	gt := target(KindWebhook, good.srv.URL+"/good")
	gt.ID = "good"
	bt := target(KindWebhook, bad.srv.URL+"/bad")
	bt.ID, bt.Name = "bad", "Broken hook"
	for _, tg := range []Target{gt, bt} {
		if err := env.svc.Create(ctx, alice, tg, Secrets{}); err != nil {
			t.Fatal(err)
		}
	}
	env.run(t)
	ff.set(healthy(fixedNow, withHealth("Critical")))
	waitFor(t, "health event and self-alert", func() bool { env.advance(time.Second); return good.count() >= 2 })
	var classes []string
	for _, c := range good.requests() {
		classes = append(classes, c.Header.Get(HeaderEvent))
	}
	if strings.Join(classes, ",") != "health,notify" {
		t.Fatalf("good target got %v", classes)
	}
	if got := env.svc.Failing(); len(got) != 1 || got[0] != "Broken hook" {
		t.Fatalf("failing %v", got)
	}
	if bad.count() != 1 {
		t.Fatalf("the failing target got its own self-alert (%d requests)", bad.count())
	}
}

const http500 = 500
