package settings

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/config"
	"oob-manager/internal/display"
	"oob-manager/internal/store"
)

var t0 = time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

const baseYAML = `tls: { cert_file: /c, key_file: /k }
public_url: https://oob.example.test
servers:
  - id: s1
    name: One
    bmc: { address: 192.0.2.10, kind: idrac9 }
    tls_pin_sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    credentials: { readonly: s1-ro }
`

func parse(t *testing.T, extra string) config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(extra + baseYAML))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

type fixture struct {
	db    *store.DB
	svc   *Service
	actor admin.Actor
}

func newFixture(t *testing.T, extraYAML string) *fixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if cerr := db.Users().Create(ctx, store.User{ID: "u1", Username: "alice", Role: store.RoleAdmin, PwHash: "x",
		CreatedAt: t0}); cerr != nil {
		t.Fatal(cerr)
	}
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	lg := audit.NewLogger(db.Audit(), nil, func() time.Time { return t0 }, quiet)
	svc, err := New(ctx, Config{DB: db, Audit: lg, File: parse(t, extraYAML), Now: func() time.Time { return t0 }, Logger: quiet})
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{db: db, svc: svc, actor: admin.Actor{UserID: "u1", Username: "alice", Role: authz.RoleAdmin,
		IP: "192.0.2.1", Method: "local"}}
}

// auditRows returns the audit rows with the given action, oldest first.
func (f *fixture) auditRows(t *testing.T, action string) []store.AuditRecord {
	t.Helper()
	recs, err := f.db.AuditSearch().Search(context.Background(), store.AuditFilter{Action: action, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func TestResolvePrecedence(t *testing.T) {
	file := parse(t, "ui: { time_zone: Europe/Paris }\n")
	rows := []store.SettingRow{
		{Key: config.KeyTimeZone, ValueJSON: `"Asia/Tokyo"`, UpdatedAt: t0, UpdatedBy: "a"},   // shadowed
		{Key: config.KeyTheme, ValueJSON: `"nord"`, UpdatedAt: t0, UpdatedBy: "bob"},          // db
		{Key: config.KeySessionIdle, ValueJSON: `"3h0m0s"`, UpdatedAt: t0, UpdatedBy: "a"},    // out of bounds
		{Key: config.KeyLoginIPPerMin, ValueJSON: `"seven"`, UpdatedAt: t0, UpdatedBy: "a"},   // unreadable
		{Key: "gelf.address", ValueJSON: `"192.0.2.5:12201"`, UpdatedAt: t0, UpdatedBy: "a"},  // not this section
		{Key: config.KeyStepUpWindow, ValueJSON: `"2m0s"`, UpdatedAt: t0, UpdatedBy: "carol"}, // db
	}
	e := Resolve(file, rows, 7)
	if e.General.TimeZone != "Europe/Paris" || e.General.Theme != "nord" || e.General.SessionIdle != 30*time.Minute ||
		e.General.LoginIPPerMin != 5 || e.General.StepUpWindow != 2*time.Minute || e.Rev != 7 {
		t.Fatalf("General = %+v", e.General)
	}
	if len(e.Ignored) != 3 {
		t.Fatalf("Ignored = %v", e.Ignored)
	}
	want := map[string]Source{config.KeyTimeZone: SourceFile, config.KeyTheme: SourceDB,
		config.KeySessionIdle: SourceDefault, config.KeyStepUpWindow: SourceDB, config.KeyPollInterval: SourceDefault}
	for k, src := range want {
		f, ok := e.Field(k)
		if !ok || f.Source != src {
			t.Errorf("%s source = %v", k, f.Source)
		}
	}
	if f, _ := e.Field(config.KeyTheme); f.UpdatedBy != "bob" || !f.UpdatedAt.Equal(t0) || f.Value != "nord" {
		t.Errorf("theme field = %+v", f)
	}
	if e.Editable(config.KeyTimeZone) || !e.Editable(config.KeyTheme) || e.Editable("nope") {
		t.Fatal("Editable wrong")
	}
	if _, ok := e.Field("nope"); ok {
		t.Fatal("unknown field found")
	}
	if len(e.Fields()) != len(config.GeneralKeys()) {
		t.Fatal("Fields incomplete")
	}
}

func TestResolveLockedSection(t *testing.T) {
	e := Resolve(parse(t, "settings: { locked: [general] }\n"), nil, 0)
	if !e.Locked || e.Editable(config.KeyTheme) {
		t.Fatal("locked section editable")
	}
}

func TestSpecDisplayAndParse(t *testing.T) {
	poll, _ := specFor(config.KeyPollInterval)
	if got := poll.display(value{d: 90 * time.Second}); got != "90" {
		t.Fatalf("display = %q", got)
	}
	step, _ := specFor(config.KeyStepUpWindow)
	if got := step.display(value{d: 2 * time.Second}); got != "2s" {
		t.Fatalf("non-whole display = %q", got)
	}
	for _, bad := range []string{"", "x", "-1", "1.5", "99999999"} {
		if _, err := poll.parseForm(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
	if v, err := step.parseForm(" 3 "); err != nil || v.d != 3*time.Minute {
		t.Fatalf("parse = %v, %v", v, err)
	}
	for _, s := range GeneralSpecs() {
		v := get(parse(t, "").General(), s.Key)
		back, err := s.decode(s.encode(v))
		if err != nil || back != v {
			t.Errorf("%s round trip: %v %v", s.Key, back, err)
		}
		if _, err := s.decode(`{`); err == nil {
			t.Errorf("%s decoded garbage", s.Key)
		}
	}
	if _, err := poll.decode(`"soon"`); err == nil {
		t.Fatal("bad duration decoded")
	}
}

func TestUpdateGeneral(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	changes, err := f.svc.UpdateGeneral(ctx, f.actor, 0, map[string]string{
		config.KeyTimeZone: "America/New_York", config.KeySessionIdle: "45", config.KeyTheme: "graphite"})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 2 || changes[0] != (Change{config.KeySessionIdle, "30 min", "45 min"}) ||
		changes[1] != (Change{config.KeyTimeZone, "UTC", "America/New_York"}) {
		t.Fatalf("changes = %+v", changes)
	}
	cur := f.svc.Current()
	if cur.General.TimeZone != "America/New_York" || cur.General.SessionIdle != 45*time.Minute || cur.Rev != 1 {
		t.Fatalf("published = %+v rev %d", cur.General, cur.Rev)
	}
	if fl, _ := cur.Field(config.KeyTimeZone); fl.Source != SourceDB || fl.UpdatedBy != "alice" {
		t.Fatalf("field = %+v", fl)
	}
	recs := f.auditRows(t, ActionGeneralUpdate)
	if len(recs) != 1 || recs[0].Result != audit.ResultOK || recs[0].Principal != "alice" {
		t.Fatalf("audit = %+v", recs)
	}
	var p struct {
		Target  string
		Rev     int64
		Changes []map[string]string
	}
	if jerr := json.Unmarshal([]byte(recs[0].ParamsJSON), &p); jerr != nil || p.Target != "general" || p.Rev != 1 ||
		len(p.Changes) != 2 || p.Changes[1]["before"] != "UTC" || p.Changes[1]["after"] != "America/New_York" {
		t.Fatalf("params = %s (%v)", recs[0].ParamsJSON, jerr)
	}
	// A second service over the same DB sees the change (it survives a restart).
	again, err := New(ctx, Config{DB: f.db, Audit: audit.NewLogger(f.db.Audit(), nil, nil, nil), File: parse(t, "")})
	if err != nil || again.Current().General.TimeZone != "America/New_York" {
		t.Fatalf("reload: %v %+v", err, again.Current().General)
	}
	// Nothing changed: no write, no audit row, no revision bump.
	if ch, err := f.svc.UpdateGeneral(ctx, f.actor, 1, map[string]string{config.KeyTimeZone: "America/New_York"}); err != nil || ch != nil {
		t.Fatalf("no-op = %v, %v", ch, err)
	}
	if len(f.auditRows(t, ActionGeneralUpdate)) != 1 || f.svc.Current().Rev != 1 {
		t.Fatal("no-op wrote")
	}
}

func TestUpdateGeneralRefusals(t *testing.T) {
	f := newFixture(t, "ratelimit: { login_acct_per_hour: 12 }\n")
	ctx := context.Background()
	cases := []struct {
		name string
		rev  int64
		form map[string]string
		want error
	}{
		{"invalid zone", 0, map[string]string{config.KeyTimeZone: "US/Eastern"}, ErrInvalid},
		{"out of bounds", 0, map[string]string{config.KeySessionMax: "48"}, ErrInvalid},
		{"idle above max", 0, map[string]string{config.KeySessionIdle: "120", config.KeySessionMax: "1"}, ErrInvalid},
		{"not a number", 0, map[string]string{config.KeyPollInterval: "fast"}, ErrInvalid},
		{"file managed", 0, map[string]string{config.KeyLoginAcctPerHour: "15"}, ErrLocked},
		{"stale revision", 5, map[string]string{config.KeyTheme: "nord"}, ErrConflict},
	}
	for _, tc := range cases {
		if _, err := f.svc.UpdateGeneral(ctx, f.actor, tc.rev, tc.form); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	// The file-managed value submitted unchanged is fine (disabled inputs).
	if _, err := f.svc.UpdateGeneral(ctx, f.actor, 0, map[string]string{config.KeyLoginAcctPerHour: "12", config.KeyTheme: "nord"}); err != nil {
		t.Fatal(err)
	}
	if rows, _ := f.db.Settings().All(ctx); len(rows) != 1 || rows[0].Key != config.KeyTheme {
		t.Fatalf("rows = %+v", rows)
	}
	denied := 0
	for _, r := range f.auditRows(t, ActionGeneralUpdate) {
		if r.Result == audit.ResultDenied {
			denied++
			if r.ErrorClass != "locked" && r.ErrorClass != "conflict" {
				t.Errorf("class %q", r.ErrorClass)
			}
		}
	}
	if denied != 2 {
		t.Fatalf("denied rows = %d, want 2 (locked, conflict)", denied)
	}
}

func TestLockedSectionRefused(t *testing.T) {
	f := newFixture(t, "settings: { locked: [general] }\n")
	if _, err := f.svc.UpdateGeneral(context.Background(), f.actor, 0, map[string]string{config.KeyTheme: "nord"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v", err)
	}
}

func TestPendingRestart(t *testing.T) {
	f := newFixture(t, "")
	if p := f.svc.Provider().PendingRestart(); len(p) != 0 {
		t.Fatalf("pending at start: %v", p)
	}
	if _, err := f.svc.UpdateGeneral(context.Background(), f.actor, 0, map[string]string{config.KeyPollInterval: "120",
		config.KeyStaleMultiplier: "4"}); err != nil {
		t.Fatal(err)
	}
	// Since S3 the poll interval applies live (fleet.Apply): nothing waits for a restart,
	// and the change is signalled to the pollers.
	if p := f.svc.Provider().PendingRestart(); len(p) != 0 {
		t.Fatalf("pending = %v", p)
	}
	select {
	case <-f.svc.Changes():
	default:
		t.Fatal("no change signal")
	}
	if f.svc.Provider().Started().PollInterval != time.Minute || f.svc.Current().General.StaleMultiplier != 4 {
		t.Fatal("started/current mixed up")
	}
}

func TestDiffRedactsUnknown(t *testing.T) {
	ch := Diff([]string{"a", "b", "c"}, map[string]string{"a": "1", "b": "s3cret", "c": "x"},
		map[string]string{"a": "2", "b": "n3w", "c": "x"}, func(k string) bool { return k == "a" })
	if len(ch) != 2 || ch[0] != (Change{"a", "1", "2"}) || ch[1] != (Change{"b", audit.Redacted, audit.Redacted}) {
		t.Fatalf("Diff = %+v", ch)
	}
	for _, c := range ch {
		if strings.Contains(c.Before+c.After, "3") && c.Field == "b" {
			t.Fatal("secret leaked")
		}
	}
}

func TestPrefs(t *testing.T) {
	f := newFixture(t, "ui: { time_zone: America/New_York, theme: nord }\n")
	ctx := context.Background()
	v, err := f.svc.View(ctx, "u1")
	if err != nil || v.Zone != "America/New_York" || v.Theme != display.ThemeNord {
		t.Fatalf("app default view = %+v, %v", v, err)
	}
	if anon, _ := f.svc.View(ctx, ""); anon.Zone != "America/New_York" {
		t.Fatalf("anonymous view = %+v", anon)
	}
	changes, err := f.svc.SetPrefs(ctx, f.actor, display.Prefs{TimeZone: "Asia/Tokyo", Clock: "12h"})
	if err != nil || len(changes) != 2 || changes[0] != (Change{"time_zone", "default", "Asia/Tokyo"}) {
		t.Fatalf("SetPrefs = %+v, %v", changes, err)
	}
	if v, _ = f.svc.View(ctx, "u1"); v.Zone != "Asia/Tokyo" || v.Clock != display.Clock12 || v.Theme != display.ThemeNord {
		t.Fatalf("user view = %+v", v)
	}
	if recs := f.auditRows(t, ActionPrefsUpdate); len(recs) != 1 || !strings.Contains(recs[0].ParamsJSON, `"after":"Asia/Tokyo"`) {
		t.Fatalf("audit = %+v", recs)
	}
	if ch, err := f.svc.SetPrefs(ctx, f.actor, display.Prefs{TimeZone: "Asia/Tokyo", Clock: "12h"}); err != nil || ch != nil {
		t.Fatalf("no-op = %v, %v", ch, err)
	}
	if _, err := f.svc.SetPrefs(ctx, f.actor, display.Prefs{TimeZone: "Mars/Olympus"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad zone err = %v", err)
	}
	if _, err := f.svc.SetPrefs(ctx, admin.Actor{}, display.Prefs{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("no user err = %v", err)
	}
}

func TestNewRequiresDeps(t *testing.T) {
	if _, err := New(context.Background(), Config{}); err == nil {
		t.Fatal("New without deps succeeded")
	}
}

func TestResetGeneral(t *testing.T) {
	f := newFixture(t, "ratelimit: { login_acct_per_hour: 12 }\n")
	ctx := context.Background()
	if _, err := f.svc.UpdateGeneral(ctx, f.actor, 0, map[string]string{config.KeySessionIdle: "45"}); err != nil {
		t.Fatal(err)
	}
	changes, err := f.svc.ResetGeneral(ctx, f.actor, 1, config.KeySessionIdle)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0] != (Change{config.KeySessionIdle, "45 min", "30 min"}) {
		t.Fatalf("changes = %+v", changes)
	}
	cur := f.svc.Current()
	if fl, _ := cur.Field(config.KeySessionIdle); fl.Source != SourceDefault || cur.General.SessionIdle != 30*time.Minute || cur.Rev != 2 {
		t.Fatalf("after reset: %+v rev %d", fl, cur.Rev)
	}
	if rows, _ := f.db.Settings().All(ctx); len(rows) != 0 {
		t.Fatalf("row kept: %+v", rows)
	}
	recs := f.auditRows(t, ActionGeneralReset)
	if len(recs) != 1 || recs[0].Result != audit.ResultOK || !strings.Contains(recs[0].ParamsJSON, `"before":"45 min"`) ||
		!strings.Contains(recs[0].ParamsJSON, `"after":"30 min"`) || !strings.Contains(recs[0].ParamsJSON, `"rev":2`) {
		t.Fatalf("audit = %+v", recs)
	}
	// Nothing saved for the key: nothing to reset, nothing written.
	if ch, err := f.svc.ResetGeneral(ctx, f.actor, 2, config.KeyTheme); err != nil || ch != nil {
		t.Fatalf("no-op reset = %v, %v", ch, err)
	}
	cases := []struct {
		name, key string
		rev       int64
		want      error
	}{
		{"file managed", config.KeyLoginAcctPerHour, 2, ErrLocked},
		{"unknown key", "gelf.address", 2, ErrInvalid},
		{"stale revision", config.KeySessionIdle, 0, ErrConflict},
	}
	if _, err := f.svc.UpdateGeneral(ctx, f.actor, 2, map[string]string{config.KeySessionIdle: "50"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		if _, err := f.svc.ResetGeneral(ctx, f.actor, tc.rev, tc.key); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
	if len(f.auditRows(t, ActionGeneralReset)) != 3 { // ok + locked + conflict denials
		t.Fatalf("reset rows = %d", len(f.auditRows(t, ActionGeneralReset)))
	}
}

func TestResetGeneralLockedSection(t *testing.T) {
	f := newFixture(t, "settings: { locked: [general] }\n")
	if _, err := f.svc.ResetGeneral(context.Background(), f.actor, 0, config.KeyTheme); !errors.Is(err, ErrLocked) {
		t.Fatalf("err = %v", err)
	}
}

// ui.instance_name (v0.9.1) is a General key: trimmed, validated like the file, audited,
// and kept across a restart; markup is refused.
func TestUpdateGeneralInstanceName(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	changes, err := f.svc.UpdateGeneral(ctx, f.actor, 0, map[string]string{config.KeyInstanceName: "  Lab rack  "})
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0] != (Change{config.KeyInstanceName, "", "Lab rack"}) {
		t.Fatalf("changes = %+v", changes)
	}
	if got := f.svc.Current().General.InstanceName; got != "Lab rack" {
		t.Fatalf("instance name = %q", got)
	}
	if len(f.auditRows(t, ActionGeneralUpdate)) != 1 {
		t.Fatal("not audited")
	}
	for _, bad := range []string{"<script>", "lab\tOOB", strings.Repeat("x", 65)} {
		if _, err := f.svc.UpdateGeneral(ctx, f.actor, 1, map[string]string{config.KeyInstanceName: bad}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: err = %v, want ErrInvalid", bad, err)
		}
	}
	if _, err := f.svc.ResetGeneral(ctx, f.actor, 1, config.KeyInstanceName); err != nil || f.svc.Current().General.InstanceName != "" {
		t.Fatalf("reset: %v %q", err, f.svc.Current().General.InstanceName)
	}
	locked := newFixture(t, "ui: { instance_name: Homelab }\n")
	if _, err := locked.svc.UpdateGeneral(ctx, locked.actor, 0, map[string]string{config.KeyInstanceName: "Other"}); !errors.Is(err, ErrLocked) {
		t.Fatalf("file managed: err = %v, want ErrLocked", err)
	}
}
