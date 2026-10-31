package registry

// repopolicy:allow private-addresses -- tests bmc_networks with the RFC 1918 default block

import (
	"context"
	"crypto/rand"
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
	"oob-manager/internal/secrets"
	"oob-manager/internal/secrets/credstore"
	"oob-manager/internal/store"
)

var t0 = time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)

const pinA = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const pinB = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// Test-only secrets: they must never appear in an audit row or the database in clear.
const (
	roPassword = "ro-password-never-logged"
	opPassword = "op-password-never-logged"
)

const fileYAML = `tls: { cert_file: /c, key_file: /k }
public_url: https://oob.example.test
settings: { bmc_networks: [192.0.2.0/24, 10.0.0.0/8] }
servers:
  - id: file1
    name: File one
    bmc: { address: 192.0.2.10, kind: idrac9 }
    tls_pin_sha256: "` + pinA + `"
    credentials: { readonly: file1-ro, operator: file1-op }
    console: { serial: none, graphical: kvm-launch }
  - id: file2
    name: File two
    bmc: { address: 198.51.100.7, kind: idrac8, auth: basic }
    tls_pin_sha256: "` + pinA + `"
    credentials: { readonly: file2-ro }
`

type fixture struct {
	db    *store.DB
	svc   *Service
	file  config.Config
	store *credstore.Store
	lease bool
	actor admin.Actor
}

func newFixture(t *testing.T, extraYAML string) *fixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "r.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	file, err := config.Parse([]byte(extraYAML + fileYAML))
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, credstore.KeyBytes)
	_, _ = rand.Read(key)
	cs, err := credstore.New(key)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{db: db, file: file, store: cs, actor: admin.Actor{UserID: "u1", Username: "alice",
		Role: authz.RoleAdmin, IP: "192.0.2.1", Method: "local"}}
	f.svc = f.open(t)
	return f
}

func (f *fixture) open(t *testing.T) *Service {
	t.Helper()
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc, err := New(context.Background(), Config{DB: f.db, Audit: audit.NewLogger(f.db.Audit(), nil, func() time.Time { return t0 }, quiet),
		File: f.file, Creds: f.store, Now: func() time.Time { return t0 }, Logger: quiet,
		// It reads the database like production does, so a call from inside a transaction
		// (single connection) would hang the test.
		LeaseActive: func(ctx context.Context, id string) (bool, error) {
			_, err := f.db.Leases().Active(ctx, id)
			return f.lease, ignoreNotFound(err)
		}})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func (f *fixture) rows(t *testing.T, action string) []store.AuditRecord {
	t.Helper()
	recs, err := f.db.AuditSearch().Search(context.Background(), store.AuditFilter{Action: action, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func draft(id string) Draft {
	return Draft{ID: id, Name: "Server " + id, Tags: []string{"lab"}, Kind: config.KindIDRAC9, Address: "192.0.2.12",
		Port: 443, TLSPin: pinA, PinVia: "tofu"}
}

func (f *fixture) rev(t *testing.T, id string) int64 {
	t.Helper()
	e, ok := f.svc.Current().DBEntry(id)
	if !ok {
		t.Fatalf("%s missing", id)
	}
	return e.Rev
}

// ready creates id and stores its read-only login and enables it.
func (f *fixture) ready(t *testing.T, id string) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.svc.Create(ctx, f.actor, draft(id)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetCredential(ctx, f.actor, id, f.rev(t, id), credstore.SlotReadOnly, "svc_ro", roPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetEnabled(ctx, f.actor, id, f.rev(t, id), true); err != nil {
		t.Fatal(err)
	}
}

func TestAddServerFlow(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	e, err := f.svc.Create(ctx, f.actor, draft("edge1"))
	if err != nil {
		t.Fatal(err)
	}
	if e.Enabled || e.Active() || len(e.Creds) != 0 || e.Server.Fan.Mode != config.FanNone ||
		e.Server.Console.Graphical != config.GraphicalNone || e.Rev != 1 || e.Server.BMC.Port != 443 {
		t.Fatalf("new server must start disabled with nothing on: %+v", e)
	}
	select {
	case <-f.svc.Changes():
	default:
		t.Fatal("no change signal")
	}
	// Enabling without the read-only login is refused.
	if _, err = f.svc.SetEnabled(ctx, f.actor, "edge1", 1, true); !errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), "credentials.readonly") {
		t.Fatalf("enable without credentials: %v", err)
	}
	ch, err := f.svc.SetCredential(ctx, f.actor, "edge1", 1, credstore.SlotReadOnly, "svc_ro", roPassword)
	if err != nil || len(ch) != 1 || ch[0].After != "[redacted] v1" || ch[0].Before != "not set" {
		t.Fatalf("set credential: %+v %v", ch, err)
	}
	if _, err = f.svc.SetEnabled(ctx, f.actor, "edge1", 2, true); err != nil {
		t.Fatal(err)
	}
	e, _ = f.svc.Current().Entry("edge1")
	if !e.Active() || e.Server.Credentials.ReadOnly != "readonly" {
		t.Fatalf("enabled: %+v", e)
	}
	if ci, ok := e.Cred(credstore.SlotReadOnly); !ok || ci.Version != 1 || ci.CreatedBy != "alice" {
		t.Fatalf("cred info %+v", ci)
	}
	got, err := f.svc.Credential(ctx, "edge1", credstore.SlotReadOnly)
	if err != nil || got.Username != "svc_ro" || got.Password.Reveal() != roPassword {
		t.Fatalf("open credential: %+v %v", got, err)
	}
	// Replace: the version grows, never re-used.
	if _, err = f.svc.SetCredential(ctx, f.actor, "edge1", 3, credstore.SlotReadOnly, "svc_ro2", roPassword+"2"); err != nil {
		t.Fatal(err)
	}
	if ci, _ := f.svc.Current().Entry("edge1"); ci.Creds[0].Version != 2 {
		t.Fatalf("replaced version = %d", ci.Creds[0].Version)
	}
	if _, err = f.svc.Credential(ctx, "edge1", credstore.SlotOperator); !errors.Is(err, ErrNoCred) {
		t.Fatalf("missing slot: %v", err)
	}
	assertNoSecrets(t, f)
}

// assertNoSecrets: no password ever reaches an audit row or the database in clear.
func assertNoSecrets(t *testing.T, f *fixture) {
	t.Helper()
	recs, err := f.db.AuditSearch().Search(context.Background(), store.AuditFilter{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		for _, secret := range []string{roPassword, opPassword} {
			if strings.Contains(r.ParamsJSON, secret) {
				t.Fatalf("secret in audit row %s: %s", r.Action, r.ParamsJSON)
			}
		}
	}
	creds, _ := f.db.Credentials().All(context.Background())
	for _, c := range creds {
		if strings.Contains(string(c.SecretEnc), "password") || strings.Contains(string(c.SecretEnc), "svc_ro") {
			t.Fatal("credential stored in clear")
		}
	}
}

func TestCreateRefusals(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	if _, err := f.svc.Create(ctx, f.actor, draft("edge1")); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		d    Draft
		want error
	}{
		"in config.yaml":  {Draft{ID: "file1", Name: "x", Kind: config.KindIDRAC9, Address: "192.0.2.13", Port: 443, TLSPin: pinA}, ErrExists},
		"duplicate":       {draft("edge1"), ErrExists},
		"loopback":        {Draft{ID: "a1", Name: "A", Kind: config.KindIDRAC9, Address: "127.0.0.1", Port: 443, TLSPin: pinA}, ErrInvalid},
		"metadata":        {Draft{ID: "a2", Name: "A", Kind: config.KindIDRAC9, Address: "169.254.169.254", Port: 443, TLSPin: pinA}, ErrInvalid},
		"hostname":        {Draft{ID: "a3", Name: "A", Kind: config.KindIDRAC9, Address: "bmc.example.test", Port: 443, TLSPin: pinA}, ErrInvalid},
		"outside network": {Draft{ID: "a4", Name: "A", Kind: config.KindIDRAC9, Address: "198.51.100.9", Port: 443, TLSPin: pinA}, ErrInvalid},
		"no pin":          {Draft{ID: "a5", Name: "A", Kind: config.KindIDRAC9, Address: "192.0.2.14", Port: 443}, ErrInvalid},
		"bad port":        {Draft{ID: "a6", Name: "A", Kind: config.KindIDRAC9, Address: "192.0.2.14", Port: 80, TLSPin: pinA}, ErrInvalid},
		"bad id":          {Draft{ID: "A_1", Name: "A", Kind: config.KindIDRAC9, Address: "192.0.2.14", Port: 443, TLSPin: pinA}, ErrInvalid},
		"bad kind":        {Draft{ID: "a7", Name: "A", Kind: "ilo", Address: "192.0.2.14", Port: 443, TLSPin: pinA}, ErrInvalid},
	}
	for name, tc := range cases {
		if _, err := f.svc.Create(ctx, f.actor, tc.d); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if len(f.svc.Current().Entries()) != 3 {
		t.Fatalf("refused creates were stored: %d", len(f.svc.Current().Entries()))
	}
	// File servers are read-only.
	if _, err := f.svc.UpdateIdentity(ctx, f.actor, "file1", 1, "New", nil); !errors.Is(err, ErrLocked) {
		t.Fatalf("edit file server: %v", err)
	}
	if denied := f.rows(t, ActionCreate); len(denied) < 2 {
		t.Fatalf("denials not audited: %d rows", len(denied))
	}
}

func TestLockedSection(t *testing.T) {
	f := newFixture(t, "")
	if _, err := f.svc.Create(context.Background(), f.actor, draft("edge1")); err != nil {
		t.Fatal(err)
	}
	f.file.Settings.Locked = []string{config.SectionServers}
	f.svc = f.open(t)
	ctx := context.Background()
	if _, err := f.svc.Create(ctx, f.actor, draft("edge2")); !errors.Is(err, ErrLocked) {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.svc.UpdateIdentity(ctx, f.actor, "edge1", 1, "x", nil); !errors.Is(err, ErrLocked) {
		t.Fatalf("update: %v", err)
	}
	if err := f.svc.Delete(ctx, f.actor, "edge1", 1); !errors.Is(err, ErrLocked) {
		t.Fatalf("delete: %v", err)
	}
	if f.svc.Current().Editable("edge1") {
		t.Fatal("editable in a locked section")
	}
}

// TestMovedAddressClearsCredentials: stored credentials never follow a server to a new
// BMC. The connection change deletes them (and the pins); a row whose address is
// changed behind the service's back cannot open them (AAD binding).
func TestMovedAddressClearsCredentials(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	f.ready(t, "edge1")
	// Behind the service's back: the sealed credential is bound to the old address.
	row, _ := f.db.Servers().Get(ctx, "edge1")
	moved := row.Clone()
	moved.Address = "192.0.2.99"
	if err := f.db.Servers().Update(ctx, moved, row.Rev); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Credential(ctx, "edge1", credstore.SlotReadOnly); !errors.Is(err, ErrNoCred) {
		t.Fatalf("moved address opened the credential: %v", err)
	}
	f.svc = f.open(t)
	// Through the service: credentials and pins cleared, server disabled.
	conn := Connection{Kind: config.KindIDRAC9, Address: "192.0.2.70", Port: 443, TLSPin: pinB, PinVia: "tofu"}
	ch, err := f.svc.UpdateConnection(ctx, f.actor, "edge1", f.rev(t, "edge1"), conn)
	if err != nil {
		t.Fatal(err)
	}
	e, _ := f.svc.Current().Entry("edge1")
	if e.Enabled || len(e.Creds) != 0 || e.Server.TLSPinSHA256 != pinB || e.Active() {
		t.Fatalf("after the move: %+v", e)
	}
	joined := ""
	for _, c := range ch {
		joined += c.Field + ":" + c.Before + ">" + c.After + ";"
	}
	if !strings.Contains(joined, "credentials.readonly:[redacted] v1>not set") || !strings.Contains(joined, "enabled:true>false") {
		t.Fatalf("changes = %s", joined)
	}
	// Unchanged connection: nothing written.
	if ch, err = f.svc.UpdateConnection(ctx, f.actor, "edge1", f.rev(t, "edge1"), conn); err != nil || ch != nil {
		t.Fatalf("no-op = %v %v", ch, err)
	}
	assertNoSecrets(t, f)
}

func TestLeaseAndConflictRefusals(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	if _, err := f.svc.Create(ctx, f.actor, draft("edge1")); err != nil {
		t.Fatal(err)
	}
	f.lease = true
	if _, err := f.svc.UpdateConnection(ctx, f.actor, "edge1", 1, Connection{Kind: config.KindIDRAC9, Address: "192.0.2.13",
		Port: 443, TLSPin: pinA}); !errors.Is(err, ErrLeaseActive) {
		t.Fatalf("move with a lease: %v", err)
	}
	feat := Features{FanMode: config.FanRedfishFloor, FanSafeMin: 41, FanMaxLease: time.Hour, Serial: config.SerialNone,
		Graphical: config.GraphicalNone, VNCPort: 5901, SSHPort: 22}
	if _, err := f.svc.UpdateFeatures(ctx, f.actor, "edge1", 1, feat); !errors.Is(err, ErrLeaseActive) {
		t.Fatalf("fan change with a lease: %v", err)
	}
	if _, err := f.svc.UpdateIdentity(ctx, f.actor, "edge1", 1, "Renamed", []string{"a"}); err != nil {
		t.Fatalf("rename with a lease: %v", err)
	}
	f.lease = false
	if _, err := f.svc.UpdateIdentity(ctx, f.actor, "edge1", 1, "Again", nil); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale rev: %v", err)
	}
	if _, err := f.svc.UpdateIdentity(ctx, f.actor, "ghost", 1, "x", nil); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	classes := map[string]bool{}
	for _, r := range f.rows(t, ActionUpdate) {
		classes[r.ErrorClass] = true
	}
	if !classes["lease_active"] || !classes["conflict"] {
		t.Fatalf("denials = %v", classes)
	}
}

func TestFeaturesAndEnabledStaysComplete(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	f.ready(t, "edge1")
	// The serial console needs the operator login: refused while enabled.
	serial := Features{FanMode: config.FanNone, Serial: config.SerialBMCSSH, Graphical: config.GraphicalNone, VNCPort: 5901, SSHPort: 22}
	if _, err := f.svc.UpdateFeatures(ctx, f.actor, "edge1", f.rev(t, "edge1"), serial); !errors.Is(err, ErrInvalid) ||
		!strings.Contains(err.Error(), "credentials.operator") {
		t.Fatalf("incomplete enabled server: %v", err)
	}
	if _, err := f.svc.SetCredential(ctx, f.actor, "edge1", f.rev(t, "edge1"), credstore.SlotOperator, "svc_op", opPassword); err != nil {
		t.Fatal(err)
	}
	serial.FanMode, serial.FanSafeMin, serial.FanMaxLease = config.FanRedfishFloor, 41, time.Hour
	serial.Impact, serial.SelfHost, serial.PollInterval = []string{"Gateway: internet drops"}, true, 90*time.Second
	ch, err := f.svc.UpdateFeatures(ctx, f.actor, "edge1", f.rev(t, "edge1"), serial)
	if err != nil || len(ch) < 5 {
		t.Fatalf("features: %v %+v", err, ch)
	}
	e, _ := f.svc.Current().Entry("edge1")
	if e.Server.Fan.Mode != config.FanRedfishFloor || e.PollInterval != 90*time.Second || !e.Server.Power.SelfHost ||
		!e.Server.Console.SSH.Has(config.QuirkIDRAC8LegacySSH) == (e.Server.BMC.Kind == config.KindIDRAC8) {
		t.Fatalf("entry = %+v", e)
	}
	bad := serial
	bad.FanSafeMin = 20
	if _, err = f.svc.UpdateFeatures(ctx, f.actor, "edge1", f.rev(t, "edge1"), bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("floor below the iDRAC9 minimum: %v", err)
	}
	bad = serial
	bad.PollInterval = 5 * time.Second
	if _, err = f.svc.UpdateFeatures(ctx, f.actor, "edge1", f.rev(t, "edge1"), bad); !errors.Is(err, ErrInvalid) {
		t.Fatalf("poll interval below the floor: %v", err)
	}
	assertNoSecrets(t, f)
}

func TestSetPinAndDelete(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	f.ready(t, "edge1")
	ch, err := f.svc.SetPin(ctx, f.actor, "edge1", f.rev(t, "edge1"), "tls", pinB, "tofu")
	if err != nil || len(ch) != 1 || ch[0].After != pinB+" (tofu)" {
		t.Fatalf("pin: %+v %v", ch, err)
	}
	// Decision 2: credentials are kept on a certificate change.
	if _, err = f.svc.Credential(ctx, "edge1", credstore.SlotReadOnly); err != nil {
		t.Fatalf("credential lost on a pin change: %v", err)
	}
	key := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
	if _, err = f.svc.SetPin(ctx, f.actor, "edge1", f.rev(t, "edge1"), "ssh", key, "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.svc.SetPin(ctx, f.actor, "edge1", f.rev(t, "edge1"), "ssh", "not a key", "manual"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad host key: %v", err)
	}
	if _, err = f.svc.SetPin(ctx, f.actor, "edge1", f.rev(t, "edge1"), "bogus", pinB, "manual"); !errors.Is(err, ErrUnknownPin) {
		t.Fatalf("bad kind: %v", err)
	}
	if err = f.svc.Delete(ctx, f.actor, "edge1", 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale delete: %v", err)
	}
	if err = f.svc.Delete(ctx, f.actor, "edge1", f.rev(t, "edge1")); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.svc.Current().Entry("edge1"); ok {
		t.Fatal("deleted server still listed")
	}
	if creds, _ := f.db.Credentials().All(ctx); len(creds) != 0 {
		t.Fatal("credentials kept after delete")
	}
	if err = f.svc.Delete(ctx, f.actor, "edge1", 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete missing: %v", err)
	}
}

// TestShadowing: a database row with a file server's id is ignored (the file wins),
// flagged, warned about and audited once per start; it can still be deleted.
func TestShadowing(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	row := rowOf(config.Normalise(config.Server{ID: "file1", Name: "Shadow", BMC: config.BMCConfig{Address: "192.0.2.77",
		Kind: config.KindIDRAC9}, TLSPinSHA256: pinB}))
	row.Enabled, row.CreatedAt, row.CreatedBy, row.UpdatedAt, row.UpdatedBy = true, t0, "alice", t0, "alice"
	if err := f.db.Servers().Insert(ctx, row); err != nil {
		t.Fatal(err)
	}
	f.svc = f.open(t)
	eff := f.svc.Current()
	if e, _ := eff.Entry("file1"); e.Source != SourceFile || e.Server.BMC.Address != "192.0.2.10" {
		t.Fatalf("file must win: %+v", e)
	}
	if e, _ := eff.DBEntry("file1"); !e.Shadowed || e.Active() {
		t.Fatalf("db copy: %+v", e)
	}
	if len(eff.Warnings) == 0 || !strings.Contains(eff.Warnings[0], "shadowed") {
		t.Fatalf("warnings = %v", eff.Warnings)
	}
	if n := len(eff.Active()); n != 2 {
		t.Fatalf("active = %d (the two file servers)", n)
	}
	if len(f.rows(t, ActionShadowed)) != 1 {
		t.Fatal("shadowed row not audited once")
	}
	if eff.Editable("file1") {
		t.Fatal("shadowed row editable")
	}
	if err := f.svc.Delete(ctx, f.actor, "file1", 1); err != nil {
		t.Fatalf("delete shadowed row: %v", err)
	}
	if _, ok := f.svc.Current().DBEntry("file1"); ok {
		t.Fatal("shadowed row kept")
	}
}

func TestResolveProblemsKeepServerOff(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	f.ready(t, "edge1")
	// Narrow the allowlist after the fact: the enabled row no longer runs.
	f.file.Settings.BMCNetworks = []string{"10.0.0.0/8"}
	f.svc = f.open(t)
	e, _ := f.svc.Current().Entry("edge1")
	if e.Active() || len(e.Problems) == 0 || !strings.Contains(e.Problems[0], "bmc_networks") {
		t.Fatalf("entry = %+v", e)
	}
	if !strings.Contains(strings.Join(f.svc.Current().Warnings, "\n"), "enabled but not running") {
		t.Fatal("no warning")
	}
	_ = ctx
}

func TestImportAndExport(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	creds, err := secrets.ParseCredentials([]byte("file1-ro: {username: svc_ro, password: " + roPassword + "}\n" +
		"file1-op: {username: svc_op, password: " + opPassword + "}\n" +
		"file2-ro: {username: svc_ro, password: " + roPassword + "}\n"))
	if err != nil {
		t.Fatal(err)
	}
	cli := admin.Actor{Username: "cli", Method: "cli"}
	res, err := f.svc.Import(ctx, cli, []string{"file1"}, creds)
	if err != nil || len(res) != 1 || len(res[0].Dropped) != 0 {
		t.Fatalf("import: %+v %v", res, err)
	}
	// Still shadowed by the file until it is removed there.
	if e, _ := f.svc.Current().DBEntry("file1"); !e.Shadowed || !e.Enabled || len(e.Creds) != 2 {
		t.Fatalf("imported: %+v", e)
	}
	got, err := f.svc.Credential(ctx, "file1", credstore.SlotOperator)
	if err != nil || got.Password.Reveal() != opPassword {
		t.Fatalf("re-sealed operator: %v", err)
	}
	if _, err = f.svc.Import(ctx, cli, []string{"file1"}, creds); !errors.Is(err, ErrExists) {
		t.Fatalf("second import: %v", err)
	}
	if _, err = f.svc.Import(ctx, cli, []string{"nope"}, creds); err == nil {
		t.Fatal("unknown id imported")
	}
	// file2 is outside settings.bmc_networks and uses basic auth: refused, nothing stored.
	if _, err = f.svc.Import(ctx, cli, []string{"file2"}, creds); err == nil || !strings.Contains(err.Error(), "bmc_networks") {
		t.Fatalf("outside the allowlist: %v", err)
	}
	if rows := f.rows(t, ActionImport); len(rows) != 1 || rows[0].Principal != "cli" {
		t.Fatalf("import audit = %+v", rows)
	}
	// After file1 leaves config.yaml, the database copy runs.
	f.file.Servers = f.file.Servers[1:]
	f.svc = f.open(t)
	if e, ok := f.svc.Current().Entry("file1"); !ok || !e.Active() || e.Source != SourceDB {
		t.Fatalf("after removal from the file: %+v", e)
	}
	out := Export(f.svc.Current())
	if len(out) != 2 || out[0].ID != "file2" || out[0].Credentials.ReadOnly != "file2-ro" ||
		out[1].ID != "file1" || out[1].Credentials.ReadOnly != "file1-readonly" || out[1].Credentials.Operator != "file1-operator" {
		t.Fatalf("export = %+v", out)
	}
	assertNoSecrets(t, f)
}

func TestImportDropsFileOnlySettings(t *testing.T) {
	src := strings.Replace(fileYAML, "198.51.100.7", "10.1.2.3", 1)
	f := newFixture(t, "")
	file, err := config.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	f.file = file
	f.svc = f.open(t)
	creds, _ := secrets.ParseCredentials([]byte("file2-ro: {username: svc_ro, password: " + roPassword + "}\n"))
	res, err := f.svc.Import(context.Background(), admin.Actor{Username: "cli", Method: "cli"}, []string{"file2"}, creds)
	if err != nil || len(res) != 1 || strings.Join(res[0].Dropped, ",") != "bmc.auth" {
		t.Fatalf("import file2: %+v %v", res, err)
	}
}

func TestNewRequiresDeps(t *testing.T) {
	if _, err := New(context.Background(), Config{}); err == nil {
		t.Fatal("accepted")
	}
}

func ignoreNotFound(err error) error {
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

// TestDeleteRemovesSecurityRows: a server's accepted risks and notification state go
// with it, in the same transaction, and another server's rows stay.
func TestDeleteRemovesSecurityRows(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	f.ready(t, "edge1")
	sec := f.db.Security()
	for _, id := range []string{"edge1", "other"} {
		row := store.SecurityAcceptRow{ServerID: id, ServerAddr: "192.0.2.12:443", CheckID: "svc.ipmi", Result: "warn",
			Subject: "on", SubjectHash: strings.Repeat("ab", 32), Comment: "lab", AcceptedBy: "alice", AcceptedAt: t0}
		if err := sec.PutAccept(ctx, row); err != nil {
			t.Fatal(err)
		}
		if err := sec.SetNotified(ctx, id, []store.SecurityNotifiedRow{{ServerID: id, Item: "f:svc.ipmi", Value: "warn|x", NotifiedAt: t0}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.svc.Delete(ctx, f.actor, "edge1", f.rev(t, "edge1")); err != nil {
		t.Fatal(err)
	}
	accepts, _ := sec.Accepts(ctx)
	notified, _ := sec.Notified(ctx)
	if len(accepts) != 1 || accepts[0].ServerID != "other" || len(notified) != 1 || notified[0].ServerID != "other" {
		t.Fatalf("security rows after delete: %+v %+v", accepts, notified)
	}
}

// TestDeleteShadowedRowKeepsTheFileServersSecurityRows: deleting the database copy of
// a file-managed server only cleans up that row; the live server's accepted risks and
// notification state stay.
func TestDeleteShadowedRowKeepsTheFileServersSecurityRows(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	row := rowOf(config.Normalise(config.Server{ID: "file1", Name: "Shadow", BMC: config.BMCConfig{Address: "192.0.2.77",
		Kind: config.KindIDRAC9}, TLSPinSHA256: pinB}))
	row.Enabled, row.CreatedAt, row.CreatedBy, row.UpdatedAt, row.UpdatedBy = true, t0, "alice", t0, "alice"
	if err := f.db.Servers().Insert(ctx, row); err != nil {
		t.Fatal(err)
	}
	f.svc = f.open(t)
	sec := f.db.Security()
	if err := sec.PutAccept(ctx, store.SecurityAcceptRow{ServerID: "file1", ServerAddr: "192.0.2.10:443", CheckID: "svc.ipmi", Result: "warn",
		Subject: "on", SubjectHash: strings.Repeat("ab", 32), Comment: "lab", AcceptedBy: "alice", AcceptedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if err := sec.SetNotified(ctx, "file1", []store.SecurityNotifiedRow{{ServerID: "file1", Item: "f:svc.ipmi", Value: "warn|x", NotifiedAt: t0}}); err != nil {
		t.Fatal(err)
	}
	if err := f.svc.Delete(ctx, f.actor, "file1", 1); err != nil {
		t.Fatalf("delete shadowed row: %v", err)
	}
	accepts, _ := sec.Accepts(ctx)
	notified, _ := sec.Notified(ctx)
	if len(accepts) != 1 || len(notified) != 1 {
		t.Fatalf("the file server's rows were wiped: %+v %+v", accepts, notified)
	}
}

// TestDeleteRemovesFirmwareRows: a deleted server's firmware view rows (components,
// changes, last scan) go with it; another server's stay (docs/tech_doc.md §38).
func TestDeleteRemovesFirmwareRows(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	f.ready(t, "edge1")
	fw := f.db.Firmware()
	for _, id := range []string{"edge1", "other"} {
		c := store.FirmwareComponentRow{ServerID: id, ComponentID: "159", Kind: "bios", Running: "1", FirstSeen: t0, LastSeen: t0}
		ch := store.FirmwareChangeRow{ServerID: id, ComponentID: "159", Field: "running", Before: "0", After: "1", SeenAt: t0}
		if err := fw.ReplaceServer(ctx, store.FirmwareScanRow{ServerID: id, ScannedAt: t0, Components: 1},
			[]store.FirmwareComponentRow{c}, []store.FirmwareChangeRow{ch}); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.svc.Delete(ctx, f.actor, "edge1", f.rev(t, "edge1")); err != nil {
		t.Fatal(err)
	}
	comps, _ := fw.Components(ctx)
	scans, _ := fw.Scans(ctx)
	changes, _ := fw.Changes(ctx, "edge1", 10)
	if len(comps) != 1 || comps[0].ServerID != "other" || len(scans) != 1 || len(changes) != 0 {
		t.Fatalf("firmware rows after delete: %+v %+v %+v", comps, scans, changes)
	}
}
