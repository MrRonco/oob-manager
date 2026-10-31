package settings

// repopolicy:allow private-addresses -- tests the private-network policy of integration settings

import (
	"context"
	"errors"
	"strings"
	"testing"

	"oob-manager/internal/config"
	"oob-manager/internal/store"
)

const pinA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func putRow(t *testing.T, db *store.DB, key, value string) {
	t.Helper()
	if err := db.Settings().Put(context.Background(), store.SettingRow{Key: key, ValueJSON: value, UpdatedAt: t0,
		UpdatedBy: "bob"}); err != nil {
		t.Fatal(err)
	}
}

func TestResolveIntegrations(t *testing.T) {
	file := parse(t, "")
	rows := []store.SettingRow{
		{Key: config.KeyGELFEnabled, ValueJSON: "true", UpdatedAt: t0, UpdatedBy: "bob"},
		{Key: config.KeyGELFAddress, ValueJSON: `"192.168.1.30:12201"`, UpdatedAt: t0, UpdatedBy: "bob"},
		{Key: config.KeyGELFTransport, ValueJSON: `"tls"`, UpdatedAt: t0, UpdatedBy: "bob"},
		{Key: config.KeyGELFPin, ValueJSON: `"` + pinA + `"`, UpdatedAt: t0, UpdatedBy: "bob"},
	}
	e := Resolve(file, rows, 3)
	g := e.Integrations
	if !g.Enabled || g.Address != "192.168.1.30:12201" || g.Transport != "tls" || g.PinSHA256 != pinA || g.ServerName != "" {
		t.Fatalf("integrations %+v", g)
	}
	f, ok := e.IntegrationField(config.KeyGELFAddress)
	if !ok || f.Source != SourceDB || f.UpdatedBy != "bob" || f.Value != "192.168.1.30:12201" {
		t.Fatalf("field %+v", f)
	}
	if f, _ := e.IntegrationField(config.KeyGELFServerName); f.Source != SourceDefault {
		t.Fatalf("server name %+v", f)
	}
	if len(e.IntegrationFields()) != 5 || !e.IntegrationEditable(config.KeyGELFAddress) {
		t.Fatal("fields or editability")
	}
	// The General section ignores the GELF rows and the other way round.
	if len(e.Ignored) != 0 {
		t.Fatalf("ignored %v", e.Ignored)
	}
}

// TestResolveIntegrationsBadCombination: rows that together fail the validator or the
// static destination policy are all ignored (the file's target runs), never half
// applied.
func TestResolveIntegrationsBadCombination(t *testing.T) {
	file := parse(t, "")
	cases := map[string][]store.SettingRow{
		"tls without pin": {
			{Key: config.KeyGELFEnabled, ValueJSON: "true"}, {Key: config.KeyGELFAddress, ValueJSON: `"10.0.0.5:12201"`},
			{Key: config.KeyGELFTransport, ValueJSON: `"tls"`}},
		"outside the allowed networks": {
			{Key: config.KeyGELFEnabled, ValueJSON: "true"}, {Key: config.KeyGELFAddress, ValueJSON: `"203.0.113.5:12201"`}},
		"unreadable": {{Key: config.KeyGELFEnabled, ValueJSON: `"yes"`}},
	}
	for name, rows := range cases {
		e := Resolve(file, rows, 1)
		if e.Integrations.Enabled || len(e.Ignored) == 0 {
			t.Errorf("%s: %+v ignored %v", name, e.Integrations, e.Ignored)
		}
		if (name != "unreadable") != (e.IntegrationsNote != "") {
			t.Errorf("%s: note %q", name, e.IntegrationsNote)
		}
	}
}

func TestResolveIntegrationsFileWins(t *testing.T) {
	file := parse(t, `audit: { gelf: { address: "10.0.0.9:12201" } }`+"\n")
	rows := []store.SettingRow{{Key: config.KeyGELFAddress, ValueJSON: `"10.0.0.5:12201"`},
		{Key: config.KeyGELFServerName, ValueJSON: `"logs.example.test"`}}
	e := Resolve(file, rows, 1)
	if e.Integrations.Address != "10.0.0.9:12201" || !e.Integrations.Enabled || e.Integrations.ServerName != "logs.example.test" {
		t.Fatalf("%+v", e.Integrations)
	}
	if e.IntegrationEditable(config.KeyGELFAddress) || e.IntegrationEditable(config.KeyGELFEnabled) ||
		!e.IntegrationEditable(config.KeyGELFServerName) {
		t.Fatal("editability")
	}
	if len(e.Ignored) != 1 || !strings.Contains(e.Ignored[0], "shadowed") {
		t.Fatalf("ignored %v", e.Ignored)
	}
	locked := Resolve(parse(t, "settings: { locked: [integrations] }\n"), nil, 0)
	if !locked.IntegrationsLocked || locked.IntegrationEditable(config.KeyGELFAddress) || locked.Locked {
		t.Fatal("integrations lock")
	}
}

func TestUpdateIntegrations(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	form := map[string]string{config.KeyGELFEnabled: "on", config.KeyGELFAddress: " 10.0.0.5:12201 ",
		config.KeyGELFTransport: "tcp", config.KeyGELFServerName: "", config.KeyGELFPin: ""}
	ch, err := f.svc.UpdateIntegrations(ctx, f.actor, 0, form, PinOrigin{})
	if err != nil || len(ch) != 2 {
		t.Fatalf("changes %+v %v", ch, err)
	}
	cur := f.svc.Current()
	if !cur.Integrations.Enabled || cur.Integrations.Address != "10.0.0.5:12201" || cur.Rev != 1 {
		t.Fatalf("published %+v rev %d", cur.Integrations, cur.Rev)
	}
	rows := f.auditRows(t, ActionIntegrationsUpdate)
	if len(rows) != 1 || !strings.Contains(rows[0].ParamsJSON, `"target":"gelf"`) ||
		!strings.Contains(rows[0].ParamsJSON, `"after":"10.0.0.5:12201"`) || !strings.Contains(rows[0].ParamsJSON, `"before":"off"`) {
		t.Fatalf("audit %+v", rows)
	}
	// Unchanged: nothing written.
	if ch, err := f.svc.UpdateIntegrations(ctx, f.actor, 1, form, PinOrigin{}); err != nil || len(ch) != 0 {
		t.Fatalf("no-op %+v %v", ch, err)
	}
	// A fetched pin with TLS: one update row and one pin row in the same transaction.
	pinned := map[string]string{config.KeyGELFTransport: "tls", config.KeyGELFPin: strings.ToUpper(pinA[:32]) + ":" + pinA[32:]}
	if _, err := f.svc.UpdateIntegrations(ctx, f.actor, 1, pinned, PinOrigin{Via: "fetched", Pinned: "issuer"}); err != nil {
		t.Fatal(err)
	}
	if g := f.svc.Current().Integrations; g.PinSHA256 != pinA || g.Transport != "tls" {
		t.Fatalf("pin %+v", g)
	}
	pins := f.auditRows(t, ActionIntegrationsPin)
	if len(pins) != 1 || !strings.Contains(pins[0].ParamsJSON, `"pin_via":"fetched"`) || !strings.Contains(pins[0].ParamsJSON, `"pinned":"issuer"`) {
		t.Fatalf("pin rows %+v", pins)
	}
	// A pin typed into the form is recorded as manual.
	if _, err := f.svc.UpdateIntegrations(ctx, f.actor, 2, map[string]string{config.KeyGELFPin: strings.Repeat("b", 64)}, PinOrigin{}); err != nil {
		t.Fatal(err)
	}
	if pins := f.auditRows(t, ActionIntegrationsPin); len(pins) != 2 || !strings.Contains(pins[0].ParamsJSON, `"pin_via":"manual"`) {
		t.Fatalf("manual pin rows %+v", pins)
	}
}

func TestUpdateIntegrationsRefusals(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	bad := []map[string]string{
		{config.KeyGELFEnabled: "maybe"},
		{config.KeyGELFEnabled: "on"}, // no address
		{config.KeyGELFEnabled: "on", config.KeyGELFAddress: "10.0.0.5:12201", config.KeyGELFTransport: "tls"},
		{config.KeyGELFAddress: "10.0.0.5"},
		{config.KeyGELFTransport: "udp"},
		{config.KeyGELFPin: "nothex"},
		{config.KeyGELFEnabled: "on", config.KeyGELFAddress: "127.0.0.1:12201"},
		{config.KeyGELFEnabled: "on", config.KeyGELFAddress: "203.0.113.9:12201"},
	}
	for _, form := range bad {
		if _, err := f.svc.UpdateIntegrations(ctx, f.actor, 0, form, PinOrigin{}); !errors.Is(err, ErrInvalid) {
			t.Errorf("%v: %v", form, err)
		}
	}
	if _, err := f.svc.UpdateIntegrations(ctx, f.actor, 7, map[string]string{config.KeyGELFAddress: "10.0.0.5:1"}, PinOrigin{}); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale rev: %v", err)
	}
	if rows := f.auditRows(t, ActionIntegrationsUpdate); len(rows) != 1 || rows[0].ErrorClass != "conflict" ||
		!strings.Contains(rows[0].ParamsJSON, `"target":"gelf"`) {
		t.Fatalf("denials %+v", rows)
	}

	file := newFixture(t, `audit: { gelf: { address: "10.0.0.9:12201" } }`+"\n")
	if _, err := file.svc.UpdateIntegrations(ctx, file.actor, 0, map[string]string{config.KeyGELFAddress: "10.0.0.5:1"}, PinOrigin{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("file-managed: %v", err)
	}
	// The unchanged file value may be submitted (a disabled input is not, but a stale
	// form may carry it).
	if _, err := file.svc.UpdateIntegrations(ctx, file.actor, 0, map[string]string{config.KeyGELFAddress: "10.0.0.9:12201"}, PinOrigin{}); err != nil {
		t.Fatalf("unchanged file value: %v", err)
	}
	locked := newFixture(t, "settings: { locked: [integrations] }\n")
	if _, err := locked.svc.UpdateIntegrations(ctx, locked.actor, 0, map[string]string{config.KeyGELFTransport: "tls"}, PinOrigin{}); !errors.Is(err, ErrLocked) {
		t.Fatalf("locked: %v", err)
	}
	if rows := locked.auditRows(t, ActionIntegrationsUpdate); len(rows) != 1 || rows[0].ErrorClass != "locked" {
		t.Fatalf("locked denial %+v", rows)
	}
}

func TestResetIntegrations(t *testing.T) {
	f := newFixture(t, "")
	ctx := context.Background()
	putRow(t, f.db, config.KeyGELFServerName, `"logs.example.test"`)
	f2, err := New(ctx, Config{DB: f.db, Audit: f.svc.cfg.Audit, File: f.svc.cfg.File, Now: f.svc.cfg.Now})
	if err != nil {
		t.Fatal(err)
	}
	if f2.Current().Integrations.ServerName != "logs.example.test" {
		t.Fatal("row not loaded")
	}
	ch, err := f2.ResetIntegrations(ctx, f.actor, 0, config.KeyGELFServerName)
	if err != nil || len(ch) != 1 || f2.Current().Integrations.ServerName != "" {
		t.Fatalf("reset %+v %v", ch, err)
	}
	if rows := f.auditRows(t, ActionIntegrationsReset); len(rows) != 1 {
		t.Fatalf("reset rows %+v", rows)
	}
	if ch, err := f2.ResetIntegrations(ctx, f.actor, 1, config.KeyGELFServerName); err != nil || ch != nil {
		t.Fatalf("second reset %+v %v", ch, err)
	}
	if _, err := f2.ResetIntegrations(ctx, f.actor, 1, "gelf.nope"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown key: %v", err)
	}
	if _, err := f2.ResetIntegrations(ctx, f.actor, 9, config.KeyGELFServerName); err != nil {
		t.Fatalf("nothing saved: %v", err) // no row: a no-op even with a stale revision
	}
	putRow(t, f.db, config.KeyGELFServerName, `"x.example.test"`)
	f3, _ := New(ctx, Config{DB: f.db, Audit: f.svc.cfg.Audit, File: f.svc.cfg.File, Now: f.svc.cfg.Now})
	if _, err := f3.ResetIntegrations(ctx, f.actor, 9, config.KeyGELFServerName); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale: %v", err)
	}
	file := newFixture(t, `audit: { gelf: { address: "10.0.0.9:12201" } }`+"\n")
	if _, err := file.svc.ResetIntegrations(ctx, file.actor, 0, config.KeyGELFAddress); !errors.Is(err, ErrLocked) {
		t.Fatalf("file key: %v", err)
	}
}

func TestIntegrationsSpecs(t *testing.T) {
	specs := IntegrationSpecs()
	if len(specs) != len(config.IntegrationKeys()) {
		t.Fatal("spec per key")
	}
	for i, s := range specs {
		if s.Key != config.IntegrationKeys()[i] || s.Label == "" || s.Help == "" {
			t.Errorf("spec %+v", s)
		}
	}
	if _, err := specs[0].parseForm("on"); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"true", "", "1"} {
		if _, err := specs[0].parseForm(raw); err == nil {
			t.Errorf("enabled %q accepted", raw)
		}
	}
	if v, err := specs[0].decode("false"); err != nil || v.b || specs[0].encode(value{b: true}) != "true" {
		t.Fatal("bool round trip")
	}
	if _, err := specs[1].decode("5"); err == nil {
		t.Fatal("a number decoded as an address")
	}
}
