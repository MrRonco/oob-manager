package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/config"
	"oob-manager/internal/store"
)

func TestSettingsImportExport(t *testing.T) {
	d := newDeployment(t, "")
	// Imported servers must sit inside settings.bmc_networks (the RFC 1918 blocks by default).
	write(t, d.configPath, []byte("settings: { bmc_networks: [192.0.2.0/24] }\n"+configYAML(d.dir, "")))
	rc, out, errOut := runCLI(t, "settings", "import", "-config", d.configPath, "-servers", "r240")
	if rc != 0 || !strings.Contains(out, "remove these servers from config.yaml and restart: r240") ||
		!strings.Contains(errOut, "Imported r240 with its credentials") {
		t.Fatalf("import: %d out %q err %q", rc, out, errOut)
	}
	db, err := store.Open(context.Background(), d.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	rows, _ := db.Servers().All(context.Background())
	creds, _ := db.Credentials().All(context.Background())
	recs, _ := db.AuditSearch().Search(context.Background(), store.AuditFilter{Action: "admin.server.import", Limit: 10})
	_ = db.Close()
	if len(rows) != 1 || !rows[0].Enabled || len(creds) != 1 || len(recs) != 1 || recs[0].Principal != "cli" {
		t.Fatalf("rows %+v creds %d audit %+v", rows, len(creds), recs)
	}
	if bytes.Contains(creds[0].SecretEnc, []byte(redfishmock.Password)) || strings.Contains(recs[0].ParamsJSON, redfishmock.Password) {
		t.Fatal("password stored or audited in clear")
	}
	if rc, _, errOut = runCLI(t, "settings", "import", "-config", d.configPath, "-servers", "r240"); rc == 0 ||
		!strings.Contains(errOut, "nothing imported") {
		t.Fatalf("second import: %d %q", rc, errOut)
	}
	rc, out, errOut = runCLI(t, "settings", "export", "-config", d.configPath)
	if rc != 0 || !strings.Contains(out, "id: r240") || !strings.Contains(out, "readonly: r240-ro") ||
		strings.Contains(out, redfishmock.Password) || !strings.Contains(out, "interval: 1m0s") {
		t.Fatalf("export: %d %q %q", rc, out, errOut)
	}
	dec := yaml.NewDecoder(strings.NewReader(out))
	dec.KnownFields(true)
	var back config.Config
	if err := dec.Decode(&back); err != nil || len(back.Servers) != 1 || back.Servers[0].BMC.Port != 443 {
		t.Fatalf("export does not read back as config.yaml keys: %v %+v", err, back.Servers)
	}
}

func TestSettingsCLIUsage(t *testing.T) {
	d := newDeployment(t, "")
	for _, args := range [][]string{
		{"settings"}, {"settings", "bogus"}, {"settings", "import", "-config", d.configPath},
		{"settings", "import", "-config", d.configPath, "-servers", "nope"},
		{"settings", "export", "-config", d.configPath, "extra"},
	} {
		if rc, _, _ := runCLI(t, args...); rc == 0 {
			t.Errorf("%v: exit 0", args)
		}
	}
	if got := splitIDs(" a, b,,a "); strings.Join(got, ",") != "a,b" {
		t.Fatalf("splitIDs = %v", got)
	}
}
