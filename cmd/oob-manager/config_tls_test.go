package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"oob-manager/internal/firstrun"
)

// writeStoreConfig writes config.yaml at the env's default path.
func writeStoreConfig(t *testing.T, d pathDefaults, src string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(d.config), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, d.config, []byte(src))
}

// A config.yaml without a tls block is a mistake (the block was removed or never
// written), not a request for a generated certificate: serve refuses and says how to
// configure TLS (plan 09 L5). Nothing is generated or removed.
func TestConfigFileWithoutTLSRefuses(t *testing.T) {
	e, d := storeEnv(t)
	writeStoreConfig(t, d, "storage: { db_path: "+d.db+" }\n")
	for _, flagValue := range []string{"", d.config} {
		_, _, err := loadServeConfig(e, flagValue)
		if err == nil {
			t.Fatalf("-config %q: a config.yaml without tls started", flagValue)
		}
		for _, want := range []string{d.config, "tls.cert_file", "tls.key_file", "gen-tls"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("-config %q: error %q does not name %q", flagValue, err, want)
			}
		}
	}
	if present(filepath.Join(filepath.Dir(d.db), "tls")) {
		t.Fatal("a certificate directory was created for a config.yaml without tls")
	}
}

// The refusal reaches the operator from serve, before the database is opened.
func TestServeRefusesConfigFileWithoutTLS(t *testing.T) {
	_, d := storeEnv(t)
	writeStoreConfig(t, d, "storage: { db_path: "+d.db+" }\n")
	rc, _, errOut := runWithPaths(t, d, "serve")
	if rc != 1 || !strings.Contains(errOut, "tls.cert_file") || !strings.Contains(errOut, "gen-tls") {
		t.Fatalf("serve: %d %q", rc, errOut)
	}
	if present(d.db) {
		t.Fatal("the database was created before the configuration was refused")
	}
}

// The marker of a store install survives a refused start: the administrator fixes config.yaml
// (or removes it) and the volume is still a store install.
func TestRefusedConfigKeepsTheStoreMarker(t *testing.T) {
	e, d := storeEnv(t)
	if _, _, err := loadServeConfig(e, ""); err != nil {
		t.Fatal(err)
	}
	writeStoreConfig(t, d, "storage: { db_path: "+d.db+" }\n")
	if _, _, err := loadServeConfig(e, ""); err == nil {
		t.Fatal("a config.yaml without tls started")
	}
	if !present(storeMarkerPath(filepath.Dir(d.db))) {
		t.Fatal("a refused start removed the store marker")
	}
}

// A store install that adds a config.yaml keeps its generated certificate by naming the
// data volume's pair; the keys stay the data volume's generated set.
func TestStoreInstallAddsConfigNamingItsCertificate(t *testing.T) {
	e, d := storeEnv(t)
	cfg, _, err := loadConfig(e, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ensureStoreFiles(context.Background(), cfg, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := firstrun.CertPathsIn(filepath.Dir(d.db))
	writeStoreConfig(t, d, "tls: { cert_file: "+certFile+", key_file: "+keyFile+" }\nstorage: { db_path: "+d.db+" }\n")
	cfg, _, err = loadServeConfig(e, "")
	if err != nil {
		t.Fatalf("config.yaml naming the generated pair: %v", err)
	}
	if cfg.TLS.Defaulted || cfg.TLS.CertFile != certFile || !dataKeys(cfg) {
		t.Fatalf("tls %+v, data keys %v", cfg.TLS, dataKeys(cfg))
	}
	if _, err = loadServeCert(cfg); err != nil {
		t.Fatalf("the generated certificate did not load: %v", err)
	}
}

// The rule is serve's: the CLI never uses the certificate, so break-glass commands keep
// working on a config.yaml without tls (the administrator may be fixing exactly that file).
func TestCLIRecoveryWorksWithoutTLSWhileServeRefuses(t *testing.T) {
	d, _ := bootstrapped(t)
	src, err := os.ReadFile(d.configPath)
	if err != nil {
		t.Fatal(err)
	}
	noTLS := strings.Replace(string(src), "tls: { cert_file: "+d.dir+"/tls.crt, key_file: "+d.dir+"/tls.key }\n", "", 1)
	if noTLS == string(src) {
		t.Fatal("test config has no tls line to remove")
	}
	writeTemp(t, d.configPath, []byte(noTLS))
	if rc, out, errOut := runCLI(t, "admin-recover", "-config", d.configPath, "-username", "admin", "-yes"); rc != 0 ||
		!strings.Contains(out, "enabled admin") {
		t.Fatalf("admin-recover on a config.yaml without tls: %d\n%s%s", rc, out, errOut)
	}
	if rc, out, errOut := runCLI(t, "token", "create", "-config", d.configPath, "-name", "dash"); rc != 0 {
		t.Fatalf("token create on a config.yaml without tls: %d\n%s%s", rc, out, errOut)
	}
	if rc, out, errOut := runCLI(t, "verify-audit", "-config", d.configPath); rc != 0 {
		t.Fatalf("verify-audit on a config.yaml without tls: %d\n%s%s", rc, out, errOut)
	}
	rc, _, errOut := runCLI(t, "serve", "-config", d.configPath)
	if rc != 1 || !strings.Contains(errOut, "tls.cert_file") || strings.Contains(errOut, "audit chain verified") {
		t.Fatalf("serve on a config.yaml without tls: %d %q", rc, errOut)
	}
}

// A CLI command on a config.yaml without tls loads it but leaves the store marker: only a
// config.yaml serve would start with ends a store install, so fixing or removing the
// file later still finds a store volume.
func TestCLIWithoutTLSKeepsTheStoreMarker(t *testing.T) {
	e, d := storeEnv(t)
	if _, _, err := loadConfig(e, ""); err != nil {
		t.Fatal(err)
	}
	writeStoreConfig(t, d, "storage: { db_path: "+d.db+" }\n")
	cfg, _, err := loadConfig(e, "")
	if err != nil || !cfg.TLS.Defaulted {
		t.Fatalf("CLI load of a config.yaml without tls: %+v %v", cfg.TLS, err)
	}
	if !present(storeMarkerPath(filepath.Dir(d.db))) {
		t.Fatal("a CLI load of a config.yaml without tls removed the store marker")
	}
}
