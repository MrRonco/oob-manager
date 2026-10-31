package main

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"oob-manager/internal/config"
)

// tempPaths returns path defaults inside a fresh temp dir; none of the files exist yet.
func tempPaths(t *testing.T) pathDefaults {
	t.Helper()
	dir := t.TempDir()
	return pathDefaults{
		config: filepath.Join(dir, "oob-manager", "config.yaml"), legacyConfig: filepath.Join(dir, "oob-console", "config.yaml"),
		db: filepath.Join(dir, "data", "oob-manager.db"), legacyDB: filepath.Join(dir, "data", "oob-console.db"),
		identity: filepath.Join(dir, "run", "age-identity"), appKeys: filepath.Join(dir, "run", "app-keys.age"),
		creds: filepath.Join(dir, "run", "bmc-credentials.age"),
	}
}

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, path, []byte("x"))
}

func TestProductionPaths(t *testing.T) {
	p := productionPaths()
	if p.config != "/etc/oob-manager/config.yaml" || p.legacyConfig != "/etc/oob-console/config.yaml" ||
		p.db != config.DefaultDBPath || p.legacyDB != config.LegacyDBPath || p.identity != config.DefaultIdentityFile ||
		p.appKeys != config.DefaultAppKeysFile || p.creds != config.DefaultCredentialsFile {
		t.Fatalf("production paths = %+v", p)
	}
	if (env{}).defaults() != p {
		t.Fatal("an env without paths must use the production defaults")
	}
	if inj := tempPaths(t); (env{paths: inj}).defaults() != inj {
		t.Fatal("injected paths ignored")
	}
}

func TestResolveConfigPath(t *testing.T) {
	p := tempPaths(t)
	if got, warn := resolveConfigPath("", p); got != p.config || warn != "" {
		t.Fatalf("neither exists: %q %q (want the new default, so the error names it)", got, warn)
	}
	touch(t, p.legacyConfig)
	if got, warn := resolveConfigPath("/explicit/config.yaml", p); got != "/explicit/config.yaml" || warn != "" {
		t.Fatalf("-config must win: %q %q", got, warn)
	}
	got, warn := resolveConfigPath("", p)
	if got != p.legacyConfig || !strings.Contains(warn, p.legacyConfig) || !strings.Contains(warn, p.config) ||
		!strings.Contains(warn, "deprecated") {
		t.Fatalf("legacy only: %q %q", got, warn)
	}
	touch(t, p.config)
	if got, warn := resolveConfigPath("", p); got != p.config || warn != "" {
		t.Fatalf("both exist: %q %q (the new path wins)", got, warn)
	}
}
func TestResolveDBPath(t *testing.T) {
	p := tempPaths(t)
	explicit := config.Config{Storage: config.StorageConfig{DBPath: "/elsewhere/x.db"}}
	touch(t, p.legacyDB)
	if got, warn, err := resolveDBPath(explicit, p, true); got.Storage.DBPath != "/elsewhere/x.db" || warn != "" || err != nil {
		t.Fatalf("a db_path set in config.yaml must be kept: %q %q %v", got.Storage.DBPath, warn, err)
	}
	defaulted := config.Config{Storage: config.StorageConfig{DBPath: config.DefaultDBPath, DBPathDefaulted: true}}
	got, warn, err := resolveDBPath(defaulted, p, true)
	if err != nil || got.Storage.DBPath != p.legacyDB || !strings.Contains(warn, p.legacyDB) ||
		!strings.Contains(warn, "deprecated database path") {
		t.Fatalf("legacy only: %q %q %v", got.Storage.DBPath, warn, err)
	}
	if defaulted.Storage.DBPath != config.DefaultDBPath {
		t.Fatal("resolveDBPath mutated its argument")
	}
	touch(t, p.db)
	got, warn, err = resolveDBPath(defaulted, p, true)
	if err != nil || got.Storage.DBPath != p.db || !strings.Contains(warn, p.db) || !strings.Contains(warn, p.legacyDB) ||
		!strings.Contains(warn, "two databases") {
		t.Fatalf("both exist: %q %q %v (the new file wins, with a warning naming both)", got.Storage.DBPath, warn, err)
	}
	fresh := tempPaths(t)
	if got, warn, err := resolveDBPath(defaulted, fresh, true); got.Storage.DBPath != fresh.db || warn != "" || err != nil {
		t.Fatalf("new install: %q %q %v", got.Storage.DBPath, warn, err)
	}
	if !legacyDBFallback {
		t.Fatal("the legacy database fallback is still meant to be on (tech_doc §36)")
	}
}

// TestLegacyDBWithoutFallbackRefusesToStart pins the behaviour planned for when the
// fallback is switched off: an install with only the pre-rename file must not start on
// a fresh database, and the error names both files.
func TestLegacyDBWithoutFallbackRefusesToStart(t *testing.T) {
	p := tempPaths(t)
	touch(t, p.legacyDB)
	defaulted := config.Config{Storage: config.StorageConfig{DBPath: config.DefaultDBPath, DBPathDefaulted: true}}
	_, _, err := resolveDBPath(defaulted, p, false)
	if err == nil || !strings.Contains(err.Error(), p.db) || !strings.Contains(err.Error(), p.legacyDB) {
		t.Fatalf("legacy only, fallback off: %v", err)
	}
	touch(t, p.db)
	if got, _, err := resolveDBPath(defaulted, p, false); err != nil || got.Storage.DBPath != p.db {
		t.Fatalf("both exist, fallback off: %q %v", got.Storage.DBPath, err)
	}
	fresh := tempPaths(t)
	if got, _, err := resolveDBPath(defaulted, fresh, false); err != nil || got.Storage.DBPath != fresh.db {
		t.Fatalf("new install, fallback off: %q %v", got.Storage.DBPath, err)
	}
}

// runWithPaths runs the CLI with injected path defaults (no -config unless args has one).
func runWithPaths(t *testing.T, p pathDefaults, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut syncBuffer
	e := cliEnv(context.Background(), strings.NewReader(""), &out, &errOut)
	e.paths = p
	e.listen = func(string, string) (net.Listener, error) { return nil, net.ErrClosed } // serve stops after startup
	rc := run(append([]string{"oob-manager"}, args...), e)
	return rc, out.String(), errOut.String()
}

// legacyInstall returns a deployment whose config.yaml (without db_path) sits at the
// pre-rename default path and whose database stands in for /data/oob-console.db.
func legacyInstall(t *testing.T) (deployment, pathDefaults) {
	t.Helper()
	d := newDeployment(t, "")
	p := tempPaths(t)
	p.legacyDB = d.dbPath
	if rc, _, errOut := runCLI(t, "settings", "export", "-config", d.configPath); rc != 0 {
		t.Fatalf("seed the legacy database: %d %q", rc, errOut)
	}
	src, err := os.ReadFile(d.configPath)
	if err != nil {
		t.Fatal(err)
	}
	noDB := strings.Replace(string(src), "db_path: "+d.dbPath+", ", "", 1)
	if noDB == string(src) {
		t.Fatal("test config has no db_path to remove")
	}
	if err = os.MkdirAll(filepath.Dir(p.legacyConfig), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, p.legacyConfig, []byte(noDB))
	return d, p
}

// TestLegacyInstallCLIIsQuiet: a CLI subcommand on a pre-rename install works on the old
// files and prints no deprecation warning (only serve logs them).
func TestLegacyInstallCLIIsQuiet(t *testing.T) {
	_, p := legacyInstall(t)
	rc, out, errOut := runWithPaths(t, p, "settings", "export")
	if rc != 0 || !strings.Contains(out, "servers:") || strings.Contains(errOut, "deprecated") {
		t.Fatalf("legacy install, CLI: %d out %q err %q", rc, out, errOut)
	}
	if _, err := os.Stat(p.db); !os.IsNotExist(err) {
		t.Fatalf("a fresh database was created at %s: %v", p.db, err)
	}
}

// TestLegacyInstallServeWarnsOnce: serve on a pre-rename install opens the old files and
// logs each deprecation warning exactly once.
func TestLegacyInstallServeWarnsOnce(t *testing.T) {
	_, p := legacyInstall(t)
	rc, _, errOut := runWithPaths(t, p, "serve")
	if rc != 1 || !strings.Contains(errOut, "audit chain verified") {
		t.Fatalf("serve should reach the listener and stop there: %d %q", rc, errOut)
	}
	if strings.Count(errOut, "deprecated config path") != 1 || strings.Count(errOut, "deprecated database path") != 1 ||
		!strings.Contains(errOut, p.legacyConfig) || !strings.Contains(errOut, p.legacyDB) {
		t.Fatalf("each warning must appear exactly once: %q", errOut)
	}
	if _, err := os.Stat(p.db); !os.IsNotExist(err) {
		t.Fatalf("a fresh database was created at %s: %v", p.db, err)
	}
}

func TestNewConfigPathHasNoWarning(t *testing.T) {
	d := newDeployment(t, "")
	p := tempPaths(t)
	src, err := os.ReadFile(d.configPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(p.config), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, p.config, src)
	touch(t, p.legacyConfig) // a stale old file must not be read when the new one exists
	if rc, _, errOut := runWithPaths(t, p, "serve"); rc != 1 || !strings.Contains(errOut, "audit chain verified") ||
		strings.Contains(errOut, "deprecated") {
		t.Fatalf("new path: %d %q", rc, errOut)
	}
}

func TestConfigFlagHelpNamesDefaults(t *testing.T) {
	rc, _, errOut := runCLI(t, "token", "list", "-h")
	if rc == 0 || !strings.Contains(errOut, "/etc/oob-manager/config.yaml") || !strings.Contains(errOut, "/etc/oob-console/config.yaml") {
		t.Fatalf("help: %d %q", rc, errOut)
	}
}

func TestEmptyConfigFlagIsRefused(t *testing.T) {
	for _, args := range [][]string{{"token", "list", "-config", ""}, {"serve", "-config="}, {"bootstrap-admin", "-config", "", "-username", "x"}} {
		rc, _, errOut := runCLI(t, args...)
		if rc == 0 || !strings.Contains(errOut, "empty path") {
			t.Fatalf("%v: %d %q", args, rc, errOut)
		}
	}
}

// writeTemp writes a file under a test's temp dir (every path here comes from t.TempDir).
func writeTemp(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil { //nolint:gosec // G703: the test's temp dir
		t.Fatal(err)
	}
}
