package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/certgen"
	"oob-manager/internal/config"
	"oob-manager/internal/firstrun"
	"oob-manager/internal/store"
)

// storeEnv is an env whose defaults all point into a temp dir; nothing exists yet but
// the data directory.
func storeEnv(t *testing.T) (env, pathDefaults) {
	t.Helper()
	d := tempPaths(t)
	if err := os.MkdirAll(filepath.Dir(d.db), 0o700); err != nil {
		t.Fatal(err)
	}
	return env{paths: d}, d
}

func TestNoConfigFileRunsOnDefaults(t *testing.T) {
	e, d := storeEnv(t)
	cfg, notes, err := loadConfig(e, "")
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if len(notes) != 1 || notes[0].level != slog.LevelWarn || !strings.Contains(notes[0].msg, "built-in defaults") {
		t.Errorf("notes = %+v", notes)
	}
	data := filepath.Dir(d.db)
	k := firstrun.KeyPathsIn(data)
	certFile, keyFile := firstrun.CertPathsIn(data)
	if cfg.Storage.DBPath != d.db || cfg.Secrets.IdentityFile != k.Identity || cfg.Secrets.AppKeysFile != k.AppKeys ||
		cfg.Secrets.CredentialsFile != "" || cfg.TLS.CertFile != certFile || cfg.TLS.KeyFile != keyFile {
		t.Fatalf("store paths not in the data volume: storage %+v secrets %+v tls %+v", cfg.Storage, cfg.Secrets, cfg.TLS)
	}
}

func TestExplicitMissingConfigStaysAnError(t *testing.T) {
	e, d := storeEnv(t)
	if _, _, err := loadConfig(e, filepath.Join(filepath.Dir(d.db), "nope.yaml")); err == nil {
		t.Fatal("a missing -config file was replaced by defaults")
	}
}

func TestMountedDefaultsWin(t *testing.T) {
	e, d := storeEnv(t)
	for _, f := range []string{d.identity, d.appKeys, d.creds} {
		touch(t, f)
	}
	cfg, _, err := loadConfig(e, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Secrets.IdentityFile != d.identity || cfg.Secrets.AppKeysFile != d.appKeys || cfg.Secrets.CredentialsFile != d.creds {
		t.Fatalf("mounted secrets not used: %+v", cfg.Secrets)
	}
	if dataKeys(cfg) {
		t.Fatal("mounted keys reported as data-volume keys")
	}
}

// existingInstall writes a config.yaml naming every file, like an existing install
// (identity outside the data volume, app keys, credentials and TLS mounted), none of which exist.
func existingInstall(t *testing.T, d pathDefaults) string {
	t.Helper()
	dir := filepath.Dir(d.config)
	run := filepath.Join(dir, "secrets")
	src := `tls: { cert_file: ` + run + `/tls.crt, key_file: ` + run + `/tls.key }
public_url: https://192.0.2.20:8443/
storage: { db_path: ` + d.db + ` }
secrets:
  credentials_file: ` + run + `/bmc-credentials.age
  identity_file: ` + run + `/age-identity
  app_keys_file: ` + run + `/app-keys.age
`
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, d.config, []byte(src))
	return run
}

func TestConfiguredPathsAreNeverReplacedOrGenerated(t *testing.T) {
	e, d := storeEnv(t)
	run := existingInstall(t, d)
	cfg, _, err := loadConfig(e, "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Secrets.IdentityFile != run+"/age-identity" || cfg.TLS.CertFile != run+"/tls.crt" ||
		cfg.Secrets.CredentialsFile != run+"/bmc-credentials.age" {
		t.Fatalf("configured paths changed: %+v %+v", cfg.Secrets, cfg.TLS)
	}
	var logs bytes.Buffer
	notice, err := ensureStoreFiles(context.Background(), cfg, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil || notice != nil {
		t.Fatalf("ensureStoreFiles = %v, %v", notice, err)
	}
	data := filepath.Dir(d.db)
	for _, p := range []string{filepath.Join(data, "keys"), filepath.Join(data, "tls"), run} {
		if _, err := os.Stat(p); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s was created for an install that configures its files", p)
		}
	}
	if _, err := loadServeCert(cfg); err == nil {
		t.Error("a missing configured certificate did not fail")
	}
	if _, err := openCore(context.Background(), cfg, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("a missing configured identity did not fail")
	}
}

func TestFirstStartGeneratesThenReuses(t *testing.T) {
	e, _ := storeEnv(t)
	cfg, _, err := loadConfig(e, "")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	notice, err := ensureStoreFiles(context.Background(), cfg, log)
	if err != nil || notice == nil || !notice.Pending() {
		t.Fatalf("first start: notice %v, err %v", notice, err)
	}
	if !strings.Contains(logs.String(), "generated the encryption keys") || !strings.Contains(logs.String(), "fingerprint") {
		t.Errorf("first-start log lacks the key or certificate lines:\n%s", logs.String())
	}
	if _, cerr := loadServeCert(cfg); cerr != nil {
		t.Fatalf("generated certificate: %v", cerr)
	}
	c, err := openCore(context.Background(), cfg, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("openCore on generated keys: %v", err)
	}
	creds, err := loadCredentials(cfg)
	if err != nil || len(creds.Refs()) != 0 {
		t.Fatalf("credentials: %v, %v", creds.Refs(), err)
	}
	_ = c.close()
	ids, _ := os.ReadFile(cfg.Secrets.IdentityFile)
	if _, err := ensureStoreFiles(context.Background(), cfg, log); err != nil {
		t.Fatalf("second start: %v", err)
	}
	again, _ := os.ReadFile(cfg.Secrets.IdentityFile)
	if !bytes.Equal(ids, again) {
		t.Fatal("the identity changed on the second start")
	}
}

func TestNoKeysWithSealedDataRefuses(t *testing.T) {
	e, d := storeEnv(t)
	// A store install (marked) whose generated keys went missing.
	seedAccount(t, d.db)
	if w := markStoreInstall(filepath.Dir(d.db)); w != "" {
		t.Fatal(w)
	}
	cfg, _, err := loadConfig(e, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ensureStoreFiles(context.Background(), cfg, slog.New(slog.DiscardHandler))
	if !errors.Is(err, firstrun.ErrKeysMissing) {
		t.Fatalf("err = %v, want ErrKeysMissing", err)
	}
	if _, serr := os.Stat(filepath.Join(filepath.Dir(d.db), "keys")); !errors.Is(serr, os.ErrNotExist) {
		t.Fatal("keys generated next to a database that holds sealed data")
	}
}

// seedAccount writes a database holding one account, like an install that has run.
func seedAccount(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	u := store.User{ID: "u1", Username: "owner", Role: store.RoleAdmin, PwHash: "$argon2id$v=19$dummy", //nolint:gosec // G101: dummy hash
		CreatedAt: time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)}
	if err := db.Users().Create(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
}

// An install that ran with config.yaml and lost it (an empty mount) must not start on
// built-in defaults: that would swap its certificate and drop file-only settings.
func TestLostConfigWithAnExistingDatabaseRefuses(t *testing.T) {
	e, d := storeEnv(t)
	seedAccount(t, d.db)
	_, _, err := loadConfig(e, "")
	if err == nil || !strings.Contains(err.Error(), "refusing to start on built-in defaults") ||
		!strings.Contains(err.Error(), "-config=none") {
		t.Fatalf("err = %v", err)
	}
	if present(storeMarkerPath(filepath.Dir(d.db))) {
		t.Fatal("a refused start marked the data volume as a store install")
	}
}

// A fresh volume needs no opt-in, and later starts of that store install (accounts now
// exist) keep working: the data volume carries the store-install marker.
func TestStoreInstallKeepsStartingWithoutConfig(t *testing.T) {
	e, d := storeEnv(t)
	if _, _, err := loadConfig(e, ""); err != nil {
		t.Fatalf("fresh volume: %v", err)
	}
	if !present(storeMarkerPath(filepath.Dir(d.db))) {
		t.Fatal("first start did not mark the store install")
	}
	seedAccount(t, d.db)
	if _, _, err := loadConfig(e, ""); err != nil {
		t.Fatalf("restart of a store install: %v", err)
	}
}

// Once an install runs with a config.yaml, the marker goes: losing that file later is
// refused like on any configured install.
func TestConfigFileRemovesTheStoreMarker(t *testing.T) {
	e, d := storeEnv(t)
	if _, _, err := loadConfig(e, ""); err != nil {
		t.Fatal(err)
	}
	seedAccount(t, d.db)
	existingInstall(t, d)
	if _, _, err := loadConfig(e, ""); err != nil {
		t.Fatalf("with config.yaml: %v", err)
	}
	if present(storeMarkerPath(filepath.Dir(d.db))) {
		t.Fatal("the store marker survived a start with config.yaml")
	}
	if err := os.Remove(d.config); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadConfig(e, ""); err == nil {
		t.Fatal("a configured install that lost its config.yaml started on defaults")
	}
}

// -config=none is the explicit opt-in: it starts on defaults even with accounts, and
// says so at ERROR level.
func TestConfigNoneIsTheOptIn(t *testing.T) {
	e, d := storeEnv(t)
	seedAccount(t, d.db)
	_, notes, err := loadConfig(e, "none")
	if err != nil {
		t.Fatalf("-config=none: %v", err)
	}
	found := false
	for _, n := range notes {
		found = found || (n.level == slog.LevelError && strings.Contains(n.msg, "-config=none"))
	}
	if !found {
		t.Fatalf("no ERROR note for -config=none: %+v", notes)
	}
}

// A key path written in config.yaml is never generated into, even when it is the data
// volume's own key path and the database is fresh (L4).
func TestConfiguredDataVolumeKeyPathIsNotGenerated(t *testing.T) {
	e, d := storeEnv(t)
	data := filepath.Dir(d.db)
	k := firstrun.KeyPathsIn(data)
	if err := os.MkdirAll(filepath.Dir(d.config), 0o700); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(filepath.Dir(d.config), "secrets") // a config.yaml must name its TLS pair (L5)
	writeTemp(t, d.config, []byte("tls: { cert_file: "+run+"/tls.crt, key_file: "+run+"/tls.key }\n"+
		"storage: { db_path: "+d.db+" }\nsecrets:\n  identity_file: "+k.Identity+"\n  app_keys_file: "+k.AppKeys+"\n"))
	cfg, _, err := loadConfig(e, "")
	if err != nil {
		t.Fatal(err)
	}
	if dataKeys(cfg) {
		t.Fatal("configured key paths treated as generated ones")
	}
	if _, err := ensureStoreFiles(context.Background(), cfg, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("ensureStoreFiles: %v", err)
	}
	if present(k.Identity) || present(k.AppKeys) {
		t.Fatal("keys generated into paths written in config.yaml")
	}
	if _, err := openCore(context.Background(), cfg, slog.New(slog.DiscardHandler)); err == nil {
		t.Fatal("missing configured keys did not fail")
	}
}

func TestUnwritableDataDirStopsBeforeAnything(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can write anywhere")
	}
	e, d := storeEnv(t)
	data := filepath.Dir(d.db)
	if err := os.Chmod(data, 0o500); err != nil { //nolint:gosec // G302: a test directory
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(data, 0o700) }) //nolint:gosec // G302: a test directory
	cfg, _, err := loadConfig(e, "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = ensureStoreFiles(context.Background(), cfg, slog.New(slog.DiscardHandler))
	if err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("err = %v", err)
	}
	if _, err := openCore(context.Background(), cfg, slog.New(slog.DiscardHandler)); err == nil || !strings.Contains(err.Error(), "not writable") {
		t.Fatalf("openCore err = %v", err)
	}
	if _, serr := os.Stat(d.db); !errors.Is(serr, os.ErrNotExist) {
		t.Fatal("database created in an unwritable directory")
	}
}

// A database that cannot be checked (corrupt, an older schema) is never fresh, and the
// error says why nothing is generated (L6).
func TestUncheckableDatabaseIsNotFresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oob-manager.db")
	writeTemp(t, path, nil) // a valid, empty SQLite file without the app's tables
	fresh, err := dbIsFresh(context.Background(), path)
	if fresh || err == nil || !strings.Contains(err.Error(), "refusing to generate keys: the database could not be checked") {
		t.Fatalf("dbIsFresh = %v, %v", fresh, err)
	}
}

func TestExpiringDataVolumeCertIsReported(t *testing.T) {
	e, d := storeEnv(t)
	cfg, _, err := loadConfig(e, "")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := certgen.Generate(certgen.Request{Hosts: []string{"localhost"}, Validity: 10 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile := firstrun.CertPathsIn(filepath.Dir(d.db))
	if err := os.MkdirAll(filepath.Dir(certFile), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTemp(t, certFile, pair.CertPEM)
	writeTemp(t, keyFile, pair.KeyPEM)
	var logs bytes.Buffer
	if _, err := ensureStoreFiles(context.Background(), cfg, slog.New(slog.NewTextHandler(&logs, nil))); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "level=WARN") || !strings.Contains(logs.String(), "ends soon") {
		t.Fatalf("no expiry warning:\n%s", logs.String())
	}
}

func TestCertHosts(t *testing.T) {
	cfg, err := config.Defaults()
	if err != nil {
		t.Fatal(err)
	}
	cfg.PublicURL = "https://oob.example.test:8443/"
	hosts := certHosts(cfg)
	for _, want := range []string{"localhost", "127.0.0.1", "oob.example.test"} {
		found := false
		for _, h := range hosts {
			found = found || h == want
		}
		if !found {
			t.Errorf("hosts %v lack %s", hosts, want)
		}
	}
}
