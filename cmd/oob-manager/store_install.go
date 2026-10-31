package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"oob-manager/internal/certgen"
	"oob-manager/internal/config"
	"oob-manager/internal/firstrun"
	"oob-manager/internal/secrets"
	"oob-manager/internal/store"
)

// A store-style install (docs/plans/09-store-ready-install.md) starts from a data volume
// alone. Paths config.yaml left out fall back to their mounted defaults; when those are
// absent too, the UI certificate and the keys live in the data volume. A path written in
// config.yaml is never replaced.

// storeMarkerName marks a data volume whose install runs without config.yaml: written on
// the first start of a fresh volume, removed once the install starts with a config.yaml.
const storeMarkerName = "store-install"

const storeMarkerText = "This data volume belongs to an oob-manager install that runs without config.yaml " +
	"(docs/plans/09-store-ready-install.md). It is removed automatically when the install starts with a config.yaml.\n"

func storeMarkerPath(dataDir string) string { return filepath.Join(dataDir, storeMarkerName) }

// markStoreInstall writes the marker; it returns a warning instead of failing, because
// an unwritable data directory is reported (with the fix) by the writable check later.
func markStoreInstall(dataDir string) string {
	f, err := os.OpenFile(storeMarkerPath(dataDir), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // G304: the data directory
	if errors.Is(err, fs.ErrExist) {
		return ""
	}
	if err == nil {
		_, err = f.WriteString(storeMarkerText)
		err = errors.Join(err, f.Close())
	}
	if err != nil {
		return fmt.Sprintf("could not mark %s as a store-style install (%v): its next start without config.yaml "+
			"will be refused once accounts exist", dataDir, err)
	}
	return ""
}

// clearStoreMarker removes the marker of an install that now starts with config.yaml, so
// losing that file later is refused like on any configured install.
func clearStoreMarker(dataDir string) string {
	err := os.Remove(storeMarkerPath(dataDir))
	if err == nil || errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	return fmt.Sprintf("could not remove %s (%v): this install now has a config.yaml, and losing it later would "+
		"start on built-in defaults", storeMarkerPath(dataDir), err)
}

// storePaths fills in the defaulted TLS and secret paths.
func storePaths(cfg config.Config, d pathDefaults) config.Config {
	dataDir := filepath.Dir(cfg.Storage.DBPath)
	if cfg.TLS.Defaulted {
		cfg.TLS.CertFile, cfg.TLS.KeyFile = firstrun.CertPathsIn(dataDir)
	}
	s := cfg.Secrets
	if s.IdentityDefaulted && d.identity != "" {
		s.IdentityFile = d.identity
	}
	if s.AppKeysDefaulted && d.appKeys != "" {
		s.AppKeysFile = d.appKeys
	}
	if s.CredentialsDefaulted && d.creds != "" {
		s.CredentialsFile = d.creds
	}
	if s.IdentityDefaulted && s.AppKeysDefaulted && absent(s.IdentityFile) && absent(s.AppKeysFile) {
		k := firstrun.KeyPathsIn(dataDir)
		s.IdentityFile, s.AppKeysFile = k.Identity, k.AppKeys
		if s.CredentialsDefaulted && absent(s.CredentialsFile) {
			s.CredentialsFile = "" // no file: only config.yaml servers use one, and there are none to serve
		}
	}
	cfg.Secrets = s
	return cfg
}

// dataKeys reports whether the keys are the data volume's generated set: both paths left
// out of config.yaml and resolved into the data volume. A path written in config.yaml is
// never generated into, even when it names the data volume's own key file.
func dataKeys(cfg config.Config) bool {
	s := cfg.Secrets
	k := firstrun.KeyPathsIn(filepath.Dir(cfg.Storage.DBPath))
	return s.IdentityDefaulted && s.AppKeysDefaulted && s.IdentityFile == k.Identity && s.AppKeysFile == k.AppKeys
}

// loadCredentials decrypts the BMC credentials file; an install without one (a store
// install whose servers all live in the database) has an empty set.
func loadCredentials(cfg config.Config) (secrets.Credentials, error) {
	if cfg.Secrets.CredentialsFile == "" {
		return secrets.Credentials{}, nil
	}
	return secrets.LoadCredentials(cfg.Secrets.CredentialsFile, cfg.Secrets.IdentityFile)
}

// ensureStoreFiles runs before the certificate, the keys or the database are opened:
// the data directory must be writable, and a store install gets its certificate and
// keys generated on first start. It returns the backup notice of generated keys (nil
// when the keys are mounted).
func ensureStoreFiles(ctx context.Context, cfg config.Config, log *slog.Logger) (*firstrun.Notice, error) {
	dataDir := filepath.Dir(cfg.Storage.DBPath)
	if err := firstrun.CheckWritable(dataDir); err != nil {
		return nil, err
	}
	if cfg.TLS.Defaulted {
		cert, err := firstrun.EnsureCert(dataDir, certHosts(cfg))
		if err != nil {
			return nil, err
		}
		msg := "using the UI certificate in the data volume"
		if cert.Generated {
			msg = "generated a self-signed UI certificate in the data volume; compare this fingerprint on the first visit"
		}
		log.Info(msg, "path", cert.CertFile, "sha256", fingerprint(cert.SHA256))
		if cert.ExpiresSoon(time.Now()) {
			log.Warn("the UI certificate in the data volume ends soon (or has ended): stop the container, remove "+
				"the tls directory and start it again for a new one (new fingerprint), or mount your own",
				"path", cert.CertFile, "not_after", cert.NotAfter.UTC().Format(time.RFC3339))
		}
	}
	if !dataKeys(cfg) {
		return nil, nil
	}
	generated, err := firstrun.EnsureKeys(dataDir, func() (bool, error) { return dbIsFresh(ctx, cfg.Storage.DBPath) })
	if err != nil {
		return nil, err
	}
	n := firstrun.NewNotice(dataDir)
	switch {
	case generated:
		log.Warn("generated the encryption keys in the data volume: back up the identity file off this server "+
			"(without it, stored passwords and authenticator secrets cannot be read after a restore)", "path", n.IdentityPath())
	case n.Pending():
		log.Warn("the generated identity file has not been backed up yet (acknowledge it in the UI once you have)",
			"path", n.IdentityPath())
	}
	return &n, nil
}

// dbIsFresh reports whether the database is new: no file, or one without any sealed
// data. Only then may new keys be generated. The file is opened read-only, so a refused
// start leaves it exactly as it was (no migration); a file it cannot read is not fresh.
func dbIsFresh(ctx context.Context, path string) (bool, error) {
	if absent(path) {
		return true, nil
	}
	db, err := store.OpenReadOnly(ctx, path)
	if err != nil {
		return false, fmt.Errorf("refusing to generate keys: the database could not be checked: %w", err)
	}
	holds, err := db.HoldsSealedData(ctx)
	if err != nil {
		err = fmt.Errorf("refusing to generate keys: the database could not be checked: %w", err)
	}
	return !holds && err == nil, errors.Join(err, db.Close())
}

// certHosts are the names a generated certificate covers: localhost, the app's own
// addresses and public_url's host. Browsers still ask once (self-signed); the
// fingerprint in the log is what the administrator compares.
func certHosts(cfg config.Config) []string {
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if u, err := url.Parse(cfg.PublicURL); err == nil && u.Hostname() != "" {
		hosts = append(hosts, u.Hostname())
	}
	for _, a := range interfaceAddrs() {
		if usableCertAddr(a) && len(hosts) < certgen.MaxHosts {
			hosts = append(hosts, a.String())
		}
	}
	return dedupe(hosts)
}

func usableCertAddr(a netip.Addr) bool {
	return a.IsValid() && !a.IsLoopback() && !a.IsLinkLocalUnicast() && !a.IsMulticast() && !a.IsUnspecified()
}

func dedupe(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// newFirstRun builds the first-run service: a setup code when no account exists (logged
// once, here) and the backup notice of generated keys.
func newFirstRun(ctx context.Context, c *core, notice *firstrun.Notice, log *slog.Logger) (*firstrun.Service, error) {
	svc := &firstrun.Service{Notice: notice, Users: c.db.Users().Count, Bootstrap: c.authn.BootstrapAdmin}
	n, err := c.db.Users().Count(ctx)
	if err != nil {
		return nil, err
	}
	if n > 0 {
		return svc, nil
	}
	setup, code, err := firstrun.NewSetup(time.Now, firstrun.SetupTTL)
	if err != nil {
		return nil, err
	}
	svc.Setup = setup
	log.Warn(fmt.Sprintf("first-run setup: no account exists yet. Open /setup on this app and enter the one-time "+
		"setup code %s (valid until %s, single use; a restart makes a new one). `oob-manager bootstrap-admin` "+
		"works too.", code, setup.ExpiresAt().UTC().Format(time.RFC3339)))
	_ = c.record(ctx, "system", "setup.code_issued", map[string]any{"expires": setup.ExpiresAt().UTC().Format(time.RFC3339)})
	return svc, nil
}
