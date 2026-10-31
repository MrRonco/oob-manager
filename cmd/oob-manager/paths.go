package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"

	"oob-manager/internal/config"
)

// The project was named oob-console until 2026-10-22. An install upgraded in place may
// still mount its config.yaml at the old path or keep its database under the old file
// name; both keep working, with one deprecation warning each per start (deploy/README.md,
// "Upgrade", "Old names from before the rename").
const (
	// DefaultConfigPath is where deploy/compose.yaml mounts config.yaml.
	DefaultConfigPath = "/etc/oob-manager/config.yaml"
	// LegacyConfigPath is the pre-rename default, read only when DefaultConfigPath is absent.
	LegacyConfigPath = "/etc/oob-console/config.yaml"
)

// configFlagUsage documents the -config default and its fallback.
const configFlagUsage = "path to config.yaml (default " + DefaultConfigPath +
	"; if that file does not exist, the deprecated " + LegacyConfigPath + "); \"none\" runs on built-in " +
	"defaults on purpose (a file named none: ./none)"

// pathDefaults are the default file locations. env carries them so tests can point them
// at a temp dir; the zero value means productionPaths.
type pathDefaults struct {
	config, legacyConfig string // config.yaml when -config is not given
	db, legacyDB         string // the database when config.yaml does not set storage.db_path
	// The mounted secret files used when config.yaml does not name them; when they are
	// absent too, a store-style install keeps its keys in the data volume (plan 09).
	identity, appKeys, creds string
}

func productionPaths() pathDefaults {
	return pathDefaults{config: DefaultConfigPath, legacyConfig: LegacyConfigPath,
		db: config.DefaultDBPath, legacyDB: config.LegacyDBPath, identity: config.DefaultIdentityFile,
		appKeys: config.DefaultAppKeysFile, creds: config.DefaultCredentialsFile}
}

// context is e.ctx, or Background for an env built without one (tests).
func (e env) context() context.Context {
	if e.ctx == nil {
		return context.Background()
	}
	return e.ctx
}

// defaults returns the path defaults in force for this env.
func (e env) defaults() pathDefaults {
	if e.paths == (pathDefaults{}) {
		return productionPaths()
	}
	return e.paths
}

// resolveConfigPath returns the config file to load and a deprecation warning ("" when
// none). An explicit -config always wins. Otherwise the new default is used unless it is
// missing and the legacy default exists.
func resolveConfigPath(flagValue string, d pathDefaults) (path, warning string) {
	if flagValue != "" {
		return flagValue, ""
	}
	if !useLegacy(d.config, d.legacyConfig) {
		return d.config, ""
	}
	return d.legacyConfig, fmt.Sprintf("deprecated config path: %s does not exist, so %s (the path before the "+
		"oob-manager rename) is used; move the file or its mount to %s", d.config, d.legacyConfig, d.config)
}

// legacyDBFallback keeps an upgraded install on its pre-rename database file. When a
// later release sets it to false, an install with only that file refuses to start
// (resolveDBPath's error) instead of starting on a fresh, empty database.
const legacyDBFallback = true

// resolveDBPath returns cfg with the database path to open, a warning ("" when none) or
// an error. A storage.db_path written in config.yaml is never changed. For a defaulted
// one: the new file wins when it exists (with a warning if the pre-rename file exists
// too); when only the pre-rename file exists it is used if allowLegacy, else refused.
func resolveDBPath(cfg config.Config, d pathDefaults, allowLegacy bool) (config.Config, string, error) {
	if !cfg.Storage.DBPathDefaulted {
		return cfg, "", nil
	}
	cfg.Storage.DBPath = d.db
	switch {
	case !present(d.legacyDB):
		return cfg, "", nil
	case present(d.db):
		return cfg, fmt.Sprintf("two databases: storage.db_path is not set, so %s is used and %s (the file name "+
			"before the oob-manager rename) is ignored; archive or remove the one you do not use", d.db, d.legacyDB), nil
	case !absent(d.db):
		return cfg, "", nil // cannot be checked (permissions): store.Open reports the real error
	case !allowLegacy:
		return config.Config{}, "", fmt.Errorf("storage.db_path is not set, %s does not exist and %s (the file name "+
			"before the oob-manager rename) does: set storage.db_path to it or rename it to %s", d.db, d.legacyDB, d.db)
	}
	cfg.Storage.DBPath = d.legacyDB
	return cfg, fmt.Sprintf("deprecated database path: storage.db_path is not set and %s does not exist, so %s "+
		"(the file name before the oob-manager rename) is used; set storage.db_path to it or rename the file to %s",
		d.db, d.legacyDB, d.db), nil
}

// useLegacy reports whether current is missing and legacy exists. A current path that
// cannot be checked (permissions) counts as present, so Load reports the real error.
func useLegacy(current, legacy string) bool {
	return absent(current) && present(legacy)
}

// present reports whether path can be stat'ed.
func present(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// absent reports whether path certainly does not exist.
func absent(path string) bool {
	_, err := os.Stat(path) //nolint:gosec // G703: operator-configured or built-in paths, only stat'ed
	return errors.Is(err, fs.ErrNotExist)
}

// startNote is a line serve logs once per start. cli marks a problem the operator must
// act on (a store marker that could not be written or removed, -config=none), which the
// CLI subcommands print to stderr too; the routine notes (pre-rename paths in use,
// running on built-in defaults) stay serve-only (plan 09 N2).
type startNote struct {
	level slog.Level
	msg   string
	cli   bool
}

func warnNote(msg string) startNote { return startNote{level: slog.LevelWarn, msg: msg} }

// problemNote is a warning the CLI subcommands print too.
func problemNote(msg string) startNote { return startNote{level: slog.LevelWarn, msg: msg, cli: true} }

// noConfigFlag is the -config value that runs without any config.yaml on purpose.
const noConfigFlag = "none"

// loadConfig resolves the config path (-config or the defaults), loads it and resolves
// the database path and the store-install paths (plan 09). It returns the start notes
// instead of logging them: only serve logs them (once per start). With no -config and
// neither default file it runs on built-in defaults, but only for a store-style install
// (a fresh data volume, or one marked as such); -config=none is the explicit opt-in.
// It is the CLI subcommands' loader: they never use the UI certificate, so a config.yaml
// without tls is accepted here (serve uses loadServeConfig).
func loadConfig(e env, flagValue string) (config.Config, []startNote, error) {
	return loadConfigFor(e, flagValue, false)
}

// configLoader is loadConfig or loadServeConfig.
type configLoader func(e env, flagValue string) (config.Config, []startNote, error)

// loadServeConfig is loadConfig for serve: a config.yaml without a tls block is refused
// (plan 09 L5) before anything on disk changes.
func loadServeConfig(e env, flagValue string) (config.Config, []startNote, error) {
	return loadConfigFor(e, flagValue, true)
}

func loadConfigFor(e env, flagValue string, serve bool) (config.Config, []startNote, error) {
	d := e.defaults()
	if flagValue == noConfigFlag {
		return loadWithoutConfig(e, d, true)
	}
	path, warn := resolveConfigPath(flagValue, d)
	if flagValue == "" && absent(path) && absent(d.legacyConfig) {
		return loadWithoutConfig(e, d, false)
	}
	var notes []startNote
	if warn != "" {
		notes = append(notes, warnNote(warn))
	}
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, nil, err
	}
	if serve && cfg.TLS.Defaulted {
		return config.Config{}, nil, noTLSError(path)
	}
	cfg, warn, err = resolveDBPath(cfg, d, legacyDBFallback)
	if err != nil {
		return config.Config{}, nil, err
	}
	if warn != "" {
		notes = append(notes, warnNote(warn))
	}
	// Only a config.yaml serve would start with ends a store install: a CLI command run on
	// one without tls leaves the marker, like serve's refusal does.
	if !cfg.TLS.Defaulted {
		if w := clearStoreMarker(filepath.Dir(cfg.Storage.DBPath)); w != "" {
			notes = append(notes, problemNote(w))
		}
	}
	return storePaths(cfg, d), notes, nil
}

// noTLSError refuses a config.yaml without a tls block (plan 09 L5): only an install
// without config.yaml uses the data volume's generated certificate, so a block removed
// by mistake never swaps the certificate browsers and dashboards pinned.
func noTLSError(path string) error {
	return fmt.Errorf("config: %s sets neither tls.cert_file nor tls.key_file: set both (create a "+
		"self-signed pair with `oob-manager gen-tls`, or use your own certificate). An install that "+
		"started without config.yaml keeps its generated certificate by naming it: tls: { cert_file: "+
		"<data>/tls/tls.crt, key_file: <data>/tls/tls.key } (<data> is the directory of storage.db_path, "+
		"default %s)", path, filepath.Dir(config.DefaultDBPath))
}

// loadWithoutConfig returns the built-in defaults for an install without config.yaml.
// An existing database that holds accounts or sealed secrets, in a data volume not
// marked as a store install, means a configured install lost its config.yaml (an empty
// mount): that is refused, since defaults would swap its certificate and drop its
// file-only settings. optIn (-config=none) skips the check and says so at ERROR level.
func loadWithoutConfig(e env, d pathDefaults, optIn bool) (config.Config, []startNote, error) {
	cfg, err := config.Defaults()
	if err != nil {
		return config.Config{}, nil, err
	}
	cfg, warn, err := resolveDBPath(cfg, d, legacyDBFallback)
	if err != nil {
		return config.Config{}, nil, err
	}
	var notes []startNote
	if warn != "" {
		notes = append(notes, warnNote(warn))
	}
	dataDir := filepath.Dir(cfg.Storage.DBPath)
	switch {
	case optIn:
		notes = append(notes, startNote{level: slog.LevelError, cli: true, msg: fmt.Sprintf("running without "+
			"config.yaml because -config=%s was given: built-in defaults apply and any config.yaml is ignored; "+
			"remove the flag if this install should read %s", noConfigFlag, d.config)})
	case present(storeMarkerPath(dataDir)):
		notes = append(notes, warnNote(noConfigWarning(d)))
	default:
		fresh, ferr := dbIsFresh(e.context(), cfg.Storage.DBPath)
		if ferr != nil {
			return config.Config{}, nil, fmt.Errorf("no config file at %s, and the database %s could not be "+
				"checked: refusing to start on built-in defaults: %w", d.config, cfg.Storage.DBPath, ferr)
		}
		if !fresh {
			return config.Config{}, nil, fmt.Errorf("no config file at %s, but the database %s already holds "+
				"accounts or stored secrets: refusing to start on built-in defaults. Restore config.yaml (check "+
				"its mount), or start with -config=%s if this install really runs without one",
				d.config, cfg.Storage.DBPath, noConfigFlag)
		}
		if w := markStoreInstall(dataDir); w != "" {
			notes = append(notes, problemNote(w))
		}
		notes = append(notes, warnNote(noConfigWarning(d)))
	}
	return storePaths(cfg, d), notes, nil
}

func noConfigWarning(d pathDefaults) string {
	return fmt.Sprintf("no config file at %s: running on built-in defaults (store-style install); "+
		"settings are edited in the browser (Settings)", d.config)
}

// configPathFlag is the -config flag value: left out means the defaults, and an
// explicitly empty value is refused rather than silently meaning "the default".
type configPathFlag string

func (c *configPathFlag) String() string {
	if c == nil {
		return ""
	}
	return string(*c)
}

func (c *configPathFlag) Set(s string) error {
	if s == "" {
		return errors.New("empty path (leave -config out to use the default)")
	}
	*c = configPathFlag(s)
	return nil
}

// addConfigFlag registers -config on set; the returned string stays "" when it is left out.
func addConfigFlag(set *flag.FlagSet) *string {
	var path string
	set.Var((*configPathFlag)(&path), "config", configFlagUsage)
	return &path
}

// logStartNotes logs loadConfig's notes (pre-rename paths in use, running without
// config.yaml); serve calls it once per start.
func logStartNotes(log *slog.Logger, notes []startNote) {
	for _, n := range notes {
		log.Log(context.Background(), n.level, n.msg)
	}
}

// printStartNotes prints the problems among loadConfig's notes to w (a CLI subcommand's
// stderr), one line each.
func printStartNotes(w io.Writer, notes []startNote) {
	for _, n := range notes {
		if !n.cli {
			continue
		}
		level := "warning"
		if n.level >= slog.LevelError {
			level = "error"
		}
		_, _ = fmt.Fprintf(w, "oob-manager: %s: %s\n", level, n.msg)
	}
}

// loadCLIConfig is loadConfig for a CLI subcommand: the problems among the start notes
// go to stderr, the routine ones are dropped.
func loadCLIConfig(e env, flagValue string) (config.Config, error) {
	cfg, notes, err := loadConfig(e, flagValue)
	printStartNotes(e.errOut, notes)
	return cfg, err
}
