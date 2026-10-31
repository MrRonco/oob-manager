package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/egress"
	"oob-manager/internal/firmware"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/firmware/catalog/dell"
	"oob-manager/internal/fwcatalog"
	"oob-manager/internal/fwinventory"
	"oob-manager/internal/maint"
	"oob-manager/internal/metrics"
	"oob-manager/internal/notify"
	"oob-manager/internal/store"
)

// maxExtraKeysBytes caps firmware.catalog.extra_keys_file.
const maxExtraKeysBytes = 1 << 20

// newCatalogImporter builds the Dell catalog importer from config.yaml: the embedded
// Dell key plus extra_keys_file, the cache next to the database, allow_unsigned and the
// fleet's systems (with the firmware.catalog.systems overrides).
func newCatalogImporter(c *core) (fwcatalog.Importer, error) {
	cc := c.cfg.Firmware.Catalog
	var extra []byte
	if cc.ExtraKeysFile != "" {
		b, err := readCapped(cc.ExtraKeysFile, maxExtraKeysBytes)
		if err != nil {
			return fwcatalog.Importer{}, fmt.Errorf("firmware.catalog.extra_keys_file: %w", err)
		}
		extra = b
	}
	src, err := dell.NewSource(extra)
	if err != nil {
		return fwcatalog.Importer{}, err
	}
	return fwcatalog.Importer{
		Source: src, Repo: c.db.Catalog(), Dir: catalogDir(c.cfg.Storage.DBPath), Limits: catalog.DefaultLimits(),
		AllowUnsigned: cc.AllowUnsigned, Want: fwcatalog.FleetWant(c.db.Firmware(), cc.Systems),
		Audit: func(ctx context.Context, e audit.Entry) {
			if _, err := c.audit.Record(ctx, e); err != nil {
				c.log.Warn("catalog audit row not written", "action", e.Action, "err", err)
			}
		},
	}, nil
}

// buildCatalogChecker builds the update check's read side over the importer (the
// online schedule is U3).
func buildCatalogChecker(c *core, log *slog.Logger, onChange func()) (*fwcatalog.Checker, error) {
	im, err := newCatalogImporter(c)
	if err != nil {
		return nil, err
	}
	host := dell.DefaultURL
	if c.cfg.Firmware.Catalog.URL != "" {
		host = c.cfg.Firmware.Catalog.URL
	}
	if u, err := url.Parse(host); err == nil {
		host = u.Hostname()
	}
	return fwcatalog.NewChecker(fwcatalog.CheckerConfig{Importer: im, Repo: c.db.Catalog(), Updates: c.db.FirmwareUpdates(),
		Audit: c.audit, DB: c.db, OnChange: onChange, File: catalogFile(c.cfg, im), Overrides: c.cfg.Firmware.Catalog.Systems, Host: host, Logger: log})
}

// catalogOnline is the scheduled online check over the view and notifications: the
// file-only URL and allowed networks, the runtime switch, interval and notify level from
// Settings › General (read on every use).
func catalogOnline(c *core, e env, fw *fwinventory.Service, n *notify.Service, m *maint.Service) (fwcatalog.Online, error) {
	cc := c.cfg.Firmware.Catalog
	allowed, err := egress.ParseNetworks(cc.AllowedNetworks)
	if err != nil {
		return fwcatalog.Online{}, err
	}
	u := cc.URL
	if u == "" {
		u = dell.DefaultURL
	}
	f := &fwcatalog.Fetcher{URL: u, UserAgent: "oob-manager/" + version, TLS: e.catalogTLS,
		Policy: egress.Policy{Allowed: allowed, Setting: "firmware.catalog.allowed_networks"}}
	o := fwcatalog.Online{Fetcher: f, Tick: e.catalogTick, FirstDelay: e.catalogFirst,
		Schedule: func() fwcatalog.Schedule {
			g := c.settings.Current().General
			return fwcatalog.Schedule{Enabled: g.CatalogEnabled, Every: time.Duration(g.CatalogCheckDays) * 24 * time.Hour,
				Notify: g.CatalogNotify}
		},
		Pending: func(ctx context.Context) []fwcatalog.Pending { return pendingUpdates(ctx, fw) }}
	if n != nil {
		o.Emit = n.Emit
	}
	if m != nil {
		o.InMaintenance = func(id string) bool { return m.InMaintenance(id, time.Now()) }
	}
	return o, nil
}

// pendingUpdates lists the view's newer, unskipped releases.
func pendingUpdates(ctx context.Context, fw *fwinventory.Service) []fwcatalog.Pending {
	if fw == nil {
		return nil
	}
	var out []fwcatalog.Pending
	for _, r := range fw.Table(ctx, firmware.Filter{Updates: true}).Rows {
		out = append(out, fwcatalog.Pending{ServerID: r.Server.ID, ServerName: r.Server.Name, ComponentID: r.ComponentID,
			FQDD: r.FQDD, Component: r.Display, Running: r.Running, Latest: r.Update.Latest.Version,
			Urgent: r.Update.State == firmware.UpdateUrgent})
	}
	return out
}

// catalogFile is the file-only part shown read-only in Settings.
func catalogFile(cfg config.Config, im fwcatalog.Importer) fwcatalog.FileSettings {
	fs := fwcatalog.FileSettings{URL: cfg.Firmware.Catalog.URL, AllowedNetworks: cfg.Firmware.Catalog.AllowedNetworks,
		AllowUnsigned: cfg.Firmware.Catalog.AllowUnsigned, Systems: len(cfg.Firmware.Catalog.Systems)}
	if src, ok := im.Source.(dell.Source); ok {
		fs.Fingerprints = src.Keys.Fingerprints()
	}
	return fs
}

// catalogMetrics adapts the checker for /metrics (nil without it).
func catalogMetrics(chk *fwcatalog.Checker) func() metrics.CatalogState {
	if chk == nil {
		return nil
	}
	return func() metrics.CatalogState {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pub, last, res, fails := chk.Metrics(ctx)
		return metrics.CatalogState{Source: dell.SourceName, Published: pub, LastCheck: last, LastResult: res, Failures: fails}
	}
}

// catalogDir is <data>/catalog/dell, next to the database (backed up with it).
func catalogDir(dbPath string) string {
	return filepath.Join(filepath.Dir(dbPath), "catalog", dell.SourceName)
}

func readCapped(path string, maxBytes int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // G304: a path from config.yaml or the operator's shell
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > maxBytes {
		return nil, fmt.Errorf("larger than %d bytes", maxBytes)
	}
	return b, nil
}

// catalogCmd dispatches `catalog import`.
func catalogCmd(e env, args []string) error {
	if len(args) == 0 || args[0] != "import" {
		return errors.New("catalog: expected import")
	}
	return catalogImportCmd(e, args[1:])
}

// catalogImportCmd imports a vendor catalog file and its detached signature from the
// shell (air-gapped installs, older catalogs for end-of-life models). The same pipeline
// as the online check runs: signature first, then the bounded parse.
func catalogImportCmd(e env, args []string) error {
	fs, cfgPath := newFlagSet("catalog import", e.errOut)
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return err
	}
	if len(pos) < 1 || len(pos) > 2 {
		return errors.New("catalog import: expected <catalog.xml.gz> [<catalog.xml.gz.sign>]")
	}
	c, err := openMutatingCLICore(e.ctx, *cfgPath, e)
	if err != nil {
		return err
	}
	defer func() { _ = c.close() }()
	im, err := newCatalogImporter(c)
	if err != nil {
		return err
	}
	var sig []byte
	if len(pos) == 2 {
		if sig, err = readCapped(pos[1], dell.MaxSignatureBytes); err != nil {
			return fmt.Errorf("catalog import: signature: %w", err)
		}
	}
	file, err := stageFile(im.Dir, pos[0])
	if err != nil {
		return fmt.Errorf("catalog import: %w", err)
	}
	res, err := im.Import(e.ctx, fwcatalog.Input{Origin: fwcatalog.OriginCLI, File: file, Sig: sig, By: cliActor.Username,
		AuthMethod: cliActor.Method})
	if err != nil {
		return fmt.Errorf("catalog import: nothing imported (%s): %w", catalog.Class(err), err)
	}
	printImport(e.out, res)
	return nil
}

func stageFile(dir, path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the operator's file
	if err != nil {
		return "", err
	}
	defer f.Close()
	return fwcatalog.Stage(dir, f)
}

func printImport(w io.Writer, res fwcatalog.Result) {
	signed := "unsigned (accepted by firmware.catalog.allow_unsigned)"
	if res.Signer.Fingerprint != "" {
		signed = "signed by " + res.Signer.Fingerprint
	}
	_, _ = fmt.Fprintf(w, "Imported catalog %s (published %s), %s: %d components listed, %d releases kept for the fleet.\n",
		res.Manifest.Version, fmtCLITime(res.Manifest.Published), signed, res.Components, res.Kept)
	if res.State == store.CatalogHeld {
		_, _ = fmt.Fprintf(w, "HELD: it keeps %d releases where the catalog in use keeps %d; the previous catalog stays "+
			"in use until an admin confirms the new one in Settings.\n", res.Kept, res.Previous)
	}
}
