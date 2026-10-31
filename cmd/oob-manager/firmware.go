package main

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"oob-manager/internal/api"
	"oob-manager/internal/bmc"
	"oob-manager/internal/bmcsec"
	"oob-manager/internal/config"
	"oob-manager/internal/firmware"
	"oob-manager/internal/fleet"
	"oob-manager/internal/fwcatalog"
	"oob-manager/internal/fwinventory"
	"oob-manager/internal/metrics"
	"oob-manager/internal/notify"
	"oob-manager/internal/web/ui"
)

// The read-only firmware view (tech_doc §38).

// errFirmwareNotReady fails a scan recorded before serve built the service (the fleet
// does not poll before Run, so this is a guard, not an expected path).
var errFirmwareNotReady = errors.New("firmware view: not ready yet")

// firmwareSink is the fleet's firmware sink. The service reads the fleet, which the
// runtime builds first, so the sink is wired to the service once serve has built it.
type firmwareSink struct {
	svc     atomic.Pointer[fwinventory.Service]
	catalog atomic.Pointer[fwcatalog.Checker]
}

var _ fleet.FirmwareSink = (*firmwareSink)(nil)

func (f *firmwareSink) Need(id string, now time.Time) func(bmc.FirmwareItem) bool {
	if s := f.svc.Load(); s != nil {
		return s.Need(id, now)
	}
	return func(bmc.FirmwareItem) bool { return false }
}

func (f *firmwareSink) Record(ctx context.Context, id string, scan bmc.FirmwareScan, at time.Time) error {
	s := f.svc.Load()
	if s == nil {
		return errFirmwareNotReady
	}
	err := s.Record(ctx, id, scan, at)
	if c := f.catalog.Load(); c != nil && err == nil {
		// A new system ID or model re-parses the cached catalog (no network), off the
		// poller's path; concurrent calls collapse into one run.
		go c.FleetChanged(context.WithoutCancel(ctx))
	}
	return err
}

// firmwarePolicy is the evaluation policy from config.yaml: firmware.minimum, names and
// stale_after, with security.min_firmware as the only minimum of each BMC's own
// firmware (shared with the fw.bmc security check).
func firmwarePolicy(cfg config.Config) firmware.Policy {
	rules := make([]firmware.Rule, 0, len(cfg.Firmware.Minimum))
	for _, r := range cfg.Firmware.Minimum {
		rules = append(rules, firmware.Rule{BMCKind: r.BMCKind, Kind: r.Kind, Model: r.Model, ComponentID: r.ComponentID,
			FQDD: r.FQDD, Version: r.Version, Note: r.Note})
	}
	mins := map[string]string{}
	for _, k := range []config.BMCKind{config.KindIDRAC8, config.KindIDRAC9, config.KindRedfish} {
		if v := cfg.Security.MinFirmware.For(k); v != "" {
			mins[string(k)] = v
		}
	}
	return firmware.NewPolicy(firmware.PolicyParams{Rules: rules, BMCMinimum: mins, StaleAfter: cfg.Firmware.StaleAge(),
		Names: cfg.Firmware.Names})
}

// buildFirmware builds the firmware view over the runtime's fleet, wires it to the
// fleet's sink and syncs it with the registry (rows of servers that left it go).
func buildFirmware(ctx context.Context, cfg config.Config, c *core, rt *serverRuntime, n *notify.Service,
	log *slog.Logger) (*fwinventory.Service, *fwcatalog.Checker, error) {
	var svc *fwinventory.Service
	chk, err := buildCatalogChecker(c, log, func() {
		if svc != nil {
			svc.UpdatesChanged()
		}
	})
	if err != nil {
		return nil, nil, err
	}
	fc := fwinventory.Config{DB: c.db, Audit: c.audit, Fleet: rt.fleet, Kind: rt.bmcKind,
		Refresh: rt.fleet.Refresh, Policy: firmwarePolicy(cfg), Logger: log, Updates: chk}
	if n != nil {
		fc.Emit = n.Emit
	}
	if svc, err = fwinventory.New(ctx, fc); err != nil {
		return nil, nil, err
	}
	rt.fwSink.catalog.Store(chk)
	if err := rt.setFirmware(ctx, svc); err != nil {
		return nil, nil, err
	}
	chk.FleetChanged(ctx)
	return svc, chk, nil
}

// buildViews builds the read-side services over the runtime's fleet: the BMC security
// checks (nil when off) and the firmware view.
func buildViews(ctx context.Context, cfg config.Config, c *core, rt *serverRuntime, n *notify.Service,
	log *slog.Logger) (*bmcsec.Service, *fwinventory.Service, *fwcatalog.Checker, error) {
	sec, err := buildSecurity(ctx, cfg, c, rt, n, log)
	if err != nil {
		return nil, nil, nil, err
	}
	fw, chk, err := buildFirmware(ctx, cfg, c, rt, n, log)
	return sec, fw, chk, err
}

// firmwarePrune is the janitor's pass over the firmware view's version changes (a no-op
// without the service).
func firmwarePrune(s *fwinventory.Service, log *slog.Logger) func(context.Context) {
	return func(ctx context.Context) {
		if s == nil {
			return
		}
		if _, err := s.Prune(ctx); err != nil && ctx.Err() == nil {
			log.Warn("janitor: prune firmware changes failed", "error", err)
		}
	}
}

// bmcKind is a server's configured BMC kind (rules match on it).
func (rt *serverRuntime) bmcKind(id string) string {
	in, _ := rt.securityInput(id)
	return in.Kind
}

// setFirmware connects the firmware view and syncs it with the registry right away.
func (rt *serverRuntime) setFirmware(ctx context.Context, svc *fwinventory.Service) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.fwSink.svc.Store(svc)
	return rt.syncFirmware(ctx)
}

// syncFirmware hands every registry id (file and browser, enabled or not) to the
// firmware view, which forgets the others. The caller holds rt.mu.
func (rt *serverRuntime) syncFirmware(ctx context.Context) error {
	svc := rt.fwSink.svc.Load()
	if svc == nil {
		return nil
	}
	entries := rt.reg.Current().Entries()
	ids := make([]string, 0, len(entries))
	for _, x := range entries {
		ids = append(ids, x.Server.ID)
	}
	return svc.SyncServers(ctx, ids)
}

// firmwareCounts adapts the view's numbers for /metrics (nil without the service).
func firmwareCounts(s *fwinventory.Service) func(string) (metrics.FirmwareCounts, bool) {
	if s == nil {
		return nil
	}
	return func(id string) (metrics.FirmwareCounts, bool) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		n, ok := s.Counts(ctx, id)
		if !ok {
			return metrics.FirmwareCounts{}, false
		}
		flagged := make(map[string]int, len(n.Flagged))
		for f, v := range n.Flagged {
			flagged[string(f)] = v
		}
		return metrics.FirmwareCounts{Components: n.Components, Flagged: flagged, Updates: n.Updates, LastScan: n.LastScan,
			Changes: n.Changes}, true
	}
}

// uiFirmware and apiFirmware keep a nil service a nil interface (the view is hidden).
func uiFirmware(s *fwinventory.Service) ui.Firmware {
	if s == nil {
		return nil
	}
	return s
}

func uiFirmwareUpdates(c *fwcatalog.Checker) ui.FirmwareUpdates {
	if c == nil {
		return nil
	}
	return c
}

func uiFirmwareCatalog(c *fwcatalog.Checker) ui.FirmwareCatalog {
	if c == nil {
		return nil
	}
	return c
}

func apiFirmware(s *fwinventory.Service) api.FirmwareView {
	if s == nil {
		return nil
	}
	return s
}
