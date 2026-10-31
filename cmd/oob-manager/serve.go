package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/api"
	"oob-manager/internal/audit"
	"oob-manager/internal/bmcreset"
	"oob-manager/internal/bmcsec"
	"oob-manager/internal/config"
	"oob-manager/internal/console"
	"oob-manager/internal/fan"
	"oob-manager/internal/fleet"
	"oob-manager/internal/fwcatalog"
	"oob-manager/internal/fwinventory"
	"oob-manager/internal/history"
	"oob-manager/internal/maint"
	"oob-manager/internal/notify"
	"oob-manager/internal/power"
	"oob-manager/internal/store"
	"oob-manager/internal/tofu"
	"oob-manager/internal/web"
)

const (
	shutdownTimeout = 10 * time.Second
	janitorEvery    = time.Hour
)

// serveCmd runs the web app until e.ctx is cancelled (SIGTERM/SIGINT), then shuts
// down gracefully: stop accepting, drain requests, stop pollers, flush the audit shipper.
func serveCmd(e env, args []string) error {
	cfg, _, notes, err := parseFlags("serve", args, e, false, loadServeConfig)
	if err != nil {
		return err
	}
	notes = append(notes, exposureNotes(cfg)...)
	log := newLogger(e.errOut, slog.LevelInfo)
	logStartNotes(log, notes)
	c, cert, err := openServe(e, cfg, log)
	if err != nil {
		return err
	}
	defer func() { _ = c.close() }()
	// From here on the General settings in force (file > DB > default) apply (live via c.settings).
	cfg = c.effective()
	creds, err := loadCredentials(cfg)
	if err != nil {
		return err
	}
	reg, err := c.openRegistry(e.ctx)
	if err != nil {
		return err
	}
	rt, err := newRuntime(e.ctx, cfg, c, reg, creds, e, log)
	if err != nil {
		return err
	}
	fl, cd := rt.fleet, rt.cd
	if cd.notify, cd.maint, err = attachNotify(e.ctx, cfg, c, creds, rt, log); err != nil {
		return err
	}
	if cd, err = withViews(e.ctx, cfg, c, rt, cd, log); err != nil {
		return err
	}
	defer cd.closeHistory() // after runServer has stopped the janitor and every request
	// Fan reconciliation runs until serve returns, before the store closes (defers are LIFO).
	fanCtx, stopFans := context.WithCancel(context.Background())
	var fanWG sync.WaitGroup
	fanWG.Go(func() { cd.fans.Run(fanCtx) })
	defer func() { stopFans(); fanWG.Wait() }()
	h, err := buildHandler(cfg, c, fl, cd, rt)
	if err != nil {
		return err
	}
	return runServer(e, c, fl, cd, h, cert, rt, cd.power.Shutdown, cd.bmc.Shutdown)
}

// openServe prepares what serve needs before its runtime: a store install's certificate
// and keys (plan 09), the UI certificate (fail fast, before the DB, polling or a
// listener), the core with GELF shipping and the audit check, and the first-run service.
func openServe(e env, cfg config.Config, log *slog.Logger) (*core, tls.Certificate, error) {
	notice, err := ensureStoreFiles(e.ctx, cfg, log)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	cert, err := loadServeCert(cfg)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	c, err := openCore(e.ctx, cfg, log)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	if err = c.prepareServe(e); err != nil {
		return nil, tls.Certificate{}, errors.Join(err, c.close())
	}
	if c.firstRun, err = newFirstRun(e.ctx, c, notice, log); err != nil {
		return nil, tls.Certificate{}, errors.Join(err, c.close())
	}
	return c, cert, nil
}

// buildFeatures builds the optional features the UI takes: the graphical and serial
// consoles, power control and the fan lease service.
func buildFeatures(cfg config.Config, c *core, creds credLookup, e env, fl *fleet.Fleet, log *slog.Logger) (consoleDeps, error) {
	cons, kvm, err := buildConsoles(cfg, creds, c.audit, e, log)
	if err != nil {
		return consoleDeps{}, err
	}
	serial, err := buildSerial(cfg, creds, c.audit, e, log)
	if err != nil {
		return consoleDeps{}, err
	}
	var bmcSvc atomic.Pointer[bmcreset.Service]
	pw, err := buildPower(cfg, creds, c.audit, e.kvmEndpoint, powerObserver(fl), powerInterlock(fl, &bmcSvc), log)
	if err != nil {
		return consoleDeps{}, err
	}
	fans, err := buildFans(cfg, c.db, creds, c.audit, e.kvmEndpoint, log)
	if err != nil {
		return consoleDeps{}, err
	}
	cd := consoleDeps{svc: cons, kvm: kvm, serial: serial, power: pw, fans: fans}
	if cd.bmc, err = buildBMCReset(cfg, c, creds, e, fl, cd, log); err != nil {
		return consoleDeps{}, err
	}
	bmcSvc.Store(cd.bmc)
	return cd, nil
}

// buildFleet resolves every server's read-only credential and driver. Servers whose
// kind has no driver yet are skipped with a warning; anything else fails startup.
func buildFleet(cfg config.Config, db *store.DB, creds credLookup, newDriver driverFactory, log *slog.Logger,
	staleMult func() int, sampling func() fleet.Sampling, restart restartCadence, fw fleet.FirmwareSink) (*fleet.Fleet, error) {
	targets, err := fleetTargets(cfg, creds, newDriver, nil, nil, log)
	if err != nil {
		return nil, err
	}
	return fleet.New(fleet.Config{
		Targets: targets, Samples: db.History(), Sampling: sampling, Capabilities: db.Capabilities(), Logger: log,
		Interval: cfg.Poll.Interval, StaleMultiplier: staleMult, PostureEvery: cfg.Security.Every,
		RestartQuiet: restart.quiet, RestartRetry: restart.retry, Firmware: fw,
	})
}

// fleetTargets builds one read-only driver per server. intervals holds per-server poll
// interval overrides (browser-managed servers); posture (nil: none) builds each server's
// security check reader. Each target carries a fingerprint of its inputs, so fleet.Apply
// keeps the poller of an unchanged server.
func fleetTargets(cfg config.Config, creds credLookup, newDriver driverFactory, intervals map[string]int64,
	posture func(config.Server) fleet.PostureFunc, log *slog.Logger) ([]fleet.Target, error) {
	var targets []fleet.Target
	for _, s := range cfg.Servers {
		ro, err := creds.Lookup(s.Credentials.ReadOnly)
		if err != nil {
			return nil, fmt.Errorf("server %s: %w", s.ID, err)
		}
		d, err := newDriver(s, ro)
		if errors.Is(err, errNoDriver) {
			log.Warn("server skipped", "server", s.ID, "reason", err.Error())
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("server %s: %w", s.ID, err)
		}
		iv := cfg.Poll.Interval
		if o := time.Duration(intervals[s.ID]); o > 0 {
			iv = o
		}
		iv = max(iv, s.BMC.Timeouts.Cycle)
		if iv > cfg.Poll.Interval {
			log.Info("poll interval raised to the cycle timeout", "server", s.ID, "interval", iv)
		}
		t := fleet.Target{ID: s.ID, Name: s.Name, Tags: s.Tags, Driver: d, CycleTimeout: s.BMC.Timeouts.Cycle, Interval: iv,
			Fingerprint: targetFingerprint(s, s.BMC.Endpoint(), ro, iv.String())}
		if posture != nil {
			t.Posture = posture(s)
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// buildHandler mounts the API (/api/, /healthz, /readyz) and the UI ("/") behind the
// standard web chain.
// consoleDeps is the graphical console broker, the native console launcher and the
// serial console broker, plus the other optional features the UI takes: power control
// and the fan lease service.
type consoleDeps struct {
	svc    *console.Service
	kvm    *kvmLauncher
	serial *console.SerialService
	power  *power.Service  // power control (P2)
	fans   *fan.Service    // fan leases (P3)
	notify *notify.Service // notifications (tech_doc §26)
	maint  *maint.Service  // maintenance mode, notes, acknowledgements (tech_doc §28)
	// security is the BMC security check service (tech_doc §31); nil when
	// security.enabled is false.
	security *bmcsec.Service
	// bmc restarts BMCs (tech_doc §37).
	bmc *bmcreset.Service
	// firmware is the read-only firmware view (tech_doc §38).
	firmware *fwinventory.Service
	// catalog is the firmware update check (plan 08): the vendor catalog in use, skips.
	catalog *fwcatalog.Checker
	// history is the sensor history (tech_doc §39) and historyRO its read-only pool.
	history   *history.Service
	historyRO *store.ReadDB
}

func buildHandler(cfg config.Config, c *core, fl *fleet.Fleet, cd consoleDeps, rt *serverRuntime) (http.Handler, error) {
	apiH, err := buildAPI(cfg, c, fl, cd)
	if err != nil {
		return nil, err
	}
	ud := UIDeps{Config: cfg, Fleet: fl, Auth: c.authn, Audit: c.audit,
		Admin: c.admin, AuditLog: audit.NewViewer(c.db.Audit(), c.db.AuditSearch()), Build: uiBuild(c.db.SchemaVersion),
		CSRFKey: c.csrfKey, Logger: c.log, Settings: c.settings, BMCWebURL: rt.webURL, Lifecycle: rt.lifecycle,
		Security: cd.security, AutoRefresh: rt.e.autoRefresh, Integrations: c.integrations, Firmware: cd.firmware,
		FirmwareUpdates: cd.catalog, FirmwareCatalog: cd.catalog,
		History: uiHistory(cd.history, rt.e.uiHistoryNow), FirstRun: c.firstRun}
	prover, err := tofu.NewProver(c.tofuKey, nil)
	if err != nil {
		return nil, err
	}
	pr := newProber(rt.reg, rt.file, rt.e, c.audit, c.log)
	pr.trust = c.notifyTap.Trust // VNC and SSH key mismatches found by Test connection
	ud.Servers, ud.Prober, ud.Proofs = rt.reg, pr, prover
	ud = withFeatures(ud, cd)
	ui, err := newUIHandler(ud)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle(api.PathPrefix, apiH)
	mux.Handle(api.PathHealth, apiH)
	mux.Handle(api.PathReady, apiH)
	mux.Handle(api.PathMetrics, apiH)
	mux.Handle("/", ui)
	return web.NewHandler(mux, web.Options{Logger: c.log, HSTS: true, TrustedOrigins: trustedOrigins(cfg.PublicURL)})
}

// withFeatures returns ud with the optional features that are wired (nil stays a nil
// interface, which hides the feature).
func withFeatures(ud UIDeps, cd consoleDeps) UIDeps {
	if cd.svc != nil {
		ud.Consoles = cd.svc
	}
	if cd.kvm != nil {
		ud.KVM = cd.kvm
	}
	if cd.power != nil {
		ud.Power = cd.power
	}
	if cd.fans != nil {
		ud.Fans = cd.fans
	}
	if cd.notify != nil {
		ud.Notifications = cd.notify
	}
	if cd.maint != nil {
		ud.Maintenance = cd.maint
	}
	if cd.serial != nil {
		ud.Serial = cd.serial
	}
	if cd.bmc != nil {
		ud.BMCReset = cd.bmc
	}
	return ud
}

// trustedOrigins turns public_url into the scheme://host origin CrossOriginProtection wants.
func trustedOrigins(publicURL string) []string {
	u, err := url.Parse(publicURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil
	}
	return []string{u.Scheme + "://" + u.Host}
}

// runServer serves h over TLS on the single configured listener until shutdown. stops
// run after the consoles end and before app.stop is recorded (power verifications).
func runServer(e env, c *core, fl *fleet.Fleet, cd consoleDeps, h http.Handler, cert tls.Certificate,
	rt *serverRuntime, stops ...func()) error {
	ln, err := e.listen("tcp", c.cfg.Listen)
	if err != nil {
		return err
	}
	srv := web.NewServer(c.cfg.Listen, h, c.log)
	srv.TLSConfig.Certificates = []tls.Certificate{cert}

	shipCtx, stopShipper := context.WithCancel(context.Background())
	bgCtx, stopBackground := context.WithCancel(context.Background())
	var ship, bg sync.WaitGroup
	ship.Go(func() { c.integrations.Run(shipCtx) })
	background(bgCtx, &bg, c, fl, cd, rt)

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.ServeTLS(ln, "", "") }()
	_ = c.record(e.ctx, "system", "app.start", map[string]any{"version": version, "config_sha256": c.cfg.SHA256})
	c.log.Info("serving", "addr", ln.Addr().String())

	select {
	case <-e.ctx.Done():
		err = nil
	case err = <-serveErr:
	}
	// Consoles are hijacked connections that srv.Shutdown does not wait for: end them first
	// so their stop audit rows are written before app.stop.
	cd.svc.Shutdown()
	if cd.serial != nil {
		cd.serial.Shutdown()
	}
	err = errors.Join(err, shutdown(srv))
	for _, stop := range stops {
		stop()
	}
	stopBackground()
	bg.Wait()
	_ = c.record(context.Background(), "system", "app.stop", nil)
	stopShipper()
	ship.Wait()
	return err
}

// background starts the long-running services on bg; each returns when ctx ends.
func background(ctx context.Context, bg *sync.WaitGroup, c *core, fl *fleet.Fleet, cd consoleDeps, rt *serverRuntime) {
	bg.Go(func() { fl.Run(ctx) })
	bg.Go(func() { janitor(ctx, c, janitorEvery, firmwarePrune(cd.firmware, c.log)) })
	bg.Go(func() { cd.svc.Run(ctx) })
	bg.Go(func() { rt.run(ctx) })
	bg.Go(func() { cd.catalog.Run(ctx) }) // the online firmware update check (off until enabled)
	if cd.notify != nil {
		bg.Go(func() { cd.notify.Run(ctx) })
	}
	if cd.maint != nil {
		bg.Go(func() { cd.maint.Run(ctx) })
	}
	if cd.security != nil {
		bg.Go(func() { cd.security.Run(ctx) })
	}
	if cd.history != nil {
		bg.Go(func() { cd.history.Run(ctx) }) // rollups and prunes, at start and HH:02
	}
}

func shutdown(srv *http.Server) error {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("shutdown: %w", err)
	}
	return nil
}

// loadServeCert loads the UI certificate. Without a usable one nothing is opened (no DB,
// no BMC polling, no listener). There is no plain-HTTP fallback and no HTTP→HTTPS
// redirect port.
func loadServeCert(cfg config.Config) (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("tls: load certificate (create one with `oob-manager gen-tls`): %w", err)
	}
	return cert, nil
}
