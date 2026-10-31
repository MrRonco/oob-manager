package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/config"
	"oob-manager/internal/firstrun"
	"oob-manager/internal/fleet"
	"oob-manager/internal/integrations"
	"oob-manager/internal/metrics"
	"oob-manager/internal/registry"
	"oob-manager/internal/secrets"
	"oob-manager/internal/secrets/credstore"
	"oob-manager/internal/settings"
	"oob-manager/internal/store"
	"oob-manager/internal/store/authrepo"
)

// maxConcurrentHashes bounds argon2id memory: 2 × 19 MiB with default params, and never
// more than auth.HashMemoryBudgetKiB even for the costliest stored hash accepted.
const maxConcurrentHashes = auth.MaxHashConcurrency

// core is what every database-backed subcommand needs: config, store, audit and auth.
type core struct {
	cfg   config.Config
	log   *slog.Logger
	db    *store.DB
	audit *audit.Logger
	// gelf is the audit logger's GELF sink: a switch the integrations service swaps
	// shippers into (tech_doc §34); empty (rows dropped) outside serve. integrations is
	// that service (serve only; nil in the CLI subcommands).
	gelf         *audit.SwitchSink
	integrations *integrations.Service
	// stopShipping flushes and stops a CLI command's GELF shipper (nil: none).
	stopShipping func()
	// registry is the server registry once serve opened it (the GELF policy denies its
	// BMC addresses).
	registry atomic.Pointer[registry.Service]
	authn    *auth.Authenticator
	tokens   *auth.TokenService
	admin    *admin.Service // settings S1 changes (users, links, tokens), each audited in its transaction
	// settings is the runtime-managed General section (file > DB > default) and the
	// per-user display preferences (slice S2); auth, the UI and the fleet read it live.
	settings *settings.Service
	// csrfKey signs UI form tokens; derived from the app keys (secrets.PurposeCSRF).
	csrfKey []byte
	// stepUpOverride is env.stepUpWindow (a test hook; zero in production).
	stepUpOverride time.Duration
	// credKey seals browser-saved BMC credentials (secrets.PurposeBMCCred); tofuKey
	// signs fingerprint proofs (secrets.PurposeTOFU).
	credKey, tofuKey []byte
	// notifyKey seals notification target secrets (notify.PurposeNotify); notifyTap
	// forwards audit records to the notifications service once it exists; chainBroken
	// records a failed startup verification for the notifications (tech_doc §26).
	notifyKey   []byte
	notifyTap   *lateTap
	chainBroken bool
	// logins counts failed sign-ins for /metrics (auth.Config.OnFailure).
	logins *metrics.LoginCounter
	// firstRun is the browser setup and generated-keys notice (plan 09); serve only.
	firstRun *firstrun.Service
}

func newLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level}))
}

// parseFlags parses -config (and -username when wantUser) and loads the config with load
// (loadServeConfig for serve, loadConfig for the CLI). It also returns the start notes:
// serve logs them, the CLI prints the problems among them.
func parseFlags(name string, args []string, e env, wantUser bool, load configLoader) (config.Config, string, []startNote, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.errOut)
	path := addConfigFlag(fs)
	var user *string
	if wantUser {
		user = fs.String("username", "", "account name (lowercase letters, digits, . _ -)")
	}
	if err := fs.Parse(args); err != nil {
		return config.Config{}, "", nil, err
	}
	if fs.NArg() > 0 {
		return config.Config{}, "", nil, fmt.Errorf("%s: unexpected arguments %v", name, fs.Args())
	}
	username := ""
	if wantUser {
		if *user == "" {
			return config.Config{}, "", nil, fmt.Errorf("%s: -username is required", name)
		}
		username = *user
	}
	cfg, notes, err := load(e, *path)
	return cfg, username, notes, err
}

// openCore loads the app keys, opens the store and builds audit + auth.
func openCore(ctx context.Context, cfg config.Config, log *slog.Logger) (*core, error) {
	// Before any migration: a data directory the process cannot write fails here, with the fix.
	if err := firstrun.CheckWritable(filepath.Dir(cfg.Storage.DBPath)); err != nil {
		return nil, err
	}
	ids, err := secrets.LoadIdentities(cfg.Secrets.IdentityFile)
	if err != nil {
		return nil, err
	}
	keys, err := secrets.LoadAppKeys(cfg.Secrets.AppKeysFile, ids)
	if err != nil {
		return nil, err
	}
	db, err := store.Open(ctx, cfg.Storage.DBPath)
	if err != nil {
		return nil, err
	}
	c := &core{cfg: cfg, log: log, db: db}
	if err := c.init(keys); err != nil {
		return nil, errors.Join(err, db.Close())
	}
	return c, nil
}

// deriveKeys derives the per-purpose subkeys of the app keys.
func (c *core) deriveKeys(keys secrets.AppKeys) error {
	var err error
	if c.csrfKey, err = keys.DeriveKey(secrets.PurposeCSRF); err != nil {
		return err
	}
	if c.credKey, err = keys.DeriveKey(secrets.PurposeBMCCred); err != nil {
		return err
	}
	if c.tofuKey, err = keys.DeriveKey(secrets.PurposeTOFU); err != nil {
		return err
	}
	c.notifyKey, err = keys.DeriveKey(secrets.PurposeNotify)
	return err
}

func (c *core) init(keys secrets.AppKeys) error {
	err := c.deriveKeys(keys)
	if err != nil {
		return err
	}
	c.gelf = &audit.SwitchSink{}
	c.notifyTap = &lateTap{}
	c.audit = audit.NewLogger(c.db.Audit(), teeSink(c.gelf, c.notifyTap), nil, c.log)
	c.settings, err = settings.New(context.Background(), settings.Config{DB: c.db, Audit: c.audit, File: c.cfg, Logger: c.log})
	if err != nil {
		return err
	}
	hasher, err := auth.NewPasswordHasher(auth.DefaultArgon2Params(), maxConcurrentHashes)
	if err != nil {
		return err
	}
	sealer, err := auth.NewAESGCMSealer(keys.TOTPKey.Bytes())
	if err != nil {
		return err
	}
	repos := authrepo.New(c.db)
	c.logins = &metrics.LoginCounter{}
	c.authn, err = auth.New(auth.Config{
		Users: repos.Users, Sessions: repos.Sessions, Lockouts: repos.Lockouts,
		Hasher: hasher, Sealer: sealer, Logger: c.log,
		SessionIdle: c.cfg.Auth.SessionIdle, SessionMax: c.cfg.Auth.SessionMax, StepUpWindow: c.cfg.Auth.StepUpWindow,
		Policy:    c.authPolicy,
		OnFailure: c.logins.Failure,
	})
	if err != nil {
		return err
	}
	c.tokens, err = auth.NewTokenService(repos.Tokens, nil)
	if err != nil {
		return err
	}
	c.admin, err = admin.New(admin.Config{DB: c.db, Audit: c.audit, Hasher: hasher, Sealer: sealer,
		Tokens: c.tokens, Logger: c.log})
	return err
}

// authPolicy is the live session and step-up policy from Settings → General.
func (c *core) authPolicy() auth.Policy {
	g := c.settings.Current().General
	p := auth.Policy{SessionIdle: g.SessionIdle, SessionMax: g.SessionMax, StepUpWindow: g.StepUpWindow}
	if c.stepUpOverride > 0 {
		p.StepUpWindow = c.stepUpOverride
	}
	return p
}

// effective is the config with the General settings in force (file > DB > default).
func (c *core) effective() config.Config { return c.cfg.WithGeneral(c.settings.Current().General) }

// cliActor is the audit principal of changes made from the shell (trusted).
var cliActor = admin.Actor{Username: "cli", Method: "cli"}

// record writes a system audit entry; a failure is logged and returned.
func (c *core) record(ctx context.Context, principal, action string, params map[string]any) error {
	_, err := c.audit.Record(ctx, audit.Entry{
		Principal: principal, AuthMethod: "system", Action: action, Params: params, Result: audit.ResultOK,
	})
	if err != nil {
		c.log.Error("audit record failed", "action", action, "error", err)
	}
	return err
}

// verifyAudit checks the hash chain at startup (security.md T3). A broken chain is
// logged loudly but does not stop the app: the evidence must stay inspectable.
func (c *core) verifyAudit(ctx context.Context) {
	res, err := audit.Verify(ctx, c.db.Audit(), audit.DefaultVerifyPage)
	if err != nil {
		c.log.Error("audit chain verification FAILED", "error", err)
		c.chainBroken = true
		return
	}
	c.log.Info("audit chain verified", "rows", res.Count, "head", res.Head)
}

func (c *core) close() error {
	if c.stopShipping != nil {
		c.stopShipping()
	}
	return c.db.Close()
}

// cliShipFlush bounds how long a CLI command waits on exit for its audit rows to reach
// the log server.
const cliShipFlush = 3 * time.Second

// startCLIShipping gives a CLI command that writes audit rows the same GELF shipping as
// serve (review H2-M1: admin-recover, reset-totp, bootstrap-admin, settings import, token
// and catalog changes), so the break-glass row and every other CLI row reach the log
// server and drill 7's head comparison holds. Best effort: a failure to build or deliver
// only warns, and close() flushes for at most cliShipFlush. The registry is not loaded
// here; the policy still denies every BMC address, read from config.yaml and the server
// rows (core.storedBMCAddrs).
func (c *core) startCLIShipping(e env) {
	if err := c.buildIntegrations(e.gelfDial); err != nil {
		c.log.Warn("audit shipping to the log server is unavailable for this command", "error", err)
		return
	}
	ctx, cancel := context.WithCancel(context.WithoutCancel(e.ctx))
	done := make(chan struct{})
	go func() { defer close(done); c.integrations.Run(ctx) }()
	c.stopShipping = func() {
		fctx, fcancel := context.WithTimeout(context.Background(), cliShipFlush)
		ok := c.integrations.Flush(fctx)
		fcancel()
		if !ok {
			c.log.Warn("the audit rows of this command did not all reach the log server; they are in the local audit chain")
		}
		cancel()
		<-done
	}
}

// openRegistry loads the effective server registry (config.yaml + browser-managed
// servers). Only serve and the settings CLI open it: shadowed rows are audited once per
// start.
func (c *core) openRegistry(ctx context.Context) (*registry.Service, error) {
	cs, err := credstore.New(c.credKey)
	if err != nil {
		return nil, err
	}
	reg, err := registry.New(ctx, registry.Config{DB: c.db, Audit: c.audit, File: c.cfg, Creds: cs, Self: selfAddrs(c.cfg),
		Logger: c.log, LeaseActive: c.leaseActive})
	if err == nil {
		c.registry.Store(reg) // the GELF policy denies its BMC addresses
	}
	return reg, err
}

func interfaceAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, perr := netip.ParsePrefix(a.String()); perr == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out
}

// leaseActive reports an active fan lease (registry refuses fan and address changes).
func (c *core) leaseActive(ctx context.Context, id string) (bool, error) {
	_, err := c.db.Leases().Active(ctx, id)
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, store.ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}

// selfAddrs are the app's own addresses, never a BMC: every local interface address
// (inside a bridge container, the container's own; the host is reached through the
// gateway, which netpolicy cannot know) plus a literal listen or public_url address.
func selfAddrs(cfg config.Config) []netip.Addr {
	out := interfaceAddrs()
	if host, _, err := net.SplitHostPort(cfg.Listen); err == nil {
		if a, perr := netip.ParseAddr(host); perr == nil && !a.IsUnspecified() {
			out = append(out, a)
		}
	}
	if u, err := url.Parse(cfg.PublicURL); err == nil {
		if a, perr := netip.ParseAddr(u.Hostname()); perr == nil {
			out = append(out, a)
		}
	}
	return out
}

// staleMultiplier is the live poll.stale_multiplier for the fleet's stale flag.
func (c *core) staleMultiplier() int { return c.settings.Current().General.StaleMultiplier }

// sampling is the live history switches (Settings → General) for the fleet's sampler.
func (c *core) sampling() fleet.Sampling {
	g := c.settings.Current().General
	return fleet.Sampling{PSUs: g.SamplePSUs, Voltages: g.SampleVoltages}
}
