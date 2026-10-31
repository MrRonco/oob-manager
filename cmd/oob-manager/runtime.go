package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/bmcsec"
	"oob-manager/internal/config"
	"oob-manager/internal/fleet"
	"oob-manager/internal/registry"
	"oob-manager/internal/secrets"
	"oob-manager/internal/secrets/credstore"
)

// serverRuntime builds the pollers and the features (consoles, power, fans, native console
// launch, BMC links) from the effective server registry, and rebuilds them without a
// restart whenever the registry changes (settings slice S3, settings_design.md §5).
type serverRuntime struct {
	base  config.Config // effective General settings; Servers is replaced per apply
	c     *core
	reg   *registry.Service
	file  secrets.Credentials
	e     env
	log   *slog.Logger
	fleet *fleet.Fleet
	cd    consoleDeps
	links atomic.Pointer[links]
	// inputs are the security check evaluation inputs per server (security.go).
	inputs atomic.Pointer[map[string]bmcsec.Inputs]
	mu     sync.Mutex // serialises apply
	// notify follows the registry (maintenance windows of removed servers end); nil until
	// serve has built it.
	notify serverNotifier
	// fwSink is the fleet's firmware sink, wired to the firmware view by serve (firmware.go).
	fwSink *firmwareSink
	// history follows the registry (the rows of removed servers go; history.go).
	history historySync
}

// links are the per-server facts the UI reads live: the BMC web UI address and whether
// a Dell Lifecycle Controller log exists.
type links struct {
	web  map[string]string
	dell map[string]bool
}

// newRuntime builds every service empty and applies the registry once. At startup a
// config.yaml server whose read-only credential is missing fails, as before; a
// browser-managed server that cannot be built is logged and skipped.
func newRuntime(ctx context.Context, base config.Config, c *core, reg *registry.Service, file secrets.Credentials,
	e env, log *slog.Logger) (*serverRuntime, error) {
	rt := &serverRuntime{base: base, c: c, reg: reg, file: file, e: e, log: log, fwSink: &firmwareSink{}}
	empty := base.WithGeneral(base.General())
	empty.Servers = nil
	fl, err := buildFleet(empty, c.db, file, e.newDriver, log, c.staleMultiplier, c.sampling, e.restart, rt.fwSink)
	if err != nil {
		return nil, err
	}
	cd, err := buildFeatures(empty, c, file, e, fl, log)
	if err != nil {
		return nil, err
	}
	rt.fleet, rt.cd = fl, cd
	rt.links.Store(&links{web: map[string]string{}, dell: map[string]bool{}})
	if err := rt.apply(ctx, true); err != nil {
		return nil, err
	}
	// Re-arm the restart window of a BMC restart that was running when the app stopped.
	if err := cd.bmc.Start(ctx); err != nil {
		return nil, err
	}
	return rt, nil
}

// applyRetry is how long a failed apply waits before it is tried again.
const applyRetry = 30 * time.Second

// run re-applies the registry after every registry or General settings change (the
// poll interval applies live) until ctx ends. A failed apply is retried, so a partial
// one never stays in place until the next change.
func (rt *serverRuntime) run(ctx context.Context) {
	var retry <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-rt.reg.Changes():
		case <-rt.c.settings.Changes(): // poll.interval is live
		case <-retry:
		}
		retry = nil
		if err := rt.apply(ctx, false); err != nil && ctx.Err() == nil {
			rt.log.Error("servers: applying the registry failed; retrying", "err", err, "in", applyRetry)
			retry = time.After(applyRetry)
		}
	}
}

// apply builds every target from the active registry entries and hands them to the
// services. Fans go first, so a lease on a removed or changed server is restored before
// anything else changes; consoles on changed servers end; the fleet is swapped last.
func (rt *serverRuntime) apply(ctx context.Context, startup bool) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	cfg, creds, intervals, err := rt.active(ctx, startup)
	if err != nil {
		return err
	}
	if err = rt.cd.fans.SetTargets(ctx, fanTargets(cfg, creds, rt.e.kvmEndpoint, rt.log)); err != nil {
		return err
	}
	vnc, err := consoleTargets(cfg, creds, rt.log)
	if err != nil {
		return err
	}
	serial, err := serialTargets(cfg, creds, rt.log)
	if err != nil {
		return err
	}
	err = errors.Join(rt.cd.svc.SetTargets(vnc), rt.cd.serial.SetTargets(serial),
		rt.cd.power.SetTargets(powerTargets(cfg, creds, rt.e.kvmEndpoint, rt.log)),
		rt.cd.bmc.SetTargets(bmcResetTargets(cfg, creds, rt.e.kvmEndpoint, rt.log)))
	if err != nil {
		return err
	}
	rt.cd.kvm.set(kvmTargets(cfg, creds, rt.e.kvmEndpoint, rt.log))
	rt.links.Store(linksOf(cfg))
	inputs := securityInputs(cfg)
	rt.inputs.Store(&inputs)
	targets, err := fleetTargets(cfg, creds, rt.e.newDriver, intervals, rt.postureFor, rt.log)
	if err != nil {
		return err
	}
	if err = rt.fleet.Apply(targets); err != nil {
		return err
	}
	return errors.Join(rt.syncNotify(ctx), rt.syncFirmware(ctx), rt.syncHistory(ctx))
}

// active is the base config with the running servers, the credentials they use and
// each server's poll interval override.
func (rt *serverRuntime) active(ctx context.Context, startup bool) (config.Config, credSet, map[string]int64, error) {
	cfg := rt.base.WithGeneral(rt.c.settings.Current().General)
	cfg.Servers = nil
	creds := credSet{file: rt.file, db: map[string]secrets.Credential{}}
	intervals := map[string]int64{}
	for _, x := range rt.reg.Current().Active() {
		s := x.Server
		if x.Source == registry.SourceDB {
			var ok bool
			if s, ok = rt.openDB(ctx, x, creds); !ok {
				continue
			}
		} else if _, err := rt.file.Lookup(s.Credentials.ReadOnly); err != nil && startup {
			return config.Config{}, credSet{}, nil, fmt.Errorf("server %s: %w", s.ID, err)
		}
		intervals[s.ID] = int64(x.PollInterval)
		cfg.Servers = append(cfg.Servers, s)
	}
	return cfg, creds, intervals, nil
}

// openDB opens a browser-managed server's stored credentials into creds and returns
// the server with in-memory refs. Without its read-only login it cannot be polled.
func (rt *serverRuntime) openDB(ctx context.Context, x registry.Entry, creds credSet) (config.Server, bool) {
	s := withDBRefs(x.Server)
	for _, ci := range x.Creds {
		c, err := rt.reg.Credential(ctx, s.ID, ci.Slot)
		if err != nil {
			rt.log.Warn("servers: a stored credential cannot be opened; enter it again", "server", s.ID, "slot", string(ci.Slot))
			continue
		}
		creds.db[dbRef(s.ID, ci.Slot)] = c
	}
	if _, ok := creds.db[dbRef(s.ID, credstore.SlotReadOnly)]; !ok {
		rt.log.Warn("servers: not polled: the read-only login is missing", "server", s.ID)
		return config.Server{}, false
	}
	return s, true
}

func linksOf(cfg config.Config) *links {
	l := &links{web: map[string]string{}, dell: map[string]bool{}}
	for _, s := range cfg.Servers {
		if s.BMC.Kind != config.KindIPMI {
			l.web[s.ID] = s.BMC.Endpoint() + "/"
		}
		l.dell[s.ID] = s.BMC.Kind == config.KindIDRAC8 || s.BMC.Kind == config.KindIDRAC9
	}
	return l
}

// webURL and lifecycle are the live lookups the UI takes.
func (rt *serverRuntime) webURL(id string) string { return rt.links.Load().web[id] }

func (rt *serverRuntime) lifecycle(id string) bool { return rt.links.Load().dell[id] }

// serverNotifier is what follows the registry: maintenance mode (*maint.Service), whose
// windows of removed servers end.
type serverNotifier interface {
	SyncServers(ctx context.Context, ids []string) error
}

// setNotify connects the notifications service once serve has built it (it needs the
// fleet, which the runtime owns) and syncs it with the registry right away.
func (rt *serverRuntime) setNotify(ctx context.Context, n serverNotifier) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.notify = n
	return rt.syncNotify(ctx)
}

// syncNotify hands every registry id (file and browser, enabled or not) to the
// maintenance (which ends the windows of removed servers) and the trust tap. The caller
// holds rt.mu. Disabled servers stay known (their window survives) but are not polled,
// so they raise no reachability or health alerts.
func (rt *serverRuntime) syncNotify(ctx context.Context) error {
	if rt.notify == nil {
		return nil
	}
	entries := rt.reg.Current().Entries()
	ids := make([]string, 0, len(entries))
	for _, x := range entries {
		ids = append(ids, x.Server.ID)
	}
	rt.c.notifyTap.keep(ids)
	return rt.notify.SyncServers(ctx, ids)
}
