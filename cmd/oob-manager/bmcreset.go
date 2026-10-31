package main

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"oob-manager/internal/api"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/bmcreset"
	"oob-manager/internal/config"
	"oob-manager/internal/fleet"
	"oob-manager/internal/metrics"
	"oob-manager/internal/store"
)

// buildBMCReset builds the BMC restart service (tech_doc §37) over the fleet's restart
// window, the power interlock, both console brokers and the fan service. Its targets
// follow the registry (serverRuntime.apply); Start runs once the fleet has servers.
func buildBMCReset(cfg config.Config, c *core, creds credLookup, e env, fl *fleet.Fleet, cd consoleDeps,
	log *slog.Logger) (*bmcreset.Service, error) {
	bc := bmcreset.Config{Targets: bmcResetTargets(cfg, creds, e.kvmEndpoint, log), Audit: c.audit,
		Store: c.db.BMCResets(), Fleet: fl, Logger: log, AfterBack: afterBMCBack(cd, log, fanReapplyWait)}
	if cd.fans != nil {
		bc.AfterTimeout = cd.fans.RequestReapply // a late return: the reconciler applies the floor
	}
	if cd.power != nil {
		bc.Power = cd.power
	}
	if cd.svc != nil {
		bc.Consoles = append(bc.Consoles, cd.svc)
	}
	if cd.serial != nil {
		bc.Consoles = append(bc.Consoles, cd.serial)
	}
	return bmcreset.New(bc)
}

// fanReapplyWait is the first pause between re-apply attempts right after a BMC's
// return (doubling; the whole AfterBack is bounded to 2 minutes).
const fanReapplyWait = 5 * time.Second

// afterBMCBack forgets what the consoles learned about the old BMC session and applies a
// BMC-side fan floor again once a restarted BMC answers. A BMC that is up but not yet
// ready for the PATCH is retried with backoff (review C-M3); if it still fails, the fan
// reconciler keeps trying (RequestReapply).
func afterBMCBack(cd consoleDeps, log *slog.Logger, wait time.Duration) func(ctx context.Context, id string) {
	return func(ctx context.Context, id string) {
		if cd.svc != nil {
			cd.svc.ForgetProbe(id)
		}
		if cd.serial != nil {
			cd.serial.ForgetAttempt(id)
		}
		if cd.fans != nil {
			reapplyFanFloor(ctx, cd.fans, id, wait, log)
		}
	}
}

// fanReapplier is the part of the fan service the BMC restart uses (*fan.Service).
type fanReapplier interface {
	ReapplyAfterBMCReset(ctx context.Context, serverID string) (bool, error)
	RequestReapply(serverID string)
}

// fanReapplyAttempts is how many times AfterBack tries before handing over.
const fanReapplyAttempts = 4

// reapplyFanFloor tries the re-apply up to fanReapplyAttempts times, pausing wait, 2×wait,
// 4×wait between attempts (none after the last); if every attempt fails or ctx ends, the
// fan reconciler takes over (RequestReapply).
func reapplyFanFloor(ctx context.Context, f fanReapplier, id string, wait time.Duration, log *slog.Logger) {
	for attempt := range fanReapplyAttempts {
		if _, err := f.ReapplyAfterBMCReset(ctx, id); err == nil {
			return
		}
		if attempt == fanReapplyAttempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			log.Warn("bmc restart: the fan floor could not be applied again yet; the fan reconciler retries it", "server", id)
			f.RequestReapply(id)
			return
		case <-time.After(wait << attempt):
		}
	}
	log.Warn("bmc restart: the fan floor could not be applied again yet; the fan reconciler retries it", "server", id)
	f.RequestReapply(id)
}

// bmcResetTargets builds one target per server. The restart uses the operator login
// (credentials.operator) on a Redfish BMC; without it the action is disabled with that
// reason. IPMI mc reset is out of scope.
func bmcResetTargets(cfg config.Config, creds credLookup, endpoint func(config.Server) string,
	log *slog.Logger) []bmcreset.Target {
	if endpoint == nil {
		endpoint = defaultEndpoint
	}
	out := make([]bmcreset.Target, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		t := bmcreset.Target{ServerID: s.ID, Deadline: bmcreset.Deadline(s.BMC.Kind), SelfHost: s.Power.SelfHost}
		t.Open = bmcResetOpener(s, creds, endpoint, log)
		out = append(out, t)
	}
	return out
}

func bmcResetOpener(s config.Server, creds credLookup, endpoint func(config.Server) string, log *slog.Logger) bmcreset.Opener {
	if s.BMC.Kind == config.KindIPMI || s.Credentials.Operator == "" {
		return nil
	}
	op, err := creds.Lookup(s.Credentials.Operator)
	if err != nil || !op.HasLogin() {
		log.Warn("bmc restart unavailable: operator credential missing", "server", s.ID)
		return nil
	}
	rc := redfish.Config{Endpoint: endpoint(s), Username: op.Username, Password: op.Password.Reveal(),
		PinSHA256: s.TLSPinSHA256, Timeout: s.BMC.Timeouts.Request, Auth: redfish.AuthMode(s.BMC.Auth)}
	return func(ctx context.Context) (bmcreset.Resetter, error) {
		r, err := redfish.OpenManagerResetter(ctx, rc)
		if err != nil {
			return nil, err
		}
		return r, nil
	}
}

// powerInterlock is the power service's Restarting hook: a server whose BMC restart is
// being requested (login, discovery, POST: review S-M1) or whose BMC is restarting takes
// no power action. The BMC reset service is built after the power service, so it is
// late-bound through bmc.
func powerInterlock(fl *fleet.Fleet, bmc *atomic.Pointer[bmcreset.Service]) func(id string) bool {
	return func(id string) bool {
		if s, ok := fl.Server(id); ok && s.Restarting {
			return true
		}
		svc := bmc.Load()
		return svc != nil && svc.Busy(id)
	}
}

// apiBMCReset and metricsBMCReset adapt the service's in-memory state (no BMC call).
func apiBMCReset(s *bmcreset.Service) func(id string) (api.BMCResetRecord, bool) {
	if s == nil {
		return nil
	}
	return func(id string) (api.BMCResetRecord, bool) {
		st := s.State(id)
		if !st.HasLast {
			return api.BMCResetRecord{}, false
		}
		return api.BMCResetRecord{At: st.Last.RequestedAt, By: st.Last.By, Result: st.Last.Result}, true
	}
}

func metricsBMCReset(s *bmcreset.Service) func(id string) metrics.BMCResetState {
	if s == nil {
		return nil
	}
	return func(id string) metrics.BMCResetState {
		st := metrics.BMCResetState{Counts: s.Counts()[id]}
		if v := s.State(id); v.HasVerified && v.LastVerified.Result == store.BMCResetVerified {
			st.LastVerified = v.LastVerified.RequestedAt
		}
		return st
	}
}
