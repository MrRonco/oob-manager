package main

import (
	"context"
	"log/slog"
	"time"

	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/config"
	"oob-manager/internal/fleet"
	"oob-manager/internal/power"
)

// powerPollEvery is how often a power action's transition is checked. Slow BMCs
// (iDRAC8: 1-3 s per GET) make faster polling pointless.
const powerPollEvery = 3 * time.Second

// buildPower builds the power service. Every configured server is a target; it can be
// controlled only with an operator login (credentials.operator) and a Redfish BMC. A
// missing login is not fatal: the Power menu says what to set up. IPMI chassis
// control (task 2.2) is not implemented: ipmi servers get no power actions.
func buildPower(cfg config.Config, creds credLookup, aud power.Auditor, endpoint func(config.Server) string,
	observe func(string, power.Observation), restarting func(string) bool, log *slog.Logger) (*power.Service, error) {
	return power.New(power.Config{Targets: powerTargets(cfg, creds, endpoint, log), Audit: aud, Logger: log,
		PollEvery: powerPollEvery, OnVerified: observe, Restarting: restarting})
}

// powerObserver hands verified power transitions to the fleet, so every reader (UI, API,
// metrics, notifications) shows the new state at once (audit R2-08). nil fleet: no-op.
func powerObserver(fl *fleet.Fleet) func(string, power.Observation) {
	if fl == nil {
		return nil
	}
	return func(id string, o power.Observation) {
		fl.ObservePower(id, fleet.PowerObservation{State: o.State, At: o.At, Action: string(o.Action), By: o.By})
	}
}

// powerTargets builds the power targets of cfg's servers.
func powerTargets(cfg config.Config, creds credLookup, endpoint func(config.Server) string, log *slog.Logger) []power.Target {
	if endpoint == nil {
		endpoint = defaultEndpoint
	}
	targets := make([]power.Target, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		t := power.Target{ServerID: s.ID, SelfHost: s.Power.SelfHost, Impact: s.Power.Impact}
		t.Open = powerOpener(s, creds, endpoint, log)
		targets = append(targets, t)
	}
	return targets
}

// powerOpener returns the operator-login opener of s, or nil (with a warning) when s
// cannot be controlled.
func powerOpener(s config.Server, creds credLookup, endpoint func(config.Server) string, log *slog.Logger) power.Opener {
	if s.BMC.Kind == config.KindIPMI {
		log.Warn("power control unavailable: IPMI chassis control is not implemented", "server", s.ID)
		return nil
	}
	if s.Credentials.Operator == "" {
		return nil
	}
	op, err := creds.Lookup(s.Credentials.Operator)
	if err != nil || !op.HasLogin() {
		log.Warn("power control unavailable: operator credential missing", "server", s.ID)
		return nil
	}
	rc := redfish.Config{Endpoint: endpoint(s), Username: op.Username, Password: op.Password.Reveal(),
		PinSHA256: s.TLSPinSHA256, Timeout: s.BMC.Timeouts.Request, Auth: redfish.AuthMode(s.BMC.Auth)}
	return func(ctx context.Context) (power.Controller, error) {
		r, err := redfish.OpenResetter(ctx, rc)
		if err != nil {
			return nil, err
		}
		return r, nil
	}
}
