package main

import (
	"context"
	"log/slog"

	"oob-manager/internal/bmc/dellredfish"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/config"
	"oob-manager/internal/fan"
	"oob-manager/internal/fan/hostlease"
	"oob-manager/internal/fan/redfishfloor"
	"oob-manager/internal/store"
)

// buildFans builds the fan lease service. host-lease servers get the lease file applier
// (storage.lease_dir); redfish-floor servers get the BMC minimum fan speed applier with
// the operator login. A server whose applier cannot be built (missing operator login,
// ipmi-oem which is not implemented) is logged and left without fan control, like the
// console does, instead of failing startup. endpoint overrides the BMC address (e2e).
//
// The service starts empty and gets its setup through SetTargets, the same path every
// later registry change takes, so each server carries a fingerprint from the start (an
// unchanged server keeps its lease across changes).
func buildFans(cfg config.Config, db *store.DB, creds credLookup, aud fan.Auditor,
	endpoint func(config.Server) string, log *slog.Logger) (*fan.Service, error) {
	svc, err := fan.New(fan.Config{Leases: db.Leases(), Audit: aud, Logger: log})
	if err != nil {
		return nil, err
	}
	if err := svc.SetTargets(context.Background(), fanTargets(cfg, creds, endpoint, log)); err != nil {
		return nil, err
	}
	return svc, nil
}

// fanTargets builds the fan setup of cfg's servers. A server whose applier cannot be
// built is logged and gets no fan control.
func fanTargets(cfg config.Config, creds credLookup, endpoint func(config.Server) string, log *slog.Logger) []fan.Target {
	if endpoint == nil {
		endpoint = defaultEndpoint
	}
	out := make([]fan.Target, 0, len(cfg.Servers))
	for _, s := range cfg.Servers {
		p := fan.PolicyFor(s)
		t := fan.Target{Policy: p}
		if p.Enabled() {
			ap, err := fanApplier(cfg, s, creds, endpoint)
			if err != nil {
				log.Warn("fan control disabled for this server", "server", s.ID, "mode", s.Fan.Mode, "reason", err.Error())
				t.Policy.Mode = config.FanNone
			} else {
				t.Applier, t.Fingerprint = ap, targetFingerprint(s, endpoint(s), loginOf(creds, s.Credentials.Operator), cfg.Storage.LeaseDir)
			}
		}
		out = append(out, t)
	}
	return out
}

type fanSetupError string

func (e fanSetupError) Error() string { return string(e) }

func fanApplier(cfg config.Config, s config.Server, creds credLookup,
	endpoint func(config.Server) string) (fan.Applier, error) {
	switch s.Fan.Mode {
	case config.FanHostLease:
		return hostlease.New(hostlease.Config{Dir: cfg.Storage.LeaseDir, ServerID: s.ID})
	case config.FanRedfishFloor:
		op, err := creds.Lookup(s.Credentials.Operator)
		if err != nil || !op.HasLogin() {
			return nil, fanSetupError("operator credential missing")
		}
		return redfishfloor.New(dellredfish.NewFanFloorClient(redfish.Config{Endpoint: endpoint(s),
			Username: op.Username, Password: op.Password.Reveal(), PinSHA256: s.TLSPinSHA256,
			Timeout: s.BMC.Timeouts.Request, Auth: redfish.AuthMode(s.BMC.Auth)})), nil
	case config.FanIPMIOEM:
		return nil, fanSetupError("ipmi-oem is not implemented in this version")
	default:
		return nil, fanSetupError("no fan control")
	}
}
