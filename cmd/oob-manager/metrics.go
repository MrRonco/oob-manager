package main

import (
	"context"
	"net/http"
	"time"

	"oob-manager/internal/api"
	"oob-manager/internal/config"
	"oob-manager/internal/console"
	"oob-manager/internal/fan"
	"oob-manager/internal/fleet"
	"oob-manager/internal/maint"
	"oob-manager/internal/metrics"
	"oob-manager/internal/notify"
)

// buildMetrics returns the /metrics collector, or nil when metrics.enabled is false
// (the API then answers 404 on the path). Every source reads cached state only.
func buildMetrics(cfg config.Config, c *core, fl fleet.Reader, cd consoleDeps) (http.Handler, error) {
	if !cfg.Metrics.Enabled {
		return nil, nil
	}
	mc := metrics.Config{
		Fleet: fl, Logins: c.logins, IncludeInventory: cfg.Metrics.IncludeInventory,
		Build:     metrics.BuildInfo{Version: version, Commit: uiBuild(nil).Commit},
		StartTime: time.Now(),
		// The startup verification ran before serve builds handlers; the flag is not
		// written afterwards.
		AuditChainOK:  func() bool { return !c.chainBroken },
		ConsoleActive: consoleActive(cd.svc, cd.serial),
	}
	if c.integrations != nil {
		mc.Shipper = c.integrations
	}
	if cd.fans != nil {
		mc.FanStatus = fanStatus(cd.fans)
	}
	if cd.notify != nil {
		mc.NotifyTargets = notifyTargets(cd.notify)
	}
	mc.Maintenance, mc.Acked = maintMetrics(cd.maint)
	mc.Security = securityCounts(cd.security)
	mc.BMCReset = metricsBMCReset(cd.bmc)
	mc.Firmware = firmwareCounts(cd.firmware)
	mc.Catalog = catalogMetrics(cd.catalog)
	mc.History = historyState(cd.history)
	return metrics.New(mc)
}

// maintMetrics adapts maintenance windows and acknowledgements (lock-free reads of the
// service's published state); nil hooks without the service.
func maintMetrics(m *maint.Service) (func(string) metrics.MaintenanceState, func(string, string, string, time.Time) bool) {
	if m == nil {
		return nil, nil
	}
	state := func(id string) metrics.MaintenanceState {
		w, ok := m.Active(id)
		if !ok {
			return metrics.MaintenanceState{}
		}
		return metrics.MaintenanceState{Active: true, Until: w.EndsAt}
	}
	return state, m.Acked
}

// fanStatus adapts fan.Service.Status (a lease table read; it never contacts a BMC).
func fanStatus(s *fan.Service) func(ctx context.Context, id string) (metrics.FanState, bool) {
	return func(ctx context.Context, id string) (metrics.FanState, bool) {
		st, err := s.Status(ctx, id)
		if err != nil {
			return metrics.FanState{}, false
		}
		return metrics.FanState{LeaseActive: st.HasLease, LeasePct: st.Lease.Pct, Remaining: st.Remaining,
			AppliedPct: st.AppliedPct, HasApplied: st.HasPct}, true
	}
}

func consoleActive(vnc *console.Service, serial *console.SerialService) func(id string) (bool, bool) {
	return func(id string) (bool, bool) {
		var v, s bool
		if vnc != nil {
			v = vnc.Status(id).InUse
		}
		if serial != nil {
			s = serial.Status(id).InUse
		}
		return v, s
	}
}

func notifyTargets(s *notify.Service) func() []metrics.NotifyTarget {
	return func() []metrics.NotifyTarget {
		views := s.Targets()
		out := make([]metrics.NotifyTarget, 0, len(views))
		for _, v := range views {
			st := v.Status
			out = append(out, metrics.NotifyTarget{ID: v.Target.ID, Enabled: v.Target.Enabled, Failing: st.Failing,
				ConsecutiveFailures: st.ConsecutiveFailures, Sent: st.Sent, Dropped: st.Dropped})
		}
		return out
	}
}

// buildAPI builds the JSON API, the probes and (when enabled) /metrics.
func buildAPI(cfg config.Config, c *core, fl fleet.Reader, cd consoleDeps) (*api.API, error) {
	var shipper api.ShipperStatus // untyped nil without the service (zero stats when GELF is off)
	if c.integrations != nil {
		shipper = c.integrations
	}
	metricsH, err := buildMetrics(cfg, c, fl, cd)
	if err != nil {
		return nil, err
	}
	return api.New(api.Deps{Fleet: fl, Tokens: c.tokens, DB: c.db, Shipper: shipper,
		Version: version, Logger: c.log, Maintenance: apiMaint(cd.maint), BMCReset: apiBMCReset(cd.bmc),
		Firmware: apiFirmware(cd.firmware), History: apiHistory(cd.history),
		Metrics: metricsH, MetricsNetworks: cfg.Metrics.Networks()})
}
