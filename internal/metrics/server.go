package metrics

import (
	"context"
	"strings"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
)

func unixSeconds(t time.Time) float64 { return float64(t.UnixNano()) / 1e9 }

// collectServer adds one server's families. Sensor readings are left out while the
// cached data is stale, so a dead BMC does not keep reporting its last temperatures.
func (c *Collector) collectServer(ctx context.Context, b *builder, s fleet.ServerState, now time.Time) {
	sl := Label{"server", s.ID}
	c.addInfo(b, s, sl)
	b.add("oob_server_up", b2f(s.Reachable()), sl)
	b.add("oob_server_stale", b2f(s.Stale), sl)
	b.add("oob_server_paused", b2f(s.Paused), sl)
	b.add("oob_server_consecutive_failures", float64(s.ConsecutiveFailures), sl)
	c.addMaintenance(b, s.ID, sl)
	c.addBMCReset(b, s, sl)
	if !s.LastSuccess.IsZero() {
		b.add("oob_server_last_success_timestamp_seconds", unixSeconds(s.LastSuccess), sl)
		b.add("oob_server_poll_duration_seconds", s.LastPollDuration.Seconds(), sl)
		b.add("oob_server_data_age_seconds", max(now.Sub(s.LastSuccess), 0).Seconds(), sl)
	}
	fresh := s.HasSnapshot && !s.Stale
	addEnum(b, "oob_server_health", sl, serverHealthStates(), healthState(s, fresh))
	addEnum(b, "oob_server_power_state", sl, powerStates(), powerState(s, fresh))
	c.addFans(ctx, b, s.ID, sl)
	addLogs(b, s, sl)
	c.addUnacked(b, s, sl)
	c.addSecurity(b, s, sl)
	c.addFirmware(b, s, sl)
	if c.cfg.History != nil {
		b.add("oob_history_keys_refused_total", float64(s.HistoryRefused), sl)
	}
	if fresh {
		addSensors(b, s.Snapshot, sl)
	}
}

func (c *Collector) addInfo(b *builder, s fleet.ServerState, sl Label) {
	ls := []Label{sl, {"name", s.Name}}
	if c.cfg.IncludeInventory && s.HasInventory {
		inv := s.Inventory.Info()
		ls = append(ls, Label{"model", inv.Model}, Label{"serial", inv.SerialNumber}, Label{"service_tag", inv.SKU},
			Label{"bios_version", inv.BIOSVersion}, Label{"bmc_firmware", inv.BMCFirmware},
			Label{"license_tier", string(s.Inventory.License().Tier)})
	}
	b.add("oob_server_info", 1, ls...)
}

// addEnum writes one series per state, 1 for current and 0 for the others.
func addEnum(b *builder, name string, sl Label, states []string, current string) {
	for _, st := range states {
		b.add(name, b2f(st == current), sl, Label{"state", st})
	}
}

// healthState is the verdict: the worst of the BMC rollup and every component, or
// "off" while the host is powered off (or powering off) and nothing is critical.
func healthState(s fleet.ServerState, fresh bool) string {
	if !fresh {
		return "unknown"
	}
	snap := s.Snapshot
	worst := strings.ToLower(string(sensorHealth(snap)))
	if p := snap.PowerState(); (p == bmc.PowerOff || p == bmc.PowerPoweringOff) && worst != "critical" {
		return "off"
	}
	return worst
}

func sensorHealth(snap bmc.Snapshot) bmc.Health {
	hs := []bmc.Health{snap.Health()}
	for _, t := range snap.Temperatures() {
		hs = append(hs, t.Health)
	}
	for _, f := range snap.Fans() {
		hs = append(hs, f.Health)
	}
	for _, p := range snap.PSUs() {
		hs = append(hs, p.Health)
	}
	return bmc.WorstHealth(hs...)
}

func powerState(s fleet.ServerState, fresh bool) string {
	if !fresh {
		return "unknown"
	}
	switch s.Snapshot.PowerState() {
	case bmc.PowerOn:
		return "on"
	case bmc.PowerOff:
		return "off"
	case bmc.PowerPoweringOn:
		return "powering_on"
	case bmc.PowerPoweringOff:
		return "powering_off"
	default:
		return "unknown"
	}
}

func (c *Collector) addFans(ctx context.Context, b *builder, id string, sl Label) {
	if c.cfg.FanStatus == nil {
		return
	}
	st, ok := c.cfg.FanStatus(ctx, id)
	if !ok {
		return
	}
	b.add("oob_fan_lease_active", b2f(st.LeaseActive), sl)
	if st.LeaseActive {
		b.add("oob_fan_lease_percent", float64(st.LeasePct), sl)
		b.add("oob_fan_lease_remaining_seconds", st.Remaining.Seconds(), sl)
	}
	if st.HasApplied {
		b.add("oob_fan_applied_percent", float64(st.AppliedPct), sl)
	}
}

func addLogs(b *builder, s fleet.ServerState, sl Label) {
	add := func(kind string, log bmc.EventLog, has bool) {
		if !has {
			return
		}
		counts := map[string]int{}
		for _, e := range log.Entries() {
			counts[strings.ToLower(string(e.Severity))]++
		}
		for _, sev := range healthStates() {
			b.add("oob_log_entries", float64(counts[sev]), sl, Label{"log", kind}, Label{"severity", sev})
		}
	}
	add("sel", s.SEL, s.HasSEL)
	add("lifecycle", s.Lifecycle, s.HasLifecycle)
}
