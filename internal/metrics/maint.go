package metrics

import (
	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
)

// addMaintenance writes the maintenance window state. A server in maintenance keeps
// reporting its real health (tech_doc §30): dashboards combine oob_server_health with
// oob_server_maintenance to leave paused servers out, as Overview does.
func (c *Collector) addMaintenance(b *builder, id string, sl Label) {
	var st MaintenanceState
	if c.cfg.Maintenance != nil {
		st = c.cfg.Maintenance(id)
	}
	b.add("oob_server_maintenance", b2f(st.Active), sl)
	until := 0.0
	if st.Active && !st.Until.IsZero() {
		until = unixSeconds(st.Until)
	}
	b.add("oob_server_maintenance_until_timestamp_seconds", until, sl)
}

// addUnacked counts the warning and critical entries of the cached logs that nobody
// acknowledged (the ones Overview lists under Needs attention, over the whole cached log
// rather than its last 24 h). Left out when no log is cached.
func (c *Collector) addUnacked(b *builder, s fleet.ServerState, sl Label) {
	if !s.HasSEL && !s.HasLifecycle {
		return
	}
	var warn, crit int
	count := func(kind string, log bmc.EventLog, has bool) {
		if !has {
			return
		}
		for _, e := range log.Entries() {
			if e.Severity != bmc.SeverityWarning && e.Severity != bmc.SeverityCritical {
				continue
			}
			if c.cfg.Acked != nil && c.cfg.Acked(s.ID, kind, e.ID, e.Created) {
				continue
			}
			if e.Severity == bmc.SeverityCritical {
				crit++
			} else {
				warn++
			}
		}
	}
	count("sel", s.SEL, s.HasSEL)
	count("lifecycle", s.Lifecycle, s.HasLifecycle)
	b.add("oob_events_unacknowledged", float64(warn), sl, Label{"severity", "warning"})
	b.add("oob_events_unacknowledged", float64(crit), sl, Label{"severity", "critical"})
}
