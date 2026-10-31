package metrics

import "oob-manager/internal/fleet"

func b2f(v bool) float64 {
	if v {
		return 1
	}
	return 0
}

// collectApp adds the process, audit, sign-in, console and notification families.
func (c *Collector) collectApp(b *builder, servers []fleet.ServerState) {
	bi := c.cfg.Build
	b.add("oob_build_info", 1, Label{"version", bi.Version}, Label{"commit", bi.Commit}, Label{"goversion", bi.GoVersion})
	if !c.cfg.StartTime.IsZero() {
		b.add("oob_process_start_time_seconds", unixSeconds(c.cfg.StartTime))
	}
	rt := c.cfg.Runtime()
	b.add("oob_process_goroutines", float64(rt.Goroutines))
	b.add("oob_process_heap_alloc_bytes", float64(rt.HeapAlloc))
	b.add("oob_process_memory_sys_bytes", float64(rt.Sys))
	b.add("oob_process_gc_cycles_total", float64(rt.NumGC))
	b.add("oob_servers", float64(len(servers)))
	c.collectAudit(b)
	if c.cfg.Logins != nil {
		for _, sc := range c.cfg.Logins.counts() {
			b.add("oob_login_failures_total", float64(sc.n), Label{"stage", sc.stage})
		}
	}
	c.collectConsoles(b, servers)
	c.collectNotify(b)
	c.collectCatalog(b)
	c.collectHistory(b)
}

func (c *Collector) collectAudit(b *builder) {
	if c.cfg.AuditChainOK != nil {
		b.add("oob_audit_chain_ok", b2f(c.cfg.AuditChainOK()))
	}
	if c.cfg.Shipper == nil {
		return
	}
	st := c.cfg.Shipper.Stats()
	// Always written, so a disabled shipper is visible (alert on == 0, or absent()).
	b.add("oob_audit_shipper_enabled", b2f(st.Active))
	if !st.Active {
		return // GELF shipping is disabled (Settings → Integrations)
	}
	b.add("oob_audit_shipper_connected", b2f(st.Connected))
	b.add("oob_audit_shipper_queued", float64(st.Queued))
	b.add("oob_audit_shipper_dropped_total", float64(st.Dropped))
	b.add("oob_audit_shipper_tls", b2f(st.TLS))
	b.add("oob_audit_shipper_pin_mismatch", b2f(st.PinMismatch))
	b.add("oob_audit_shipper_reconnects_total", float64(st.Reconnects))
	last := 0.0
	if !st.LastSuccess.IsZero() {
		last = float64(st.LastSuccess.Unix())
	}
	b.add("oob_audit_shipper_last_success_timestamp_seconds", last)
}

func (c *Collector) collectConsoles(b *builder, servers []fleet.ServerState) {
	if c.cfg.ConsoleActive == nil {
		return
	}
	var vnc, serial int
	for _, s := range servers {
		v, sr := c.cfg.ConsoleActive(s.ID)
		vnc += int(b2f(v))
		serial += int(b2f(sr))
	}
	b.add("oob_console_sessions_active", float64(vnc), Label{"type", "vnc"})
	b.add("oob_console_sessions_active", float64(serial), Label{"type", "serial"})
}

func (c *Collector) collectNotify(b *builder) {
	if c.cfg.NotifyTargets == nil {
		return
	}
	ts := c.cfg.NotifyTargets()
	if len(ts) > MaxNotifyTargets {
		b.drop((len(ts) - MaxNotifyTargets) * 4)
		ts = ts[:MaxNotifyTargets]
	}
	for _, t := range ts {
		if !t.Enabled {
			continue
		}
		l := Label{"target", t.ID}
		b.add("oob_notify_target_failing", b2f(t.Failing), l)
		b.add("oob_notify_target_consecutive_failures", float64(t.ConsecutiveFailures), l)
		b.add("oob_notify_sent_total", float64(t.Sent), l)
		b.add("oob_notify_dropped_total", float64(t.Dropped), l)
	}
}
