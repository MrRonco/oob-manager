package metrics

import (
	"time"

	"oob-manager/internal/fleet"
)

// BMCResetState is a server's BMC restart record (bmcreset.Service, tech_doc §37).
type BMCResetState struct {
	// LastVerified is when the app's last verified restart was requested (zero: none).
	LastVerified time.Time
	// Counts are the resets since start by result (sent, refused, verified, timeout).
	Counts map[string]int64
}

// bmcResetResults are the oob_bmc_resets_total result labels.
func bmcResetResults() []string { return []string{"sent", "refused", "verified", "timeout"} }

// addBMCReset writes the restart window gauge (from the fleet), the last restart time
// (the BMC's own LastResetTime when it reports one, else the app's last verified
// restart, else 0) and, with the hook, the reset counters.
func (c *Collector) addBMCReset(b *builder, s fleet.ServerState, sl Label) {
	b.add("oob_server_bmc_restarting", b2f(s.Restarting), sl)
	var st BMCResetState
	if c.cfg.BMCReset != nil {
		st = c.cfg.BMCReset(s.ID)
	}
	last := 0.0
	switch {
	case s.HasCapabilities && !s.Capabilities.Flags().BMCLastReset.IsZero():
		last = unixSeconds(s.Capabilities.Flags().BMCLastReset)
	case !st.LastVerified.IsZero():
		last = unixSeconds(st.LastVerified)
	}
	b.add("oob_server_bmc_last_reset_timestamp_seconds", last, sl)
	if c.cfg.BMCReset == nil {
		return
	}
	for _, r := range bmcResetResults() {
		b.add("oob_bmc_resets_total", float64(st.Counts[r]), sl, Label{"result", r})
	}
}
