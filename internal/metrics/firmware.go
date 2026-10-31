package metrics

import (
	"time"

	"oob-manager/internal/fleet"
)

// FirmwareCounts are a server's firmware view numbers (fwinventory.Service.Counts).
// Versions themselves are never exposed here: oob_server_info carries the BIOS and BMC
// versions only with include_inventory.
type FirmwareCounts struct {
	Components int
	// Flagged counts components per flag (below_minimum, update_urgent, not_applied,
	// update_available, cannot_compare, stale_release).
	Flagged map[string]int
	// Updates counts newer vendor releases, not skipped, by criticality.
	Updates  map[string]int
	LastScan time.Time // zero: never scanned
	Changes  int64     // version changes since the process started
}

// firmwareFlags are the oob_firmware_flagged flag labels, worst first.
func firmwareFlags() []string {
	return []string{"below_minimum", "update_urgent", "not_applied", "update_available", "cannot_compare", "stale_release"}
}

// updateCriticalities are the oob_firmware_updates_available labels.
func updateCriticalities() []string { return []string{"urgent", "recommended", "optional"} }

// CatalogState is the firmware update check for /metrics (fwcatalog.Checker).
type CatalogState struct {
	Source     string
	Published  time.Time        // zero: none imported or no date
	LastCheck  time.Time        // zero: never checked
	LastResult string           // catalog_checks.result of the last check
	Failures   map[string]int64 // failed checks since start, by class
}

// catalogFailureClasses are the oob_firmware_catalog_check_failures_total labels.
func catalogFailureClasses() []string {
	return []string{"download", "size", "signature", "untrusted_key", "parse"}
}

// collectCatalog writes the update check's families (absent without the hook).
func (c *Collector) collectCatalog(b *builder) {
	if c.cfg.Catalog == nil {
		return
	}
	st := c.cfg.Catalog()
	src := Label{"source", st.Source}
	pub := 0.0
	if !st.Published.IsZero() {
		pub = unixSeconds(st.Published)
	}
	b.add("oob_firmware_catalog_published_timestamp_seconds", pub, src)
	if !st.LastCheck.IsZero() {
		b.add("oob_firmware_catalog_last_check_timestamp_seconds", unixSeconds(st.LastCheck), src, Label{"result", st.LastResult})
	}
	for _, cl := range catalogFailureClasses() {
		b.add("oob_firmware_catalog_check_failures_total", float64(st.Failures[cl]), src, Label{"class", cl})
	}
}

// addFirmware writes the firmware view families from the hook (absent for a server the
// view does not know).
func (c *Collector) addFirmware(b *builder, s fleet.ServerState, sl Label) {
	if c.cfg.Firmware == nil {
		return
	}
	n, ok := c.cfg.Firmware(s.ID)
	if !ok {
		return
	}
	b.add("oob_firmware_components", float64(n.Components), sl)
	for _, f := range firmwareFlags() {
		b.add("oob_firmware_flagged", float64(n.Flagged[f]), sl, Label{"flag", f})
	}
	last := 0.0
	if !n.LastScan.IsZero() {
		last = unixSeconds(n.LastScan)
	}
	b.add("oob_firmware_last_scan_timestamp_seconds", last, sl)
	b.add("oob_firmware_changes_total", float64(n.Changes), sl)
	for _, cr := range updateCriticalities() {
		b.add("oob_firmware_updates_available", float64(n.Updates[cr]), sl, Label{"criticality", cr})
	}
}
