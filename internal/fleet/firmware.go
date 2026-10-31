package fleet

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"oob-manager/internal/bmc"
)

// DefaultFirmwareEvery is the firmware tier's period (docs/tech_doc.md §38): firmware
// changes rarely, and member documents cost one GET each on a slow iDRAC8.
const DefaultFirmwareEvery = 24 * time.Hour

// FirmwareSink records firmware scans (the firmware view's service). Need is asked once
// per scan; Record runs on the poller goroutine and must not block for long.
type FirmwareSink interface {
	// Need returns, for server id, whether an ID-derived item's member document should
	// be read in this scan.
	Need(id string, now time.Time) func(bmc.FirmwareItem) bool
	// Record stores a scan taken at at.
	Record(ctx context.Context, id string, scan bmc.FirmwareScan, at time.Time) error
}

// Tier names a slow tier Refresh can run now.
type Tier string

// Tiers.
const (
	TierFirmware Tier = "firmware"
	TierPosture  Tier = "posture"
)

// ErrNoTier means the server has no such tier (a driver without a firmware scanner, no
// firmware sink, an unknown tier).
var ErrNoTier = errors.New("fleet: this server has no such tier")

// Refresh marks one of server id's slow tiers due now and wakes its poller: the next
// cycle polls the snapshot and then runs the tier (after the BMC is back when a restart
// window is open). Requests made before the tier runs are folded into one. The caller
// rate-limits (it is a BMC read).
func (f *Fleet) Refresh(id string, tier Tier) error {
	if tier == TierPosture {
		return f.RequestPosture(id)
	}
	p, ok := f.roster.Load().byID[id]
	switch {
	case !ok:
		return ErrUnknownServer
	case tier != TierFirmware || !p.firmwareOn():
		return ErrNoTier
	case p.state.Load().Paused:
		return ErrPaused
	}
	p.firmwareReq.Store(true)
	select {
	case p.wake <- struct{}{}:
	default: // a wake-up is already pending
	}
	return nil
}

// firmwareOn reports whether this server has a firmware tier.
func (p *poller) firmwareOn() bool {
	_, ok := p.target.Driver.(bmc.FirmwareScanner)
	return ok && p.cfg.Firmware != nil
}

// runFirmwareIfDue runs the firmware tier when it is due or requested, and schedules it.
func (p *poller) runFirmwareIfDue(ctx context.Context, s ServerState, cad cadence, now time.Time) (ServerState, cadence) {
	if !p.firmwareOn() || cad.holdFirmware {
		return s, cad
	}
	if requested := p.firmwareReq.Swap(false); requested || !now.Before(cad.firmware) {
		var ok bool
		var sig string
		s, sig, ok = p.refreshFirmware(ctx, s, now)
		cad.firmware = p.nextDue(now, p.cfg.FirmwareEvery, ok)
		if ok {
			cad.fwSig = sig
		}
	}
	s.FirmwareNext = cad.firmware
	return s, cad
}

// refreshFirmware is the firmware tier (docs/tech_doc.md §38): one read-only scan under
// its own budget, recorded by the sink. A failed scan keeps the last one (stored by the
// sink), records its class and is retried after EventsEvery; it never trips the breaker.
func (p *poller) refreshFirmware(ctx context.Context, s ServerState, now time.Time) (ServerState, string, bool) {
	cctx, cancel := p.budget(ctx)
	defer cancel()
	running := s
	running.FirmwareRunning = true
	p.publish(running)
	scanner, _ := p.target.Driver.(bmc.FirmwareScanner) // firmwareOn checked it
	scan, err := scanner.ScanFirmware(cctx, p.cfg.Firmware.Need(p.target.ID, now))
	if err == nil {
		err = p.cfg.Firmware.Record(ctx, p.target.ID, scan, now)
	}
	s.FirmwareError = bmc.Classify(budgetClass(ctx, cctx, err))
	if err != nil {
		if ctx.Err() == nil {
			p.cfg.Logger.Warn("fleet: firmware scan failed", "server", p.target.ID, "class", string(s.FirmwareError))
		}
		return s, "", false
	}
	s.FirmwareAsOf = now
	return s, firmwareSignature(scan.Items()), true
}

// firmwareSignature identifies a firmware list by its members and versions, so the
// cheap inventory tier can tell that something changed since the last scan.
func firmwareSignature(items []bmc.FirmwareItem) string {
	parts := make([]string, 0, len(items))
	for _, it := range items {
		parts = append(parts, strings.Join([]string{it.ID, it.State, it.ComponentID, it.FQDD, it.Version}, "\x1f"))
	}
	slices.SortFunc(parts, cmp.Compare)
	return strings.Join(parts, "\x1e")
}

// inventoryChanged marks the firmware tier due when the inventory tier's list differs
// from the last scan's (a version changed, a component came or went).
func (p *poller) inventoryChanged(s ServerState, cad cadence) cadence {
	if !p.firmwareOn() || cad.fwSig == "" || !s.HasInventory {
		return cad
	}
	fw := s.Inventory.Firmware()
	if len(fw) > 0 && firmwareSignature(fw) != cad.fwSig {
		cad.firmware = time.Time{}
	}
	return cad
}
