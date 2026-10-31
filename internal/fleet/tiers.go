package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/store"
)

// refreshSlowTiers runs the logs tier (SEL + Lifecycle, every EventsEvery), the
// inventory tier (Probe + Inventory, every InventoryEvery and at startup), the firmware
// tier (firmware.go) and the posture tier when due, each with its own budget. Their failures are recorded per section and never trip the
// breaker; a failed tier is retried after min(its period, EventsEvery).
func (p *poller) refreshSlowTiers(ctx context.Context, s ServerState, cad cadence, now time.Time) (ServerState, cadence) {
	if !now.Before(cad.events) {
		var ok bool
		s, ok = p.refreshLogs(ctx, s, now)
		cad.events = p.nextDue(now, p.cfg.EventsEvery, ok)
	}
	if !now.Before(cad.inventory) {
		var ok bool
		s, ok = p.refreshInventory(ctx, s, now)
		cad.inventory = p.nextDue(now, p.cfg.InventoryEvery, ok)
		if ok {
			cad = p.inventoryChanged(s, cad)
		}
	}
	s, cad = p.runFirmwareIfDue(ctx, s, cad, now)
	if p.target.Posture == nil {
		return s, cad
	}
	if requested := p.postureReq.Swap(false); requested || !now.Before(cad.posture) {
		var ok bool
		s, ok = p.refreshPosture(ctx, s, now)
		cad.posture, cad.postureFails = p.postureDue(now, ok, cad.postureFails)
	}
	return s, cad
}

// postureDue schedules the next security check run: the posture period after a good
// run; after a failed one the events period, doubling with every further consecutive
// failure up to the posture period, so a BMC that cannot be probed completely is not
// re-read every few minutes forever.
func (p *poller) postureDue(now time.Time, ok bool, fails int) (time.Time, int) {
	if ok {
		return now.Add(p.cfg.PostureEvery), 0
	}
	fails++
	wait := min(p.cfg.EventsEvery, p.cfg.PostureEvery)
	for i := 1; i < fails && wait < p.cfg.PostureEvery; i++ {
		wait = min(2*wait, p.cfg.PostureEvery)
	}
	return now.Add(wait), fails
}

// refreshPosture is the security-check tier (docs/tech_doc.md §31). Readers see
// PostureRunning while it reads: a run can take a while on a slow BMC.
func (p *poller) refreshPosture(ctx context.Context, s ServerState, now time.Time) (ServerState, bool) {
	cctx, cancel := p.budget(ctx)
	defer cancel()
	running := s
	running.PostureRunning = true
	p.publish(running)
	post, err := p.target.Posture(cctx, p.target.Driver)
	s.PostureError = bmc.Classify(budgetClass(ctx, cctx, err))
	if err == nil {
		// A probe that could not reach the BMC (a timeout, no route) makes the run as
		// unreliable as an error: the previous posture is kept and the run retried soon.
		s.PostureError = post.TransportFailure()
	}
	if s.PostureError != bmc.ClassNone {
		if ctx.Err() == nil {
			p.cfg.Logger.Warn("fleet: security checks failed", "server", p.target.ID, "class", string(s.PostureError))
		}
		return s, false
	}
	s.Posture, s.HasPosture = post, true
	s.PostureAsOf = post.Started
	if s.PostureAsOf.IsZero() {
		s.PostureAsOf = now
	}
	return s, true
}

func (p *poller) nextDue(now time.Time, every time.Duration, ok bool) time.Time {
	if ok {
		return now.Add(every)
	}
	return now.Add(min(every, p.cfg.EventsEvery))
}

func (p *poller) refreshLogs(ctx context.Context, s ServerState, now time.Time) (ServerState, bool) {
	cctx, cancel := p.budget(ctx)
	defer cancel()
	sel, err := p.target.Driver.EventLog(cctx, time.Time{})
	s.SELError = bmc.Classify(budgetClass(ctx, cctx, err))
	ok := err == nil
	if ok {
		s.SEL, s.HasSEL, s.SELAsOf = sel, true, now
	}
	lc, isLC := p.target.Driver.(LifecycleLogger)
	if !isLC {
		return s, ok
	}
	log, err := lc.LifecycleLog(cctx, time.Time{})
	switch {
	case errors.Is(err, bmc.ErrUnsupported):
		s.LifecycleError = bmc.ClassNone
	case err != nil:
		s.LifecycleError, ok = bmc.Classify(budgetClass(ctx, cctx, err)), false
	default:
		s.Lifecycle, s.HasLifecycle, s.LifecycleError, s.LifecycleAsOf = log, true, bmc.ClassNone, now
	}
	return s, ok
}

func (p *poller) refreshInventory(ctx context.Context, s ServerState, now time.Time) (ServerState, bool) {
	cctx, cancel := p.budget(ctx)
	defer cancel()
	if caps, err := p.target.Driver.Probe(cctx); err == nil {
		s.Capabilities, s.HasCapabilities = caps, true
		p.storeCapabilities(cctx, caps)
	}
	inv, err := p.target.Driver.Inventory(cctx)
	s.InventoryError = bmc.Classify(budgetClass(ctx, cctx, err))
	if err != nil {
		return s, false
	}
	s.Inventory, s.HasInventory, s.InventoryAsOf = inv, true, now
	return s, true
}

type capabilityDoc struct {
	Flags             bmc.CapabilityFlags `json:"flags"`
	ResetTypes        []string            `json:"reset_types"`
	ManagerResetTypes []string            `json:"manager_reset_types,omitempty"`
}

func (p *poller) storeCapabilities(ctx context.Context, caps bmc.Capabilities) {
	if p.cfg.Capabilities == nil {
		return
	}
	doc, err := json.Marshal(capabilityDoc{Flags: caps.Flags(), ResetTypes: caps.ResetTypes(),
		ManagerResetTypes: caps.ManagerResetTypes()})
	if err == nil {
		err = p.cfg.Capabilities.Put(ctx, store.Capability{
			ServerID: p.target.ID, ProbedAt: caps.Flags().ProbedAt, JSON: string(doc)})
	}
	if err != nil {
		p.cfg.Logger.Warn("fleet: store capabilities failed", "server", p.target.ID, "error", err)
	}
}
