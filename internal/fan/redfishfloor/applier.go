// Package redfishfloor is the fan applier for mode redfish-floor (Dell iDRAC9): it raises
// the BMC's own minimum fan speed (ThermalSettings.1.MinimumFanSpeed) and restores the
// recorded original value when the lease ends. The BMC stays in automatic control, so
// there is no manual mode to strand; if the app is gone for good the fans run faster than
// needed, never slower (docs/system_design.md §3.3).
package redfishfloor

import (
	"context"
	"fmt"

	"oob-manager/internal/bmc/dellredfish"
	"oob-manager/internal/fan"
	"oob-manager/internal/store"
)

// Floor reads and writes the BMC's minimum fan speed (*dellredfish.FanFloorClient).
type Floor interface {
	Read(ctx context.Context) (dellredfish.FanFloor, error)
	Set(ctx context.Context, v int) error
}

// Applier is safe for concurrent use as long as Floor is.
type Applier struct {
	floor Floor
}

var _ fan.Applier = (*Applier)(nil)

// New returns an applier over floor.
func New(floor Floor) *Applier { return &Applier{floor: floor} }

// Prepare reads the current value (the one to restore) and the BMC's range, and clamps
// the floor into [max(safeMin, BMC minimum), BMC maximum]. It never plans a value below
// a floor that is already set (boost only).
func (a *Applier) Prepare(ctx context.Context, pct, safeMin int) (fan.Plan, error) {
	f, err := a.floor.Read(ctx)
	if err != nil {
		return fan.Plan{}, err
	}
	target := f.Clamp(pct, safeMin)
	if !f.Automatic() && f.Current > target {
		target = f.Current
	}
	if target < safeMin {
		return fan.Plan{}, fmt.Errorf("redfishfloor: BMC maximum %d %% is below the safe minimum %d %%", f.High, safeMin)
	}
	return fan.Plan{Pct: target, Original: f.Current, HasOriginal: true}, nil
}

// Apply writes the floor; it is in effect at once.
func (a *Applier) Apply(ctx context.Context, l store.FanLease) (bool, error) {
	if err := a.floor.Set(ctx, l.Pct); err != nil {
		return false, err
	}
	return true, nil
}

// Release restores the recorded original value; an absent or implausible original
// restores automatic (255), the BMC default.
func (a *Applier) Release(ctx context.Context, l store.FanLease) error {
	v := dellredfish.FanFloorAuto
	if l.HasOriginal && dellredfish.ValidFloorValue(l.OriginalValue) {
		v = l.OriginalValue
	}
	return a.floor.Set(ctx, v)
}

// Observe reports from the lease row only (no BMC traffic): a stored lease was applied
// by a successful PATCH; without one the BMC's automatic control is in charge.
func (a *Applier) Observe(l store.FanLease, has bool) fan.Observation {
	if !has {
		return fan.Observation{Owner: fan.OwnerBMC}
	}
	applied := l.State == store.LeaseApplied
	return fan.Observation{Applied: applied, Owner: fan.OwnerLease, AppliedPct: l.Pct, HasPct: applied}
}
