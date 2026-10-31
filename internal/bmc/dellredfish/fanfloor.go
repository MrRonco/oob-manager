package dellredfish

import (
	"context"
	"encoding/json"
	"fmt"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfish"
)

// Fan floor (iDRAC9, fan mode redfish-floor; docs/system_design.md §3.3). The BMC stays
// in automatic control; ThermalSettings.1.MinimumFanSpeed only raises its lower bound.
// Attribute names and ranges come from the P3.1 spike on iDRAC9 firmware 7.00.
const (
	// FanFloorAttrsURI is the only URI the fan floor client may PATCH.
	FanFloorAttrsURI = "/redfish/v1/Managers/System.Embedded.1/Attributes"
	// AttrMinFanSpeed is the only attribute it may PATCH.
	AttrMinFanSpeed = "ThermalSettings.1.MinimumFanSpeed"
	attrMFSLow      = "ThermalSettings.1.MFSMinimumLimit"
	attrMFSHigh     = "ThermalSettings.1.MFSMaximumLimit"
	// FanFloorAuto is MinimumFanSpeed's "not set" value: the BMC's own curve decides.
	FanFloorAuto = 255
)

// FanFloor is the BMC's current minimum fan speed and the range it accepts (percent).
type FanFloor struct {
	Current   int // FanFloorAuto or 1..100
	Low, High int // MFSMinimumLimit, MFSMaximumLimit
}

// Automatic reports whether no minimum is set.
func (f FanFloor) Automatic() bool { return f.Current == FanFloorAuto }

// Clamp returns want raised to max(safeMin, Low) and capped at High. The result can be
// below safeMin only when the BMC's maximum is; callers must check.
func (f FanFloor) Clamp(want, safeMin int) int {
	return min(max(want, safeMin, f.Low), f.High)
}

// ValidFloorValue reports whether v may be written to MinimumFanSpeed: FanFloorAuto or a
// percentage 1..100. The BMC's own range is checked separately (Clamp).
func ValidFloorValue(v int) bool { return v == FanFloorAuto || (v >= 1 && v <= 100) }

// FanFloorClient reads and writes the fan floor with the operator login. Each call logs
// in, does its work and logs out again, so no operator session stays open.
type FanFloorClient struct {
	cfg redfish.Config
}

// NewFanFloorClient returns a client for cfg (operator credentials). It does not contact
// the BMC; a bad cfg fails on the first call.
func NewFanFloorClient(cfg redfish.Config) *FanFloorClient { return &FanFloorClient{cfg: cfg} }

type attrsDoc struct {
	Attributes map[string]json.RawMessage `json:"Attributes"`
}

// Read returns the current floor and the BMC's allowed range. A missing attribute is
// ErrUnsupported; an out-of-range or non-integer value is ErrDecode.
func (c *FanFloorClient) Read(ctx context.Context) (FanFloor, error) {
	var doc attrsDoc
	err := c.with(ctx, func(d *redfish.Driver) error { return d.GetJSON(ctx, FanFloorAttrsURI, &doc) })
	if err != nil {
		return FanFloor{}, err
	}
	return parseFanFloor(doc)
}

// Set writes MinimumFanSpeed. v must pass ValidFloorValue.
func (c *FanFloorClient) Set(ctx context.Context, v int) error {
	if !ValidFloorValue(v) {
		return fmt.Errorf("%w: minimum fan speed %d", bmc.ErrInvalidConfig, v)
	}
	return c.with(ctx, func(d *redfish.Driver) error {
		return d.PatchAttributes(ctx, FanFloorAttrsURI, map[string]int{AttrMinFanSpeed: v})
	})
}

// with runs fn on a fresh driver allowed exactly one PATCH (the floor attribute) and
// deletes its session afterwards.
func (c *FanFloorClient) with(ctx context.Context, fn func(*redfish.Driver) error) error {
	d, err := redfish.New(c.cfg, redfish.WithAttributePatch(FanFloorAttrsURI, AttrMinFanSpeed))
	if err != nil {
		return err
	}
	defer func() {
		lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), logoutTimeout)
		defer cancel()
		_ = d.Close(lctx)
	}()
	return fn(d)
}

func parseFanFloor(doc attrsDoc) (FanFloor, error) {
	var f FanFloor
	for _, a := range []struct {
		key string
		dst *int
	}{{AttrMinFanSpeed, &f.Current}, {attrMFSLow, &f.Low}, {attrMFSHigh, &f.High}} {
		raw, ok := doc.Attributes[a.key]
		if !ok {
			return FanFloor{}, fmt.Errorf("fan floor: %w: %s absent", bmc.ErrUnsupported, a.key)
		}
		if err := json.Unmarshal(raw, a.dst); err != nil {
			return FanFloor{}, fmt.Errorf("fan floor: %w: %s", bmc.ErrDecode, a.key)
		}
	}
	inRange := func(v int) bool { return v >= 1 && v <= 100 }
	if !ValidFloorValue(f.Current) || !inRange(f.Low) || !inRange(f.High) || f.Low > f.High {
		return FanFloor{}, fmt.Errorf("fan floor: %w: values out of range", bmc.ErrDecode)
	}
	return f, nil
}
