package redfish

import (
	"context"

	"github.com/stmcginnis/gofish/schemas"

	"oob-manager/internal/bmc"
)

// maxVoltages bounds the voltage sensors kept from one Power resource.
const maxVoltages = 64

type powerData struct {
	psus  []bmc.PSU
	draw  bmc.PowerDraw
	volts []bmc.Voltage
}

// empty is true when the resource reported no PSUs and no non-zero draw. Voltages do
// not count: a BMC without PSU telemetry may still report them (the idrac9-r240 fixture).
func (p powerData) empty() bool {
	telemetry, _ := bmc.ClassifyPower(p.psus, p.draw, true)
	return telemetry == bmc.PowerTelemetryUnavailable
}

// readPower prefers legacy Power and falls back to PowerSubsystem when Power is absent
// or reports nothing. Voltages exist only in legacy Power, so they are kept across the
// fallback.
func (d *Driver) readPower(ctx context.Context, res Resources) (powerData, error) {
	data, err := d.legacyPower(ctx, res.Power)
	if (err == nil || isAbsent(err)) && data.empty() && res.PowerSubsystem != "" {
		sub, subErr := d.subsystemPower(ctx, res.PowerSubsystem)
		sub.volts = data.volts
		return sub, subErr
	}
	if isAbsent(err) {
		return powerData{}, nil
	}
	return data, err
}

func (d *Driver) legacyPower(ctx context.Context, uri string) (powerData, error) {
	if uri == "" {
		return powerData{}, nil
	}
	var pw schemas.Power
	if err := d.GetJSON(ctx, uri, &pw); err != nil {
		return powerData{}, err
	}
	out := powerData{volts: voltages(pw.Voltages)}
	if len(pw.PowerControl) > 0 {
		out.draw = powerDraw(pw.PowerControl[0])
	}
	for _, p := range pw.PowerSupplies {
		if len(out.psus) >= maxPSUs { // the subsystem path's cap (review HIGH-1)
			break
		}
		if p.Name == "" && p.MemberID == "" {
			continue
		}
		out.psus = append(out.psus, legacyPSU(p))
	}
	out.psus = reclassifyRatedInput(out.psus, out.draw)
	return out, nil
}

func powerDraw(pc schemas.PowerControl) bmc.PowerDraw {
	return bmc.PowerDraw{
		ConsumedWatts: bmc.ReadingFrom(pc.PowerConsumedWatts),
		AverageWatts:  bmc.ReadingFrom(pc.PowerMetrics.AverageConsumedWatts),
		MinWatts:      bmc.ReadingFrom(pc.PowerMetrics.MinConsumedWatts),
		MaxWatts:      bmc.ReadingFrom(pc.PowerMetrics.MaxConsumedWatts),
		CapacityWatts: bmc.ReadingFrom(pc.PowerCapacityWatts),
	}
}

func legacyPSU(p schemas.PowerSupply) bmc.PSU {
	return bmc.PSU{
		ID:             clean(p.MemberID),
		Name:           clean(p.Name),
		Model:          clean(p.Model),
		Firmware:       clean(p.FirmwareVersion),
		CapacityWatts:  firstReading(bmc.ReadingFrom(p.PowerCapacityWatts), ratedOutput(p.InputRanges)),
		InputWatts:     bmc.ReadingFrom(p.PowerInputWatts),
		OutputWatts:    firstReading(bmc.ReadingFrom(p.LastPowerOutputWatts), bmc.ReadingFrom(p.PowerOutputWatts)),
		LineInputVolts: bmc.ReadingFrom(p.LineInputVoltage),
		Health:         bmc.ParseHealth(string(p.Status.Health)),
	}
}

// ratedOutput is the largest OutputWattage of a PSU's input ranges (its rating when
// PowerCapacityWatts is absent, as on the iDRAC8 capture).
func ratedOutput(ranges []schemas.InputRange) bmc.Reading {
	best := bmc.NoReading()
	for _, r := range ranges {
		if v := bmc.ReadingFrom(r.OutputWattage); v.Valid && (!best.Valid || v.Value > best.Value) {
			best = v
		}
	}
	return best
}

func firstReading(rs ...bmc.Reading) bmc.Reading {
	for _, r := range rs {
		if r.Valid {
			return r
		}
	}
	return bmc.NoReading()
}

// implausibleInputFactor: per-PSU inputs adding up to more than this times the chassis
// draw cannot be measurements (the sum of PSU inputs is what the chassis draws).
const implausibleInputFactor = 1.5

// reclassifyRatedInput returns psus with PowerInputWatts moved to RatedInputWatts when
// the inputs cannot be live readings given the chassis draw. Without a chassis figure
// nothing can be judged and the values are kept.
func reclassifyRatedInput(psus []bmc.PSU, draw bmc.PowerDraw) []bmc.PSU {
	if !draw.ConsumedWatts.Valid || draw.ConsumedWatts.Value <= 0 {
		return psus
	}
	var sum float64
	for _, p := range psus {
		if p.InputWatts.Valid {
			sum += p.InputWatts.Value
		}
	}
	if sum <= implausibleInputFactor*draw.ConsumedWatts.Value {
		return psus
	}
	out := make([]bmc.PSU, 0, len(psus))
	for _, p := range psus {
		p.RatedInputWatts, p.InputWatts = p.InputWatts, bmc.NoReading()
		out = append(out, p)
	}
	return out
}

// voltages maps legacy Power.Voltages, skipping nameless placeholders.
func voltages(vs []schemas.Voltage) []bmc.Voltage {
	var out []bmc.Voltage
	for _, v := range vs {
		if len(out) >= maxVoltages {
			break
		}
		if v.Name == "" && v.ReadingVolts == nil {
			continue
		}
		out = append(out, bmc.Voltage{
			ID:      clean(v.MemberID),
			Name:    clean(v.Name),
			Context: clean(string(v.PhysicalContext)),
			Volts:   bmc.ReadingFrom(v.ReadingVolts),
			Health:  bmc.ParseHealth(string(v.Status.Health)),
		})
	}
	return out
}
