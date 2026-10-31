package redfish

import (
	"context"
	"fmt"

	"github.com/stmcginnis/gofish/schemas"

	"oob-manager/internal/bmc"
)

type thermalData struct {
	temps []bmc.Temperature
	fans  []bmc.Fan
}

func (t thermalData) empty() bool { return len(t.temps) == 0 && len(t.fans) == 0 }

// Snapshot reads health, power state, temperatures, fans and PSUs. Only a failure to
// read the ComputerSystem (or an expired parent context) is an error; other sections
// that fail are listed in Snapshot.Problems, and sections the BMC lacks are empty.
func (d *Driver) Snapshot(ctx context.Context) (bmc.Snapshot, error) {
	disc, err := d.discovered(ctx)
	if err != nil {
		return bmc.Snapshot{}, err
	}
	res := disc.res
	var sys schemas.ComputerSystem
	if err := d.GetJSON(ctx, res.System, &sys); err != nil {
		return bmc.Snapshot{}, err
	}
	chassisHealth, chErr := d.chassisHealth(ctx, res.Chassis)
	thermal, thErr := d.readThermal(ctx, res)
	power, pwErr := d.readPower(ctx, res)
	if ctx.Err() != nil {
		return bmc.Snapshot{}, fmt.Errorf("snapshot: %w", bmc.ErrTimeout)
	}
	telemetry, draw := bmc.ClassifyPower(power.psus, power.draw, pwErr == nil)
	return bmc.NewSnapshot(bmc.SnapshotParams{
		TakenAt:        d.opts.now(),
		PowerState:     bmc.ParsePowerState(string(sys.PowerState)),
		Health:         bmc.WorstHealth(statusHealth(sys.Status), chassisHealth),
		Temperatures:   thermal.temps,
		Fans:           thermal.fans,
		PSUs:           power.psus,
		Power:          draw,
		Voltages:       power.volts,
		PowerTelemetry: telemetry,
		Problems:       problems(section{"chassis", chErr}, section{"thermal", thErr}, section{"power", pwErr}),
	}), nil
}

type section struct {
	name string
	err  error
}

// problems renders section errors as UI-safe "name: class" strings (no BMC text).
func problems(sections ...section) []string {
	var out []string
	for _, s := range sections {
		if s.err != nil {
			out = append(out, fmt.Sprintf("%s: %s", s.name, bmc.Classify(s.err)))
		}
	}
	return out
}

func statusHealth(s schemas.Status) bmc.Health {
	if h := bmc.ParseHealth(string(s.HealthRollup)); h != bmc.HealthUnknown {
		return h
	}
	return bmc.ParseHealth(string(s.Health))
}

func (d *Driver) chassisHealth(ctx context.Context, uri string) (bmc.Health, error) {
	ch, found, err := optional[schemas.Chassis](ctx, d, uri)
	if err != nil || !found {
		return bmc.HealthUnknown, err
	}
	return statusHealth(ch.Status), nil
}

// readThermal prefers the legacy Thermal resource (one GET, thresholds included) and
// falls back to ThermalSubsystem when Thermal is absent or empty.
func (d *Driver) readThermal(ctx context.Context, res Resources) (thermalData, error) {
	data, err := d.legacyThermal(ctx, res.Thermal)
	if (err == nil || isAbsent(err)) && data.empty() && res.ThermalSubsystem != "" {
		return d.subsystemThermal(ctx, res.ThermalSubsystem)
	}
	if isAbsent(err) {
		return thermalData{}, nil
	}
	return data, err
}

func (d *Driver) legacyThermal(ctx context.Context, uri string) (thermalData, error) {
	if uri == "" {
		return thermalData{}, nil
	}
	var th schemas.Thermal
	if err := d.GetJSON(ctx, uri, &th); err != nil {
		return thermalData{}, err
	}
	out := thermalData{}
	for _, t := range th.Temperatures {
		if len(out.temps) >= maxTemps { // the subsystem path's caps (review HIGH-1)
			break
		}
		if t.Name == "" && t.ReadingCelsius == nil {
			continue // iDRAC8 emits an all-null placeholder entry
		}
		out.temps = append(out.temps, bmc.Temperature{
			ID:        clean(t.MemberID),
			Name:      clean(t.Name),
			Context:   clean(string(t.PhysicalContext)),
			Celsius:   bmc.ReadingFrom(t.ReadingCelsius),
			WarnAbove: bmc.ReadingFrom(t.UpperThresholdNonCritical),
			CritAbove: bmc.ReadingFrom(t.UpperThresholdCritical),
			Health:    bmc.ParseHealth(string(t.Status.Health)),
		})
	}
	for _, f := range th.Fans {
		if len(out.fans) >= maxFans {
			break
		}
		out.fans = append(out.fans, legacyFan(f))
	}
	return out, nil
}

func legacyFan(f schemas.ThermalFan) bmc.Fan {
	name := f.Name
	if name == "" {
		name = f.FanName //nolint:staticcheck // SA1019: Redfish 1.0-era BMCs (iDRAC8) only populate FanName
	}
	units := bmc.FanRPM
	if f.ReadingUnits == schemas.PercentReadingUnits {
		units = bmc.FanPercent
	}
	return bmc.Fan{
		ID:     clean(f.MemberID),
		Name:   clean(name),
		Speed:  bmc.ReadingFrom(f.Reading),
		Units:  units,
		Health: bmc.ParseHealth(string(f.Status.Health)),
	}
}
