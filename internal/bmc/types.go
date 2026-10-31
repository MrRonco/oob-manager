package bmc

import (
	"slices"
	"strings"
	"time"
)

// Health is a normalised Redfish-style health value.
type Health string

// Health values, ordered from best to worst by healthRank.
const (
	HealthUnknown  Health = "Unknown"
	HealthOK       Health = "OK"
	HealthWarning  Health = "Warning"
	HealthCritical Health = "Critical"
)

// ParseHealth maps a BMC-supplied health string to a Health (case-insensitive).
func ParseHealth(s string) Health {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "ok":
		return HealthOK
	case "warning":
		return HealthWarning
	case "critical":
		return HealthCritical
	default:
		return HealthUnknown
	}
}

func healthRank(h Health) int {
	switch h {
	case HealthOK:
		return 1
	case HealthWarning:
		return 2
	case HealthCritical:
		return 3
	default:
		return 0
	}
}

// WorstHealth returns the most severe known health; Unknown only when nothing is known.
func WorstHealth(hs ...Health) Health {
	worst := HealthUnknown
	for _, h := range hs {
		if healthRank(h) > healthRank(worst) {
			worst = h
		}
	}
	return worst
}

// PowerState is the host power state reported by the BMC.
type PowerState string

// Power states.
const (
	PowerUnknown     PowerState = "Unknown"
	PowerOn          PowerState = "On"
	PowerOff         PowerState = "Off"
	PowerPoweringOn  PowerState = "PoweringOn"
	PowerPoweringOff PowerState = "PoweringOff"
)

// ParsePowerState maps a Redfish PowerState string to a PowerState.
func ParsePowerState(s string) PowerState {
	switch PowerState(strings.TrimSpace(s)) {
	case PowerOn:
		return PowerOn
	case PowerOff:
		return PowerOff
	case PowerPoweringOn:
		return PowerPoweringOn
	case PowerPoweringOff:
		return PowerPoweringOff
	default:
		return PowerUnknown
	}
}

// Reading is an optional numeric sensor value. BMCs often report null.
type Reading struct {
	Value float64
	Valid bool
}

// NoReading is an absent value.
func NoReading() Reading { return Reading{} }

// ReadingOf wraps a present value.
func ReadingOf(v float64) Reading { return Reading{Value: v, Valid: true} }

// ReadingFrom converts an optional decoded number into a Reading.
func ReadingFrom[T ~int | ~int64 | ~uint | ~float32 | ~float64](p *T) Reading {
	if p == nil {
		return NoReading()
	}
	return ReadingOf(float64(*p))
}

// FanUnits says how a fan speed is expressed.
type FanUnits string

// Fan speed units.
const (
	FanRPM     FanUnits = "RPM"
	FanPercent FanUnits = "Percent"
)

// Temperature is one temperature sensor.
type Temperature struct {
	ID        string
	Name      string
	Context   string // PhysicalContext, e.g. "CPU", "Intake"
	Celsius   Reading
	WarnAbove Reading // UpperThresholdNonCritical
	CritAbove Reading // UpperThresholdCritical
	Health    Health
}

// Fan is one fan sensor.
type Fan struct {
	ID     string
	Name   string
	Speed  Reading
	Units  FanUnits
	Health Health
}

// PSU is one power supply.
type PSU struct {
	ID            string
	Name          string
	Model         string
	Firmware      string
	CapacityWatts Reading // rated output
	InputWatts    Reading // measured input, now
	OutputWatts   Reading // measured output, now
	// RatedInputWatts is the maximum input the PSU is rated for. Some BMCs (the iDRAC8
	// capture) report it in PowerInputWatts; the driver moves it here when the figure
	// cannot be a measurement (UI review F-11).
	RatedInputWatts Reading
	LineInputVolts  Reading
	Health          Health
}

// PowerDraw is the chassis-level power consumption.
type PowerDraw struct {
	ConsumedWatts Reading
	AverageWatts  Reading
	MinWatts      Reading
	MaxWatts      Reading
	CapacityWatts Reading
}

// SnapshotParams are the inputs to NewSnapshot. Slices are copied.
type SnapshotParams struct {
	TakenAt    time.Time
	PowerState PowerState
	// PowerAsOf is when PowerState was observed (zero: TakenAt). A verified power
	// action is newer than the poll it overlays (WithPowerState).
	PowerAsOf    time.Time
	Health       Health
	Temperatures []Temperature
	Fans         []Fan
	PSUs         []PSU
	Power        PowerDraw
	Voltages     []Voltage
	// PowerTelemetry is whether the server reports PSUs/power draw at all (zero = unknown).
	PowerTelemetry PowerTelemetry
	// Problems lists sections that could not be read (e.g. "power: bmc: HTTP 5xx").
	Problems []string
}

// Snapshot is an immutable point-in-time view of one server's sensors and health.
// Accessors return copies, so a published Snapshot can be shared between goroutines.
type Snapshot struct {
	p SnapshotParams
}

// NewSnapshot builds a Snapshot, copying every slice.
func NewSnapshot(p SnapshotParams) Snapshot {
	p.Temperatures = slices.Clone(p.Temperatures)
	p.Fans = slices.Clone(p.Fans)
	p.PSUs = slices.Clone(p.PSUs)
	p.Voltages = slices.Clone(p.Voltages)
	p.Problems = slices.Clone(p.Problems)
	return Snapshot{p: p}
}

// TakenAt is when the snapshot was assembled.
func (s Snapshot) TakenAt() time.Time { return s.p.TakenAt }

// PowerState is the host power state.
func (s Snapshot) PowerState() PowerState { return s.p.PowerState }

// PowerAsOf is when the power state was observed: the poll, or a later verified power
// action (WithPowerState).
func (s Snapshot) PowerAsOf() time.Time {
	if s.p.PowerAsOf.IsZero() {
		return s.p.TakenAt
	}
	return s.p.PowerAsOf
}

// WithPowerState returns a copy of s whose power state is st as of at (a verified power
// action); everything else, TakenAt included, is kept. s is not modified.
func (s Snapshot) WithPowerState(st PowerState, at time.Time) Snapshot {
	p := s.p
	p.PowerState, p.PowerAsOf = st, at
	return NewSnapshot(p)
}

// Health is the overall health rollup.
func (s Snapshot) Health() Health { return s.p.Health }

// Power is the chassis power draw.
func (s Snapshot) Power() PowerDraw { return s.p.Power }

// Temperatures returns a copy of the temperature sensors.
func (s Snapshot) Temperatures() []Temperature { return slices.Clone(s.p.Temperatures) }

// Fans returns a copy of the fan sensors.
func (s Snapshot) Fans() []Fan { return slices.Clone(s.p.Fans) }

// PSUs returns a copy of the power supplies.
func (s Snapshot) PSUs() []PSU { return slices.Clone(s.p.PSUs) }

// Voltages returns a copy of the voltage sensors.
func (s Snapshot) Voltages() []Voltage { return slices.Clone(s.p.Voltages) }

// PowerTelemetry reports whether the server monitors its PSUs and power draw.
func (s Snapshot) PowerTelemetry() PowerTelemetry {
	if s.p.PowerTelemetry == "" {
		return PowerTelemetryUnknown
	}
	return s.p.PowerTelemetry
}

// Problems returns a copy of the per-section read problems.
func (s Snapshot) Problems() []string { return slices.Clone(s.p.Problems) }

// Degraded reports whether any section failed to read.
func (s Snapshot) Degraded() bool { return len(s.p.Problems) > 0 }
