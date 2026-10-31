package bmc

import "regexp"

// PowerTelemetry says whether a BMC reports power supplies or power draw at all. Some
// servers (for example a cabled, non-PMBus PSU) expose neither: no PSUs in either
// Redfish schema, an empty PowerControl and all-zero power metrics. That is a property
// of the server, not a fault, and the UI says "Not monitored by this server" for it
// instead of "Unknown".
type PowerTelemetry string

// Power telemetry states.
const (
	PowerTelemetryUnknown     PowerTelemetry = "unknown"     // not read yet, or the read failed
	PowerTelemetryAvailable   PowerTelemetry = "available"   // PSUs and/or a non-zero draw reported
	PowerTelemetryUnavailable PowerTelemetry = "unavailable" // read fine, nothing reported
)

// Voltage is one voltage sensor. Many are discrete "power good" sensors whose reading
// is null; their Health is still meaningful.
type Voltage struct {
	ID      string
	Name    string
	Context string // PhysicalContext, e.g. "SystemBoard", "CPU"
	Volts   Reading
	Health  Health
}

// powerGoodName matches iDRAC power-good signals ("CPU1 VCORE PG", "PS1 PG Fail"): boolean
// signals that the BMC reports as voltage sensors (UX-02).
var powerGoodName = regexp.MustCompile(`(^|\s)PG(\s|$)`)

// IsPowerGood reports whether v is a power-good signal rather than an analog rail: the
// UI shows it as Good or Fault, and the history never samples it.
func (v Voltage) IsPowerGood() bool { return powerGoodName.MatchString(v.Name) }

// ClassifyPower decides the telemetry state from what a successful (ok) power read
// returned. When nothing is monitored, an all-zero draw is replaced by an empty one so
// that 0 W is never shown or sampled as if it were a measurement.
func ClassifyPower(psus []PSU, draw PowerDraw, ok bool) (PowerTelemetry, PowerDraw) {
	switch {
	case !ok:
		return PowerTelemetryUnknown, draw
	case len(psus) > 0 || nonZero(draw):
		return PowerTelemetryAvailable, draw
	default:
		return PowerTelemetryUnavailable, PowerDraw{}
	}
}

func nonZero(d PowerDraw) bool {
	for _, r := range []Reading{d.ConsumedWatts, d.AverageWatts, d.MinWatts, d.MaxWatts, d.CapacityWatts} {
		if r.Valid && r.Value != 0 {
			return true
		}
	}
	return false
}
