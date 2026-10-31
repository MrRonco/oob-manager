package metrics

import (
	"strings"

	"oob-manager/internal/bmc"
)

// capped returns at most MaxSensorsPerServer items and records the rest as dropped
// (perSeries: how many series each left-out item would have produced).
func capped[T any](b *builder, items []T, perSeries int) []T {
	if len(items) <= MaxSensorsPerServer {
		return items
	}
	b.drop((len(items) - MaxSensorsPerServer) * perSeries)
	return items[:MaxSensorsPerServer]
}

// sensorID is the stable series key: the BMC member ID, or the name when it has none.
func sensorID(id, name string) string {
	if strings.TrimSpace(id) != "" {
		return id
	}
	return name
}

func addSensors(b *builder, snap bmc.Snapshot, sl Label) {
	addTemps(b, snap, sl)
	addFanSpeeds(b, snap, sl)
	addPSUs(b, snap, sl)
	for _, v := range capped(b, snap.Voltages(), 1) {
		if v.Volts.Valid {
			b.add("oob_voltage_volts", v.Volts.Value, sl, Label{"sensor", sensorID(v.ID, v.Name)}, Label{"name", v.Name})
		}
	}
	if d := snap.Power().ConsumedWatts; d.Valid && snap.PowerTelemetry() == bmc.PowerTelemetryAvailable {
		b.add("oob_server_power_watts", d.Value, sl)
	}
}

func addTemps(b *builder, snap bmc.Snapshot, sl Label) {
	for _, t := range capped(b, snap.Temperatures(), 3) {
		ls := []Label{sl, {"sensor", sensorID(t.ID, t.Name)}, {"name", t.Name}, {"kind", t.Context}}
		if t.Celsius.Valid {
			b.add("oob_temperature_celsius", t.Celsius.Value, ls...)
		}
		if t.WarnAbove.Valid {
			b.add("oob_temperature_upper_warning_celsius", t.WarnAbove.Value, ls...)
		}
		if t.CritAbove.Valid {
			b.add("oob_temperature_upper_critical_celsius", t.CritAbove.Value, ls...)
		}
	}
}

func addFanSpeeds(b *builder, snap bmc.Snapshot, sl Label) {
	for _, f := range capped(b, snap.Fans(), 1) {
		if !f.Speed.Valid {
			continue
		}
		name := "oob_fan_speed_rpm"
		if f.Units == bmc.FanPercent {
			name = "oob_fan_speed_percent"
		}
		b.add(name, f.Speed.Value, sl, Label{"fan", sensorID(f.ID, f.Name)}, Label{"name", f.Name})
	}
}

func addPSUs(b *builder, snap bmc.Snapshot, sl Label) {
	if snap.PowerTelemetry() != bmc.PowerTelemetryAvailable {
		return
	}
	ok := 0
	psus := snap.PSUs()
	for _, p := range capped(b, psus, 2) {
		ls := []Label{sl, {"psu", sensorID(p.ID, p.Name)}, {"name", p.Name}}
		healthy := p.Health == bmc.HealthOK
		ok += int(b2f(healthy))
		b.add("oob_psu_healthy", b2f(healthy), ls...)
		if p.InputWatts.Valid {
			b.add("oob_psu_input_watts", p.InputWatts.Value, ls...)
		}
	}
	if len(psus) > 0 {
		b.add("oob_psu_redundant", b2f(ok >= 2), sl)
	}
}
