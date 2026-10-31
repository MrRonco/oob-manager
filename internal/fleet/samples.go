package fleet

import (
	"context"

	"oob-manager/internal/bmc"
	"oob-manager/internal/store"
)

// Sample key prefixes. Keys are "<prefix>:<sensor ID or name>" (the BMC member ID, stable
// across polls; the name when there is none); the UI and the API ask for history with
// the same key. Rollups, retention and reads live in internal/history.
const (
	KeyTemperature = "temp"
	KeyFan         = "fan"
	KeyPowerWatts  = "power:consumed"
	KeyPSUIn       = "psu_in"
	KeyPSUOut      = "psu_out"
	KeyVoltage     = "volt"
)

// SampleKey builds the history key of a sensor.
func SampleKey(prefix, id, name string) string {
	if id != "" {
		return prefix + ":" + id
	}
	return prefix + ":" + name
}

// Sampling switches the optional sensor families on (Settings → General,
// history.sample_psus and history.sample_voltages).
type Sampling struct {
	PSUs, Voltages bool
}

// Per-family caps of one poll's samples (the drivers' own caps, again: a driver that
// does not cap cannot flood the history either; review HIGH-1).
const (
	maxSampleTemps = 128
	maxSampleFans  = 32
	maxSamplePSUs  = 16 // two samples each
	maxSampleVolts = 64
)

// AllSampling records every family.
func AllSampling() Sampling { return Sampling{PSUs: true, Voltages: true} }

// HistorySamples turns a snapshot into the samples of one poll: valid readings only, in
// the BMC's units, one per key (the first wins). Power-good signals are never sampled
// (bmc.Voltage.IsPowerGood).
func HistorySamples(s bmc.Snapshot, on Sampling) []store.SensorSample {
	var out []store.SensorSample
	seen := map[string]bool{}
	add := func(key string, kind store.SensorKind, unit store.SensorUnit, name string, r bmc.Reading) {
		if r.Valid && key != "" && !seen[key] {
			seen[key] = true
			out = append(out, store.SensorSample{Key: key, Kind: kind, Unit: unit, Name: name, Value: r.Value})
		}
	}
	for _, t := range capped(s.Temperatures(), maxSampleTemps) {
		add(SampleKey(KeyTemperature, t.ID, t.Name), store.SensorTemp, store.UnitCelsius, t.Name, t.Celsius)
	}
	for _, f := range capped(s.Fans(), maxSampleFans) {
		unit := store.UnitRPM
		if f.Units == bmc.FanPercent {
			unit = store.UnitPercent
		}
		add(SampleKey(KeyFan, f.ID, f.Name), store.SensorFan, unit, f.Name, f.Speed)
	}
	add(KeyPowerWatts, store.SensorPower, store.UnitWatts, "Power draw", s.Power().ConsumedWatts)
	if on.PSUs {
		for _, p := range capped(s.PSUs(), maxSamplePSUs) {
			add(SampleKey(KeyPSUIn, p.ID, p.Name), store.SensorPSUIn, store.UnitWatts, p.Name+" input", p.InputWatts)
			add(SampleKey(KeyPSUOut, p.ID, p.Name), store.SensorPSUOut, store.UnitWatts, p.Name+" output", p.OutputWatts)
		}
	}
	if on.Voltages {
		var analog []bmc.Voltage
		for _, v := range s.Voltages() {
			if !v.IsPowerGood() {
				analog = append(analog, v)
			}
		}
		for _, v := range capped(analog, maxSampleVolts) {
			add(SampleKey(KeyVoltage, v.ID, v.Name), store.SensorVolt, store.UnitVolts, v.Name, v.Volts)
		}
	}
	return out
}

// capped is at most n items of xs.
func capped[T any](xs []T, n int) []T {
	if len(xs) > n {
		return xs[:n]
	}
	return xs
}

// storeSamples records the poll's readings and returns how many samples of new sensors
// the store refused (the server has store.MaxKeysPerServer; logged once per poller) plus
// the archives it dropped (logged every time).
// History is best-effort: a failed insert is logged and polling goes on. When the poll is older than samples already stored (the
// wall clock moved back, for example NTP after a cold boot without an RTC), it logs one
// warning and records the time once per occurrence; nothing stored is rewritten.
func (p *poller) storeSamples(ctx context.Context, snap bmc.Snapshot) int64 {
	if p.cfg.Samples == nil {
		return 0
	}
	on := AllSampling()
	if p.cfg.Sampling != nil {
		on = p.cfg.Sampling()
	}
	res, err := p.cfg.Samples.Insert(ctx, store.SensorPoll{ServerID: p.target.ID, TS: snap.TakenAt(),
		Samples: HistorySamples(snap, on)})
	if err != nil {
		p.cfg.Logger.Warn("fleet: store samples failed", "server", p.target.ID, "error", err)
		return 0
	}
	p.noteHistoryOddities(res)
	if res.Behind && !p.behind {
		p.cfg.Logger.Warn("fleet: the clock moved back; history samples around it may overlap",
			"server", p.target.ID, "at", snap.TakenAt())
		if nerr := p.cfg.Samples.NoteClockJump(ctx, snap.TakenAt()); nerr != nil {
			p.cfg.Logger.Warn("fleet: record the clock jump failed", "error", nerr)
		}
	}
	p.behind = res.Behind
	return int64(res.Refused + res.Dropped)
}

// noteHistoryOddities logs, once per poller, sensors refused by the key cap, and every
// sensor whose unit or kind changed (its old readings are kept under an archived key).
func (p *poller) noteHistoryOddities(res store.InsertResult) {
	if res.Refused > 0 && !p.refusedLogged {
		p.refusedLogged = true
		p.cfg.Logger.Warn("fleet: the BMC reports more sensors than the history keeps; new ones are not recorded",
			"server", p.target.ID, "limit", store.MaxKeysPerServer, "refused", res.Refused)
	}
	if res.Archived > 0 && !p.archivedLogged {
		p.archivedLogged = true
		p.cfg.Logger.Warn("fleet: a sensor changed its unit or kind; its readings in each unit are kept apart",
			"server", p.target.ID, "sensors", res.Archived)
	}
	if res.Dropped > 0 { // rare: a sensor cycling through more than MaxArchivesPerKey units or kinds
		p.cfg.Logger.Warn("fleet: a sensor's oldest archived history was deleted (too many unit or kind changes)",
			"server", p.target.ID, "archives", res.Dropped, "limit", store.MaxArchivesPerKey)
	}
}
