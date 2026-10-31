package redfish

import (
	"context"
	"encoding/json"

	"github.com/stmcginnis/gofish/schemas"

	"oob-manager/internal/bmc"
)

// Bounds on per-member GETs so a hostile or buggy BMC cannot make one poll unbounded.
const (
	maxFans  = 32
	maxPSUs  = 16
	maxTemps = 128
)

// subsystemThermal reads ThermalSubsystem: Fans (one GET per fan) and ThermalMetrics.
func (d *Driver) subsystemThermal(ctx context.Context, uri string) (thermalData, error) {
	doc, found, err := optional[thermalSubsystemDoc](ctx, d, uri)
	if err != nil || !found {
		return thermalData{}, err
	}
	fans, err := d.subsystemFans(ctx, doc.Fans.ID)
	if err != nil {
		return thermalData{}, err
	}
	temps, err := d.subsystemTemps(ctx, doc.ThermalMetrics.ID)
	if err != nil {
		return thermalData{}, err
	}
	return thermalData{temps: temps, fans: fans}, nil
}

func (d *Driver) subsystemFans(ctx context.Context, collection string) ([]bmc.Fan, error) {
	members, err := d.optionalMembers(ctx, collection, maxFans)
	if err != nil {
		return nil, err
	}
	var out []bmc.Fan
	for _, m := range members {
		f, found, err := optional[fanDoc](ctx, d, m)
		if err != nil {
			return nil, err
		}
		if found {
			out = append(out, subsystemFan(f))
		}
	}
	return out, nil
}

// fanDoc is the part of a ThermalSubsystem Fan the driver reads. SpeedPercent is kept
// raw so a SpeedRPM that is present but null (a momentary gap) is told apart from one
// that is absent (a fan reported in percent only).
type fanDoc struct {
	ID           string                     `json:"Id"`
	Name         string                     `json:"Name"`
	Status       schemas.Status             `json:"Status"`
	SpeedPercent map[string]json.RawMessage `json:"SpeedPercent"`
}

// subsystemFan reads a fan's speed: in RPM whenever the fan reports SpeedRPM (a null
// reading is no reading, never a switch to percent, so its history keeps one unit),
// else the percent Reading.
func subsystemFan(f fanDoc) bmc.Fan {
	key, units := "Reading", bmc.FanPercent
	if _, ok := f.SpeedPercent["SpeedRPM"]; ok {
		key, units = "SpeedRPM", bmc.FanRPM
	}
	var v *float64
	if raw, ok := f.SpeedPercent[key]; ok {
		var x *float64
		if json.Unmarshal(raw, &x) == nil { // null or a wrongly typed value is no reading
			v = x
		}
	}
	return bmc.Fan{
		ID:     clean(f.ID),
		Name:   clean(f.Name),
		Speed:  bmc.ReadingFrom(v),
		Units:  units,
		Health: bmc.ParseHealth(string(f.Status.Health)),
	}
}

func (d *Driver) subsystemTemps(ctx context.Context, uri string) ([]bmc.Temperature, error) {
	tm, found, err := optional[schemas.ThermalMetrics](ctx, d, uri)
	if err != nil || !found {
		return nil, err
	}
	var out []bmc.Temperature
	for i, r := range tm.TemperatureReadingsCelsius {
		if i >= maxTemps {
			break
		}
		out = append(out, bmc.Temperature{
			ID:      clean(r.DataSourceURI),
			Name:    clean(r.DeviceName),
			Context: clean(string(r.PhysicalContext)),
			Celsius: bmc.ReadingFrom(r.Reading),
			Health:  bmc.HealthUnknown,
		})
	}
	return out, nil
}

// subsystemPower reads PowerSubsystem/PowerSupplies (one GET per PSU). The new schema
// has no chassis-level consumption figure, so PowerDraw stays empty.
func (d *Driver) subsystemPower(ctx context.Context, uri string) (powerData, error) {
	doc, found, err := optional[powerSubsystemDoc](ctx, d, uri)
	if err != nil || !found {
		return powerData{}, err
	}
	members, err := d.optionalMembers(ctx, doc.PowerSupplies.ID, maxPSUs)
	if err != nil {
		return powerData{}, err
	}
	var out powerData
	for _, m := range members {
		p, found, err := optional[schemas.PowerSupplyUnit](ctx, d, m)
		if err != nil {
			return powerData{}, err
		}
		if found {
			out.psus = append(out.psus, bmc.PSU{
				ID:            clean(p.ID),
				Name:          clean(p.Name),
				Model:         clean(p.Model),
				Firmware:      clean(p.FirmwareVersion),
				CapacityWatts: bmc.ReadingFrom(p.PowerCapacityWatts),
				Health:        bmc.ParseHealth(string(p.Status.Health)),
			})
		}
	}
	return out, nil
}

// optionalMembers lists up to limit members of a collection; absent means none.
func (d *Driver) optionalMembers(ctx context.Context, uri string, limit int) ([]string, error) {
	col, _, err := optional[collectionDoc](ctx, d, uri)
	if err != nil {
		return nil, err
	}
	uris := col.uris()
	if len(uris) > limit {
		uris = uris[:limit]
	}
	return uris, nil
}
