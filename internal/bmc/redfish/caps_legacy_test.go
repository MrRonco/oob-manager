package redfish

import (
	"encoding/json"
	"fmt"
	"testing"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

// TestLegacyThermalAndPowerAreCapped (review HIGH-1): a BMC listing hundreds of sensors
// in the legacy Thermal and Power resources is cut to the same caps as the subsystem
// path (128 temperatures, 32 fans, 16 PSUs, 64 voltages).
func TestLegacyThermalAndPowerAreCapped(t *testing.T) {
	s := mockFor(t, idrac8,
		redfishmock.WithOverlay(thermalURI, manyOf(t, s0(t).fixture(thermalURI), "Temperatures", "Fans")),
		redfishmock.WithOverlay(powerURI, manyOf(t, s0(t).fixture(powerURI), "PowerSupplies", "Voltages")))
	snap, err := driverFor(t, s).Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if p := snap.Problems(); len(p) > 0 {
		t.Fatalf("problems %v", p)
	}
	if n := len(snap.Temperatures()); n != maxTemps {
		t.Errorf("%d temperatures", n)
	}
	if n := len(snap.Fans()); n != maxFans {
		t.Errorf("%d fans", n)
	}
	if n := len(snap.PSUs()); n != maxPSUs {
		t.Errorf("%d PSUs", n)
	}
	if n := len(snap.Voltages()); n != maxVoltages {
		t.Errorf("%d voltages", n)
	}
}

type fixtures struct{ m *redfishmock.Server }

func s0(t *testing.T) fixtures { return fixtures{mockFor(t, idrac8)} }

func (f fixtures) fixture(path string) []byte {
	b, ok := f.m.Fixture(path)
	if !ok {
		panic("no fixture " + path)
	}
	return b
}

// manyOf repeats the first member of each named array of a captured document 300 times
// with distinct member IDs and names: a BMC that lists hundreds of sensors.
func manyOf(t *testing.T, doc []byte, arrays ...string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	for _, a := range arrays {
		arr, ok := m[a].([]any)
		if !ok || len(arr) == 0 {
			t.Fatalf("fixture has no %s", a)
		}
		first, ok := arr[0].(map[string]any)
		if !ok {
			t.Fatalf("%s[0] is not an object", a)
		}
		var out []any
		for i := 0; i < 300; i++ {
			c := map[string]any{}
			for k, v := range first {
				c[k] = v
			}
			c["MemberId"], c["Name"] = fmt.Sprintf("m%d", i), fmt.Sprintf("Sensor %d", i)
			out = append(out, c)
		}
		m[a] = out
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestSubsystemFanNullRPMKeepsItsUnit (re-check MEDIUM-N1a): a fan that reports SpeedRPM
// keeps RPM as its unit when the reading is momentarily null (the sample is skipped:
// no valid reading), instead of flipping to the percent reading.
func TestSubsystemFanNullRPMKeepsItsUnit(t *testing.T) {
	for doc, want := range map[string]struct {
		units bmc.FanUnits
		valid bool
		value float64
	}{
		`{"Id":"F","SpeedPercent":{"SpeedRPM":7920,"Reading":40}}`: {bmc.FanRPM, true, 7920},
		`{"Id":"F","SpeedPercent":{"SpeedRPM":null,"Reading":40}}`: {bmc.FanRPM, false, 0},
		`{"Id":"F","SpeedPercent":{"Reading":40}}`:                 {bmc.FanPercent, true, 40},
		`{"Id":"F","SpeedPercent":{"SpeedRPM":"x"}}`:               {bmc.FanRPM, false, 0},
		`{"Id":"F"}`: {bmc.FanPercent, false, 0},
	} {
		var f fanDoc
		if err := json.Unmarshal([]byte(doc), &f); err != nil {
			t.Fatal(err)
		}
		got := subsystemFan(f)
		if got.Units != want.units || got.Speed.Valid != want.valid || got.Speed.Value != want.value {
			t.Errorf("%s = %+v, want %+v", doc, got, want)
		}
	}
}
