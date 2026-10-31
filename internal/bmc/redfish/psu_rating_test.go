package redfish

import (
	"testing"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

// The captured iDRAC8 reports PowerInputWatts 900 on each 750 W PSU while the chassis
// draws 263 W: 900 W is the rated maximum input, not a measurement (UI review F-11).
// The rated output comes from InputRanges[].OutputWattage; no live per-PSU figure exists.
func TestIDRAC8PSURatingIsNotShownAsLiveInput(t *testing.T) {
	snap, err := driverFor(t, mockFor(t, idrac8)).Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	psus := snap.PSUs()
	if len(psus) != 2 {
		t.Fatalf("%d PSUs", len(psus))
	}
	for _, p := range psus {
		if p.InputWatts.Valid || p.OutputWatts.Valid {
			t.Errorf("%s: live input %+v / output %+v from a rating", p.Name, p.InputWatts, p.OutputWatts)
		}
		if !p.RatedInputWatts.Valid || p.RatedInputWatts.Value != 900 {
			t.Errorf("%s: rated input = %+v", p.Name, p.RatedInputWatts)
		}
		if !p.CapacityWatts.Valid || p.CapacityWatts.Value != 750 {
			t.Errorf("%s: rated output = %+v", p.Name, p.CapacityWatts)
		}
	}
	if d := snap.Power(); !d.ConsumedWatts.Valid || d.ConsumedWatts.Value != 263 {
		t.Fatalf("chassis draw = %+v", d.ConsumedWatts)
	}
}

// SYNTHETIC: a BMC whose per-PSU input adds up to the chassis draw reports live input,
// and LastPowerOutputWatts is the live output.
func TestPlausiblePSUInputIsLive(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithOverlay(powerURI, `{"PowerControl": [{"MemberId": "0",
		"PowerConsumedWatts": 250}], "PowerSupplies": [
		{"MemberId": "0", "Name": "PS1", "PowerInputWatts": 130, "LastPowerOutputWatts": 118, "PowerCapacityWatts": 495},
		{"MemberId": "1", "Name": "PS2", "PowerInputWatts": 121, "PowerOutputWatts": 109, "PowerCapacityWatts": 495}]}`))
	snap, err := driverFor(t, s).Snapshot(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	ps := snap.PSUs()
	if len(ps) != 2 || ps[0].InputWatts.Value != 130 || ps[0].OutputWatts.Value != 118 ||
		ps[1].OutputWatts.Value != 109 || ps[0].RatedInputWatts.Valid {
		t.Fatalf("PSUs = %+v", ps)
	}
}

func TestReclassifyRatedInput(t *testing.T) {
	psu := func(in float64) bmc.PSU { return bmc.PSU{InputWatts: bmc.ReadingOf(in)} }
	draw := bmc.PowerDraw{ConsumedWatts: bmc.ReadingOf(263)}
	got := reclassifyRatedInput([]bmc.PSU{psu(900), psu(900)}, draw)
	if got[0].InputWatts.Valid || got[0].RatedInputWatts.Value != 900 {
		t.Fatalf("implausible input kept as live: %+v", got[0])
	}
	live := reclassifyRatedInput([]bmc.PSU{psu(140), psu(135)}, draw)
	if !live[0].InputWatts.Valid || live[0].RatedInputWatts.Valid {
		t.Fatalf("plausible input reclassified: %+v", live[0])
	}
	noDraw := reclassifyRatedInput([]bmc.PSU{psu(900)}, bmc.PowerDraw{})
	if !noDraw[0].InputWatts.Valid {
		t.Fatal("without a chassis figure nothing can be judged; keep the value")
	}
}
