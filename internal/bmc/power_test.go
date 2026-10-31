package bmc

import "testing"

func TestSnapshotVoltagesAreCopied(t *testing.T) {
	vs := []Voltage{{ID: "0", Name: "CPU1 VCORE VR", Volts: ReadingOf(0.18), Health: HealthOK}}
	s := NewSnapshot(SnapshotParams{Voltages: vs, PowerTelemetry: PowerTelemetryUnavailable})
	vs[0].Name = "mutated"
	got := s.Voltages()
	if len(got) != 1 || got[0].Name != "CPU1 VCORE VR" {
		t.Fatalf("voltages not copied: %+v", got)
	}
	got[0].Name = "mutated"
	if s.Voltages()[0].Name != "CPU1 VCORE VR" {
		t.Fatal("accessor returned shared slice")
	}
	if s.PowerTelemetry() != PowerTelemetryUnavailable {
		t.Fatalf("telemetry = %q", s.PowerTelemetry())
	}
}

func TestPowerTelemetryDefaultsToUnknown(t *testing.T) {
	if got := NewSnapshot(SnapshotParams{}).PowerTelemetry(); got != PowerTelemetryUnknown {
		t.Fatalf("zero telemetry = %q", got)
	}
}

func TestClassifyPowerTelemetry(t *testing.T) {
	psu := []PSU{{ID: "PSU.Slot.1"}}
	cases := map[string]struct {
		psus  []PSU
		draw  PowerDraw
		ok    bool
		want  PowerTelemetry
		blank bool
	}{
		"read failed":      {psus: psu, ok: false, want: PowerTelemetryUnknown},
		"psus":             {psus: psu, ok: true, want: PowerTelemetryAvailable},
		"watts only":       {draw: PowerDraw{ConsumedWatts: ReadingOf(120)}, ok: true, want: PowerTelemetryAvailable},
		"nothing":          {ok: true, want: PowerTelemetryUnavailable},
		"all zero":         {draw: PowerDraw{ConsumedWatts: ReadingOf(0), MaxWatts: ReadingOf(0)}, ok: true, want: PowerTelemetryUnavailable, blank: true},
		"psus, zero watts": {psus: psu, draw: PowerDraw{ConsumedWatts: ReadingOf(0)}, ok: true, want: PowerTelemetryAvailable},
	}
	for name, c := range cases {
		got, draw := ClassifyPower(c.psus, c.draw, c.ok)
		if got != c.want {
			t.Errorf("%s: %q, want %q", name, got, c.want)
		}
		if c.blank && draw != (PowerDraw{}) {
			t.Errorf("%s: zero draw kept: %+v", name, draw)
		}
		if !c.blank && draw != c.draw {
			t.Errorf("%s: draw changed: %+v", name, draw)
		}
	}
}

func TestVoltageIsPowerGood(t *testing.T) {
	for name, want := range map[string]bool{"CPU1 VCORE PG": true, "PS1 PG Fail": true, "PG": true,
		"System Board 3.3V": false, "PGOOD": false, "CPU1 VCOREPG": false, "": false} {
		if got := (Voltage{Name: name}).IsPowerGood(); got != want {
			t.Errorf("IsPowerGood(%q) = %v, want %v", name, got, want)
		}
	}
}
