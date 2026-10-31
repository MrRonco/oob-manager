package ui

import (
	"strings"
	"testing"

	"oob-manager/internal/bmc"
)

func TestReadingChange(t *testing.T) {
	cases := []struct {
		cur, prev bmc.Reading
		want      string
	}{
		{bmc.ReadingOf(41), bmc.ReadingOf(40), "up"},
		{bmc.ReadingOf(39), bmc.ReadingOf(40), "down"},
		{bmc.ReadingOf(40.2), bmc.ReadingOf(40), ""}, // same at the shown precision
		{bmc.ReadingOf(40), bmc.NoReading(), ""},     // new reading: nothing to compare
		{bmc.NoReading(), bmc.ReadingOf(40), ""},
	}
	for _, c := range cases {
		if got := readingChange(c.cur, c.prev); got != c.want {
			t.Errorf("readingChange(%v, %v) = %q, want %q", c.cur, c.prev, got, c.want)
		}
	}
}

func TestSensorRowsMarkChanges(t *testing.T) {
	prevT := []bmc.Temperature{{Name: "CPU1 Temp", Context: "CPU", Celsius: bmc.ReadingOf(50)}, {Name: "Inlet", Context: "Intake", Celsius: bmc.ReadingOf(21)}}
	curT := []bmc.Temperature{{Name: "CPU1 Temp", Context: "CPU", Celsius: bmc.ReadingOf(53)}, {Name: "Inlet", Context: "Intake", Celsius: bmc.ReadingOf(21)},
		{Name: "Exhaust", Context: "Exhaust", Celsius: bmc.ReadingOf(30)}}
	rows := tempRows(curT, celsius())
	marked := withTempChanges(rows, curT, prevT)
	got := map[string]string{}
	for _, r := range marked {
		got[r.FullName] = r.Change
	}
	if got["CPU1 Temp"] != "up" || got["Inlet"] != "" || got["Exhaust"] != "" {
		t.Fatalf("temperature changes %v", got)
	}
	for _, r := range rows {
		if r.Change != "" {
			t.Fatalf("withTempChanges modified its input: %+v", r)
		}
	}

	prevF := []bmc.Fan{{Name: "Fan 1", Speed: bmc.ReadingOf(7200)}, {Name: "Fan 2", Speed: bmc.ReadingOf(7000)}}
	curF := []bmc.Fan{{Name: "Fan 1", Speed: bmc.ReadingOf(6840)}, {Name: "Fan 2", Speed: bmc.ReadingOf(7000)}}
	fans := withFanChanges(fanRows(curF), curF, prevF)
	if fans[0].Change != "down" || fans[1].Change != "" {
		t.Fatalf("fan changes %+v", fans)
	}
}

// TestSensorTablesCarryTheChangeClass: the Sensors tab marks a changed reading's cell
// (motion.css tints it; nothing else uses the class).
func TestSensorTablesCarryTheChangeClass(t *testing.T) {
	rd, err := newRenderer()
	must(t, err)
	cur := []bmc.Temperature{{Name: "Inlet", Context: "Intake", Celsius: bmc.ReadingOf(24)}}
	prev := []bmc.Temperature{{Name: "Inlet", Context: "Intake", Celsius: bmc.ReadingOf(22)}}
	temps := withTempChanges(tempRows(cur, celsius()), cur, prev)
	var b strings.Builder
	must(t, rd.pages[pageSensors].ExecuteTemplate(&b, "tempspanel", serverDetail{Temps: temps, TempUnit: "°C"}))
	if !strings.Contains(b.String(), `class="num chg chg-up"`) {
		t.Fatalf("changed temperature not marked:\n%s", b.String())
	}
	curF := []bmc.Fan{{Name: "Fan 1", Speed: bmc.ReadingOf(6000)}}
	prevF := []bmc.Fan{{Name: "Fan 1", Speed: bmc.ReadingOf(6600)}}
	b.Reset()
	must(t, rd.pages[pageSensors].ExecuteTemplate(&b, "fanspanel", withFanChanges(fanRows(curF), curF, prevF)))
	if !strings.Contains(b.String(), `<strong class="chg chg-down">6000</strong>`) {
		t.Fatalf("changed fan not marked:\n%s", b.String())
	}
	b.Reset()
	must(t, rd.pages[pageSensors].ExecuteTemplate(&b, "fanspanel", fanRows(curF)))
	if strings.Contains(b.String(), "chg") {
		t.Fatalf("unchanged fan marked:\n%s", b.String())
	}
}
