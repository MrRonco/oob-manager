package display

import (
	"errors"
	"slices"
	"testing"
	"time"
)

func TestEveryZoneLoads(t *testing.T) {
	zones := canonicalZones()
	if !slices.IsSorted(zones) {
		t.Fatal("canonicalZones must be sorted (KnownZone binary-searches it)")
	}
	if len(zones) < 300 {
		t.Fatalf("only %d zones", len(zones))
	}
	for _, z := range zones {
		if _, err := LoadZone(z); err != nil {
			t.Errorf("%s: %v", z, err)
		}
	}
}

func TestZoneGroups(t *testing.T) {
	g := ZoneGroups()
	if g[0].Region != "UTC" || g[0].Zones[0].Name != UTC {
		t.Fatalf("UTC must come first: %+v", g[0])
	}
	found := false
	for _, grp := range g {
		for _, z := range grp.Zones {
			if z.Name == "America/Argentina/Buenos_Aires" {
				found = z.Label == "Argentina / Buenos Aires" && grp.Region == "America"
			}
		}
	}
	if !found {
		t.Fatal("Buenos Aires missing or mislabelled")
	}
	g[0].Region = "changed"
	if ZoneGroups()[0].Region != "UTC" {
		t.Fatal("ZoneGroups must return a fresh value")
	}
}

func TestLoadZoneRejects(t *testing.T) {
	for _, bad := range []string{"", "Local", "EST", "US/Eastern", "America/Nowhere", "../etc/passwd",
		"america/new_york", "America/New_York ", "Etc/GMT+5"} {
		if _, err := LoadZone(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q accepted", bad)
		}
	}
	loc, err := LoadZone("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	summer := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC).In(loc)
	if name, _ := summer.Zone(); name != "EDT" {
		t.Fatalf("zone abbreviation %q", name)
	}
}

func TestParseTheme(t *testing.T) {
	for _, th := range Themes() {
		if got, err := ParseTheme(string(th.ID)); err != nil || got != th.ID {
			t.Errorf("%s: %v", th.ID, err)
		}
	}
	if _, err := ParseTheme("Graphite"); err == nil {
		t.Fatal("case must match exactly")
	}
}

func TestPrefsValidate(t *testing.T) {
	good := Prefs{TimeZone: "Europe/Paris", Theme: "nord", DateFormat: "us", Clock: "12h", TempUnit: "f", Density: "comfortable"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := (Prefs{}).Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []Prefs{{TimeZone: "Mars/Base"}, {Theme: "pink"}, {DateFormat: "eu"}, {Clock: "36h"},
		{TempUnit: "k"}, {Density: "huge"}} {
		if err := bad.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestResolve(t *testing.T) {
	app := Prefs{TimeZone: "America/New_York", Theme: "nord"}
	v := Resolve(Prefs{}, app)
	if v.Zone != "America/New_York" || v.Theme != ThemeNord || v.Date != DateISO || v.Clock != Clock24 ||
		v.Temp != Celsius || v.Density != Compact || v.Loc == nil {
		t.Fatalf("app defaults: %+v", v)
	}
	u := Resolve(Prefs{TimeZone: "Asia/Tokyo", Theme: "dracula", DateFormat: "us", Clock: "12h", TempUnit: "f",
		Density: "comfortable"}, app)
	if u.Zone != "Asia/Tokyo" || u.Loc.String() != "Asia/Tokyo" || u.Theme != ThemeDracula || u.Date != DateUS ||
		u.Clock != Clock12 || u.Temp != Fahrenheit || u.Density != Comfortable {
		t.Fatalf("user override: %+v", u)
	}
	bad := Resolve(Prefs{TimeZone: "Gone/Zone", Theme: "gone"}, Prefs{TimeZone: "Also/Gone", Theme: "gone", Clock: "25h"})
	if bad.Zone != UTC || bad.Loc != time.UTC || bad.Theme != DefaultTheme || bad.Clock != Clock24 {
		t.Fatalf("fallback: %+v", bad)
	}
	// App defaults for the formats apply to a user who chose none; a user's own choice wins.
	appFmt := Prefs{DateFormat: "us", Clock: "12h", TempUnit: "f", Density: "comfortable"}
	if a := Resolve(Prefs{}, appFmt); a.Date != DateUS || a.Clock != Clock12 || a.Temp != Fahrenheit || a.Density != Comfortable {
		t.Fatalf("app format defaults: %+v", a)
	}
	if o := Resolve(Prefs{Clock: "24h", TempUnit: "c"}, appFmt); o.Clock != Clock24 || o.Temp != Celsius || o.Date != DateUS {
		t.Fatalf("user over app formats: %+v", o)
	}
	if ChoiceLabel("12h", ClockFormats()) != "12-hour (2:05 PM)" || ChoiceLabel("x", ClockFormats()) != "x" ||
		ChoiceValues(TempUnits()) != "c, f" {
		t.Fatal("choice helpers")
	}
}

func TestChoiceLists(t *testing.T) {
	for _, cs := range [][]Choice{DateFormats(), ClockFormats(), TempUnits(), Densities()} {
		if len(cs) != 2 {
			t.Fatalf("%v", cs)
		}
	}
}
