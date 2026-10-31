package redfish

import (
	"encoding/json"
	"testing"

	"github.com/stmcginnis/gofish/schemas"

	"oob-manager/internal/bmc"
)

func TestFlexString(t *testing.T) {
	cases := map[string]string{
		`"Assert"`:                              "Assert",
		`null`:                                  "",
		`[{"Member":"Deassert"}]`:               "Deassert",
		`[{"Member":"a"},"b",{"Other":1},null]`: "a, b",
		`42`:                                    "",
		`{"x":1}`:                               "",
	}
	for in, want := range cases {
		var f flexString
		if err := json.Unmarshal([]byte(in), &f); err != nil || string(f) != want {
			t.Errorf("flexString(%s) = %q, %v; want %q", in, f, err, want)
		}
	}
}

func TestLegacyFanUnitsAndName(t *testing.T) {
	pct := 40
	f := legacyFan(schemas.ThermalFan{FanName: "Fan A", Reading: &pct, ReadingUnits: schemas.PercentReadingUnits}) //nolint:staticcheck // SA1019: exercises the FanName fallback
	if f.Name != "Fan A" || f.Units != bmc.FanPercent || f.Speed.Value != 40 || f.Health != bmc.HealthUnknown {
		t.Fatalf("fan %+v", f)
	}
}

func TestStatusHealthFallsBackToHealth(t *testing.T) {
	if h := statusHealth(schemas.Status{Health: "Warning"}); h != bmc.HealthWarning {
		t.Fatalf("got %q", h)
	}
	if h := statusHealth(schemas.Status{Health: "OK", HealthRollup: "Critical"}); h != bmc.HealthCritical {
		t.Fatalf("rollup must win: %q", h)
	}
}

func TestCleanBoundsAndTrims(t *testing.T) {
	long := "  é"
	for len(long) < 3000 {
		long += "é"
	}
	got := clean(long)
	if len(got) > maxFieldLen || got[0] == ' ' {
		t.Fatalf("len %d", len(got))
	}
	if !json.Valid([]byte(`"` + got + `"`)) {
		t.Fatal("truncation produced invalid UTF-8")
	}
}
