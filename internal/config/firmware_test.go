package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFirmwareDefaults(t *testing.T) {
	f := mustParse(t, validYAML()).Firmware
	if f.StaleAge() != 0 || len(f.Minimum) != 0 || len(f.Names) != 0 {
		t.Fatalf("firmware defaults = %+v", f)
	}
}

func TestFirmwareParse(t *testing.T) {
	f := mustParse(t, validYAML()+`firmware:
  stale_after: 3y
  names: { "101068": "Backplane expander" }
  minimum:
    - { bmc_kind: idrac9, kind: bios, model: "PowerEdge R440", version: "2.20.0" }
    - { component_id: "105897", version: "23.31.1", note: "BCM5720 fix" }
    - { fqdd: "NIC.Slot.*", version: "23.0.8" }
`).Firmware
	if f.StaleAge() != 3*365*24*time.Hour || f.Names["101068"] != "Backplane expander" || len(f.Minimum) != 3 {
		t.Fatalf("firmware = %+v", f)
	}
	if r := f.Minimum[0]; r.BMCKind != "idrac9" || r.Kind != "bios" || r.Model != "PowerEdge R440" || r.Version != "2.20.0" {
		t.Fatalf("rule %+v", r)
	}
	for in, want := range map[string]time.Duration{"0": 0, "": 0, "1y": 365 * 24 * time.Hour, "400d": 400 * 24 * time.Hour,
		"26280h": 26280 * time.Hour} {
		if got := mustParse(t, validYAML()+"firmware: { stale_after: \""+in+"\" }\n").Firmware.StaleAge(); got != want {
			t.Errorf("stale_after %q = %v, want %v", in, got, want)
		}
	}
	if got := mustParse(t, validYAML()+"firmware: { stale_after: 0 }\n").Firmware.StaleAge(); got != 0 {
		t.Errorf("a bare 0 = %v", got)
	}
}

func TestFirmwareRejectsBadValues(t *testing.T) {
	cases := map[string]string{
		"firmware: { stale_after: 3 years }\n":                                               "firmware.stale_after",
		"firmware: { stale_after: 51y }\n":                                                   "firmware.stale_after",
		"firmware: { stale_after: -1y }\n":                                                   "firmware.stale_after",
		"firmware: { minimum: [ { kind: bmc, version: \"2.86\" } ] }\n":                      "security.min_firmware",
		"firmware: { minimum: [ { component_id: \"25227\" } ] }\n":                           "version",
		"firmware: { minimum: [ { version: \"1.0\" } ] }\n":                                  "at least one of",
		"firmware: { minimum: [ { kind: cpu, version: \"1.0\" } ] }\n":                       "kind",
		"firmware: { minimum: [ { bmc_kind: idrac7, version: \"1.0\" } ] }\n":                "bmc_kind",
		"firmware: { minimum: [ { fqdd: \"NIC.*.1\", version: \"1.0\" } ] }\n":               "fqdd",
		"firmware: { minimum: [ { component_id: \"a b\", version: \"1.0\" } ] }\n":           "component_id",
		"firmware: { minimum: [ { kind: bios, version: \"1..0\" } ] }\n":                     "version",
		"firmware: { minimum: [ { kind: bios, version: \"1.0\", note: \"a\\u202eb\" } ] }\n": "note",
		"firmware: { names: { \"a b\": \"x\" } }\n":                                          "firmware.names",
		"firmware: { names: { \"1\": \"\" } }\n":                                             "firmware.names",
		"firmware: { names: { \"1\": \"x\\ny\" } }\n":                                        "firmware.names",
	}
	for extra, want := range cases {
		_, err := Parse([]byte(validYAML() + extra))
		var ve *ValidationError
		if !errors.As(err, &ve) || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: got %v, want a problem mentioning %q", extra, err, want)
		}
	}
	var b strings.Builder
	b.WriteString("firmware:\n  minimum:\n")
	for range MaxFirmwareRules + 1 {
		b.WriteString("    - { kind: bios, version: \"1.0\" }\n")
	}
	if _, err := Parse([]byte(validYAML() + b.String())); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("too many rules: %v", err)
	}
}

func TestFirmwareRejectsUnknownKeys(t *testing.T) {
	for _, extra := range []string{"firmware: { every: 24h }\n", "firmware: { minimum: [ { kind: bios, version: \"1\", severity: high } ] }\n"} {
		if _, err := Parse([]byte(validYAML() + extra)); err == nil {
			t.Errorf("%q accepted", extra)
		}
	}
}

// TestFirmwareRefusesRulesForTheBMCRow (review C-L2): a rule that can only match the
// BMC's own row would never apply (that row is judged by security.min_firmware), so it
// fails the load instead of silently doing nothing.
func TestFirmwareRefusesRulesForTheBMCRow(t *testing.T) {
	for _, rule := range []string{`{ component_id: "25227", version: "2.86" }`, `{ fqdd: "iDRAC.Embedded.1-1", version: "7.0" }`,
		`{ fqdd: "iDRAC.*", version: "7.0" }`} {
		_, err := Parse([]byte(validYAML() + "firmware: { minimum: [ " + rule + " ] }\n"))
		if err == nil || !strings.Contains(err.Error(), "security.min_firmware") {
			t.Errorf("%s: %v", rule, err)
		}
	}
	if _, err := Parse([]byte(validYAML() + "firmware: { minimum: [ { fqdd: \"NIC.*\", version: \"1\" } ] }\n")); err != nil {
		t.Fatal(err)
	}
}
