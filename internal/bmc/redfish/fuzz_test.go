package redfish

import (
	"encoding/json"
	"testing"
	"unicode/utf8"

	"github.com/stmcginnis/gofish/schemas"

	"oob-manager/internal/bmc"
)

// FuzzLogEntryDecode: mutated log pages (flexString's string/null/[{"Member"}] shapes)
// never panic, and every event text field is valid UTF-8 within maxFieldLen bytes.
func FuzzLogEntryDecode(f *testing.F) {
	f.Add([]byte(`{"Members":[{"Id":"1","Created":"2026-10-21T10:00:00Z","Severity":"Critical","Message":"PSU lost","MessageId":"PSU0003"}]}`))
	f.Add([]byte(`{"Members":[{"Message":[{"Member":"a"},"b",{"Member":""},7],"Severity":null,"Created":["x"]}]}`))
	f.Add([]byte("{\"Members\":[{\"Id\":{\"x\":1},\"Message\":\"\\u0000\\u202e\\ud800\"}]}"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		var page logPageDoc
		if json.Unmarshal(raw, &page) != nil {
			return
		}
		for _, m := range page.Members {
			e := toEvent(m)
			for _, s := range []string{e.ID, e.Message, e.MessageID, e.EntryType, e.EntryCode, e.SensorType} {
				if len(s) > maxFieldLen || !utf8.ValidString(s) {
					t.Fatalf("unbounded or invalid field: %d bytes", len(s))
				}
			}
		}
	})
}

// FuzzSnapshotDecode: mutated legacy Thermal and subsystem Fan documents never panic,
// text stays bounded and units stay in the closed set.
func FuzzSnapshotDecode(f *testing.F) {
	f.Add([]byte(`{"Fans":[{"MemberId":"0","FanName":"Fan1","Reading":7440,"ReadingUnits":"RPM","Status":{"Health":"OK"}}],"Temperatures":[{"Name":"Inlet","ReadingCelsius":25}]}`),
		[]byte(`{"Id":"Fan1","Name":"Fan 1","SpeedPercent":{"SpeedRPM":7440,"Reading":40},"Status":{"Health":"Warning"}}`))
	f.Add([]byte(`{"Fans":[{"Reading":"fast","ReadingUnits":"Percent"}]}`), []byte(`{"SpeedPercent":{"SpeedRPM":null,"Reading":"x"}}`))
	f.Fuzz(func(t *testing.T, thermal, fanJSON []byte) {
		var th schemas.Thermal
		if json.Unmarshal(thermal, &th) == nil {
			for _, fan := range th.Fans {
				checkFan(t, legacyFan(fan))
			}
		}
		var fd fanDoc
		if json.Unmarshal(fanJSON, &fd) == nil {
			checkFan(t, subsystemFan(fd))
		}
	})
}

func checkFan(t *testing.T, fan bmc.Fan) {
	t.Helper()
	if len(fan.ID) > maxFieldLen || len(fan.Name) > maxFieldLen || !utf8.ValidString(fan.Name) {
		t.Fatalf("unbounded fan text: %d/%d bytes", len(fan.ID), len(fan.Name))
	}
	if fan.Units != bmc.FanRPM && fan.Units != bmc.FanPercent {
		t.Fatalf("units %q", fan.Units)
	}
}
