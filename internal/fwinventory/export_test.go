package fwinventory

import (
	"bytes"
	"encoding/csv"
	"errors"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/csvx"
	"oob-manager/internal/firmware"
	"oob-manager/internal/firmware/catalog"
)

func TestWriteCSV(t *testing.T) {
	rows := []firmware.Row{{
		Server: firmware.ServerInfo{ID: "r730xd", Name: "=HYPERLINK(\"x\")", BMCKind: "idrac8"},
		Component: firmware.Component{Key: firmware.Key{ComponentID: "159"}, Kind: bmc.FirmwareBIOS, Running: "2.19.0", Previous: "2.18.1",
			Stored: "2.20.0", ReleaseDate: time.Date(2025, 9, 27, 0, 0, 0, 0, time.UTC), Updateable: true},
		Verdict:  firmware.Verdict{Flags: []firmware.Flag{firmware.FlagBelowMinimum}, Minimum: "2.20.0"},
		Display:  "-BIOS",
		LastSeen: t0,
		Update: firmware.Update{State: firmware.UpdateUrgent, Latest: catalog.Release{Version: "2.25.2",
			Date: time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC), Criticality: catalog.CriticalityUrgent}},
	}, {
		Server:    firmware.ServerInfo{ID: "r240", Name: "R240", BMCKind: "idrac9"},
		Component: firmware.Component{Key: firmware.Key{ComponentID: "1"}, Kind: bmc.FirmwareNIC, Running: "1.0"},
		Display:   "NIC",
	}}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, rows, "26.10.22"); err != nil {
		t.Fatal(err)
	}
	recs, err := csv.NewReader(&buf).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(recs[0], CSVColumns()) || len(recs) != 3 || recs[0][10] != "stored" || recs[0][17] != "latest_version" {
		t.Fatalf("records %q", recs)
	}
	r := recs[1]
	want := []string{"r730xd", "'=HYPERLINK(\"x\")", "idrac8", "bios", "'-BIOS", "159", "", "2.19.0", "2.18.1", "", "2.20.0", "2025-09-27",
		"true", "below_minimum", "2.20.0", "", "2026-10-23T12:00:00Z", "2.25.2", "2026-09-24", "urgent", "urgent", "26.10.22"}
	if !slices.Equal(r, want) {
		t.Fatalf("row\n got %q\nwant %q", r, want)
	}
	if tail := recs[2][17:]; !slices.Equal(tail, []string{"", "", "", "", ""}) {
		t.Fatalf("a row without a catalog verdict names the catalog: %q", tail)
	}
	if got := CSVName(firmware.Filter{}, t0); got != "firmware_fleet_20261023T1200Z.csv" {
		t.Fatalf("name %q", got)
	}
	if got := CSVName(firmware.Filter{ServerID: "r240"}, t0); got != "firmware_r240_20261023T1200Z.csv" {
		t.Fatalf("name %q", got)
	}
}

func TestParseFilter(t *testing.T) {
	f, err := ParseFilter(url.Values{"server": {"r730xd"}, "kind": {"bios"}, "flagged": {"1"}, "q": {"  2.19 "}, "other": {"x"}})
	if err != nil || f != (firmware.Filter{ServerID: "r730xd", Kind: bmc.FirmwareBIOS, Flagged: true, Text: "2.19"}) {
		t.Fatalf("filter %+v %v", f, err)
	}
	if got := Query(f).Encode(); got != "flagged=1&kind=bios&q=2.19&server=r730xd" {
		t.Fatalf("query %q", got)
	}
	if f, err := ParseFilter(url.Values{}); err != nil || f.Active() || len(Query(f)) != 0 {
		t.Fatalf("empty %+v %v", f, err)
	}
	for _, bad := range []url.Values{
		{"server": {"../x"}}, {"server": {"UPPER"}}, {"kind": {"cpu"}}, {"flagged": {"yes"}},
		{"q": {strings.Repeat("a", 65)}}, {"q": {"a\u202eb"}}, {"q": {"a\nb"}},
	} {
		if _, err := ParseFilter(bad); !errors.Is(err, ErrBadFilter) {
			t.Errorf("%v accepted: %v", bad, err)
		}
	}
}

func TestWriteCSVReportsErrors(t *testing.T) {
	if err := WriteCSV(failing{}, []firmware.Row{{}}, ""); err == nil {
		t.Fatal("a broken writer must surface")
	}
}

type failing struct{}

func (failing) Write([]byte) (int, error) { return 0, errors.New("gone") }

// TestParseFilterCountsRunes (review C-L6): the 64-character limit counts characters, as
// the form's maxlength does, not bytes.
func TestParseFilterCountsRunes(t *testing.T) {
	if f, err := ParseFilter(url.Values{"q": {strings.Repeat("é", 64)}}); err != nil || f.Text == "" {
		t.Fatalf("64 two-byte characters: %v", err)
	}
	if _, err := ParseFilter(url.Values{"q": {strings.Repeat("é", 65)}}); !errors.Is(err, ErrBadFilter) {
		t.Fatalf("65 characters: %v", err)
	}
}

// TestWriteCSVByteCap (review S-L7): an export larger than MaxCSVBytes fails with
// csvx.ErrTooLarge instead of streaming tens of megabytes.
func TestWriteCSVByteCap(t *testing.T) {
	big := strings.Repeat("x", 500)
	rows := make([]firmware.Row, 0, 2000)
	for range 3000 {
		rows = append(rows, firmware.Row{Display: big, Component: firmware.Component{Running: big, Previous: big, Identity: big}})
	}
	var buf bytes.Buffer
	if err := WriteCSV(&buf, rows, ""); !errors.Is(err, csvx.ErrTooLarge) || buf.Len() > MaxCSVBytes {
		t.Fatalf("err %v, %d bytes", err, buf.Len())
	}
}
