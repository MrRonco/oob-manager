package redfishmock

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

const selPath = "/redfish/v1/Managers/iDRAC.Embedded.1/Logs/Sel"

// created returns every member's Created time of a log collection served by s.
func created(t *testing.T, s *Server, path string) []time.Time {
	t.Helper()
	code, body := get(t, s, http.MethodGet, path, true)
	if code != http.StatusOK {
		t.Fatalf("%s: %d", path, code)
	}
	var doc struct {
		Members []struct {
			Created string
		}
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	var out []time.Time
	for _, m := range doc.Members {
		at, err := time.Parse(time.RFC3339, m.Created)
		if err != nil {
			t.Fatalf("Created %q: %v", m.Created, err)
		}
		out = append(out, at)
	}
	if len(out) < 2 {
		t.Fatalf("%s: %d entries", path, len(out))
	}
	return out
}

func TestWithLogTimeShiftMovesEveryEntryAndKeepsSpacing(t *testing.T) {
	dir := FixtureDir(t, "idrac8-r730xd")
	plain := created(t, New(t, dir), selPath)
	shift := 400*24*time.Hour + 90*time.Second
	moved := created(t, New(t, dir, WithLogTimeShift(shift)), selPath)
	if len(moved) != len(plain) {
		t.Fatalf("%d entries, want %d", len(moved), len(plain))
	}
	for i := range plain {
		if got := moved[i].Sub(plain[i]); got != shift {
			t.Errorf("entry %d moved by %v, want %v", i, got, shift)
		}
		_, off := moved[i].Zone()
		if _, want := plain[i].Zone(); off != want {
			t.Errorf("entry %d: offset %d, want %d (the BMC's own zone)", i, off, want)
		}
	}
	// Documents without log times are served byte for byte.
	_, a := get(t, New(t, dir), http.MethodGet, "/redfish/v1/Systems/System.Embedded.1", true)
	_, b := get(t, New(t, dir, WithLogTimeShift(shift)), http.MethodGet, "/redfish/v1/Systems/System.Embedded.1", true)
	if string(a) != string(b) {
		t.Error("a document without Created changed")
	}
}

func TestLatestCreated(t *testing.T) {
	dirs := []string{FixtureDir(t, "idrac8-r730xd"), FixtureDir(t, "idrac9-r240")}
	latest, err := LatestCreated(dirs...)
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range created(t, New(t, dirs[0]), selPath) {
		if at.After(latest) {
			t.Errorf("%v is after the latest %v", at, latest)
		}
	}
	if latest.IsZero() || latest.After(time.Now()) {
		t.Errorf("latest = %v", latest)
	}
	if _, err := LatestCreated(t.TempDir()); err == nil {
		t.Error("no error for a directory without log entries")
	}
}

func TestWithLogTextReplaceOnlyTouchesLogEntries(t *testing.T) {
	dir := FixtureDir(t, "idrac8-r730xd")
	const lcPath = "/redfish/v1/Managers/iDRAC.Embedded.1/Logs/Lclog"
	_, plain := get(t, New(t, dir), http.MethodGet, lcPath, true)
	if !strings.Contains(string(plain), "from 192.0.2.10 ") {
		t.Fatal("fixture no longer names 192.0.2.10 in a log message")
	}
	s := New(t, dir, WithLogTextReplace("192.0.2.10", "192.0.2.99"))
	_, body := get(t, s, http.MethodGet, lcPath, true)
	if strings.Contains(string(body), "192.0.2.10") || !strings.Contains(string(body), "from 192.0.2.99 ") {
		t.Errorf("log entries not rewritten: %.300s", body)
	}
	// The address outside log entries (the BMC's own) is served unchanged.
	sys := "/redfish/v1/Managers/iDRAC.Embedded.1/Attributes"
	_, a := get(t, New(t, dir), http.MethodGet, sys, true)
	_, b := get(t, s, http.MethodGet, sys, true)
	if !strings.Contains(string(a), "192.0.2.10") || string(a) != string(b) {
		t.Error("a document without log entries changed")
	}
}
