package notify

import (
	"strings"
	"testing"
	"time"
)

func TestFirmwareUpdatesEvent(t *testing.T) {
	now := time.Unix(1800000000, 0)
	one := FirmwareUpdatesEvent([]FirmwareUpdate{{ServerName: "a", Component: "BIOS", Running: "1", Latest: "2"}}, now)
	if one.Class != ClassFirmware || one.Severity != SeverityInfo || one.Title != "Firmware update available" ||
		!strings.Contains(one.Message, "a: BIOS 1 → 2") || !one.quiet() || one.Class.Mutable() {
		t.Fatalf("one %+v", one)
	}
	var many []FirmwareUpdate
	for i := range 20 {
		many = append(many, FirmwareUpdate{ServerName: "s", Component: "c", Running: "1", Latest: "2", Urgent: i == 3})
	}
	e := FirmwareUpdatesEvent(many, now)
	if e.Severity != SeverityWarning || e.Title != "20 new firmware updates (1 urgent)" || !strings.Contains(e.Message, "and 4 more") ||
		strings.Count(e.Message, "s: c") != 16 {
		t.Fatalf("many %+v", e)
	}
	if !strings.HasPrefix(strings.SplitN(e.Message, ". ", 3)[2], "s: c 1 → 2 (urgent)") {
		t.Fatalf("urgent not listed first: %q", e.Message)
	}
	var long []FirmwareUpdate
	for range 16 {
		long = append(long, FirmwareUpdate{ServerName: strings.Repeat("n", 40), Component: strings.Repeat("c", 60), Running: "1", Latest: "2"})
	}
	if l := FirmwareUpdatesEvent(long, now); len(l.Message) > 1000 || !strings.Contains(l.Message, " more") {
		t.Fatalf("byte budget: %d bytes %q", len(l.Message), l.Message[len(l.Message)-40:])
	}
	if u := FirmwareUpdatesEvent(many[3:4], now); u.Title != "Urgent firmware update available" {
		t.Fatalf("urgent %q", u.Title)
	}
	f := CatalogFailingEvent("download", 3, now)
	if f.Class != ClassFirmware || f.Severity != SeverityWarning || !strings.Contains(f.Message, "3 times") {
		t.Fatalf("failing %+v", f)
	}
	if c, err := ParseClass("firmware"); err != nil || c != ClassFirmware || ClassFirmware.Label() != "New firmware updates" {
		t.Fatal("class")
	}
}
