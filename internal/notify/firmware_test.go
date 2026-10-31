package notify

import (
	"fmt"
	"strings"
	"testing"

	"oob-manager/internal/audit"
)

func TestFirmwareEventAggregates(t *testing.T) {
	var lines []FirmwareChangeLine
	for i := range 64 {
		lines = append(lines, FirmwareChangeLine{Component: fmt.Sprintf("NIC %d", i), Field: "running", Before: "1.0", After: "2.0"})
	}
	e := FirmwareEvent(FirmwareChange{ServerID: "r1", ServerName: "R1", Components: 64, Lines: lines}, fixedNow)
	if e.Class != ClassSecurity || e.Severity != SeverityWarning || e.Count != 64 || e.Key != "security/firmware/r1" ||
		e.Title != "R1: firmware changed on 64 components" || len(e.Detail) != maxFirmwareDetail+1 ||
		e.Detail[0] != "NIC 0: running 1.0 → 2.0" || e.Detail[maxFirmwareDetail] != "and 48 more" ||
		strings.Contains(e.Title+e.Message, "NIC") || !e.quiet() {
		t.Fatalf("event %+v", e)
	}
	one := FirmwareEvent(FirmwareChange{ServerID: "r1", ServerName: "R1", Components: 1,
		Lines: []FirmwareChangeLine{{Component: "BIOS", Field: "staged", After: "2.1"}}}, fixedNow)
	if one.Title != "R1: firmware changed on 1 component" || one.Detail[0] != "BIOS: staged none → 2.1" {
		t.Fatalf("one %+v", one)
	}
}

// TestTapLeavesFirmwareRowsToTheService: the audit rows of a scan raise nothing on their
// own; the firmware service sends one message per scan.
func TestTapLeavesFirmwareRowsToTheService(t *testing.T) {
	h := newTapHarness()
	if evs := h.send("server.firmware.changed", audit.ResultOK, "", `{"field":"running","before":"1","after":"2"}`); len(evs) != 0 {
		t.Fatalf("%+v", evs)
	}
}
