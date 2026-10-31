package dellredfish

import (
	"testing"

	"oob-manager/internal/bmc"
)

func TestParseFirmwareID(t *testing.T) {
	cases := []struct {
		in   string
		want bmc.FirmwareItem
		ok   bool
	}{
		{"/x/Installed-25227-2.86.86.86", bmc.FirmwareItem{
			ID: "Installed-25227-2.86.86.86", Name: "iDRAC", Version: "2.86.86.86", State: "Installed", ComponentID: "25227"}, true},
		{"/x/Current-102301-23.0.8__NIC.Slot.2-1-1", bmc.FirmwareItem{
			ID: "Current-102301-23.0.8__NIC.Slot.2-1-1", Name: "NIC.Slot.2-1-1", Version: "23.0.8",
			State: "Current", ComponentID: "102301", FQDD: "NIC.Slot.2-1-1"}, true},
		{"/x/Installed-999-1.2-beta", bmc.FirmwareItem{
			ID: "Installed-999-1.2-beta", Name: "Component 999", Version: "1.2-beta", State: "Installed", ComponentID: "999"}, true},
		{"/x/Bogus-1-2", bmc.FirmwareItem{}, false},
		{"/x/Installed-abc-1.0", bmc.FirmwareItem{}, false},
		{"/x/Installed-1", bmc.FirmwareItem{}, false},
		{"/x/Installed-1-", bmc.FirmwareItem{}, false},
		{"", bmc.FirmwareItem{}, false},
	}
	for _, c := range cases {
		got, ok := parseFirmwareID(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("parseFirmwareID(%q) = %+v, %v; want %+v, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestParseFirmwareMembersFallsBackOnUnknownFormat(t *testing.T) {
	if _, ok := parseFirmwareMembers([]string{"/x/Installed-159-2.19.0", "/x/SomethingElse"}); ok {
		t.Fatal("an unparseable member must make the parser defer to per-member GETs")
	}
	items, ok := parseFirmwareMembers([]string{"/x/Installed-159-2.19.0"})
	if !ok || len(items) != 1 || items[0].Name != "BIOS" {
		t.Fatalf("items %+v ok %v", items, ok)
	}
}

// TestParseFirmwareIDCleansTheFQDD (review S-L1): a format character inside a BMC-supplied
// FQDD is removed, so two near-identical FQDDs are one component.
func TestParseFirmwareIDCleansTheFQDD(t *testing.T) {
	a, okA := parseFirmwareID("/x/Current-102301-23.0.8__NIC.Slot.2\u200b-1-1")
	b, okB := parseFirmwareID("/x/Installed-102301-23.0.8__NIC.Slot.2-1-1")
	if !okA || !okB || a.FQDD != "NIC.Slot.2-1-1" || a.FQDD != b.FQDD {
		t.Fatalf("%+v %+v", a, b)
	}
}
