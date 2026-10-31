package bmc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestParseSeverity(t *testing.T) {
	cases := map[string]Severity{
		"OK":       SeverityOK,
		"Warning":  SeverityWarning,
		"critical": SeverityCritical,
		"":         SeverityUnknown,
	}
	for in, want := range cases {
		if got := ParseSeverity(in); got != want {
			t.Errorf("ParseSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEventLogCopies(t *testing.T) {
	in := []Event{{ID: "1", Message: "Log cleared."}}
	l := NewEventLog("/redfish/v1/x", in, true)
	in[0].Message = "mutated"
	if l.Entries()[0].Message != "Log cleared." {
		t.Fatal("event log shares input")
	}
	out := l.Entries()
	out[0].Message = "mutated"
	if l.Entries()[0].Message != "Log cleared." {
		t.Fatal("event log leaks internal slice")
	}
	if l.Source() != "/redfish/v1/x" || !l.Complete() || l.Len() != 1 {
		t.Fatalf("accessors: %q %v %d", l.Source(), l.Complete(), l.Len())
	}
}

func TestInventoryWithLicenseReturnsCopy(t *testing.T) {
	fw := []FirmwareItem{{Name: "iDRAC", Version: "2.86.86.86"}}
	inv := NewInventory(InventoryParams{Model: "PowerEdge R730xd", Firmware: fw})
	fw[0].Version = "mutated"
	if inv.Firmware()[0].Version != "2.86.86.86" {
		t.Fatal("inventory shares firmware input")
	}
	lic := License{Tier: LicenseEnterprise, Source: "LicenseService"}
	inv2 := inv.WithLicense(lic)
	if inv.License().Tier != "" {
		t.Fatalf("original changed: %+v", inv.License())
	}
	if inv2.License().Tier != LicenseEnterprise || inv2.Info().Model != "PowerEdge R730xd" {
		t.Fatalf("copy wrong: %+v %+v", inv2.License(), inv2.Info())
	}
	inv3 := inv.WithFirmware([]FirmwareItem{{Name: "BIOS"}})
	if len(inv.Firmware()) != 1 || inv.Firmware()[0].Name != "iDRAC" || inv3.Firmware()[0].Name != "BIOS" {
		t.Fatal("WithFirmware must not mutate the receiver")
	}
	out := inv.Firmware()
	out[0].Name = "mutated"
	if inv.Firmware()[0].Name != "iDRAC" {
		t.Fatal("firmware slice leaks")
	}
}

func TestParseLicenseTier(t *testing.T) {
	cases := map[string]LicenseTier{
		"iDRAC9 x5 Enterprise License":   LicenseEnterprise,
		"iDRAC9 Datacenter License":      LicenseDatacenter,
		"iDRAC8 Express":                 LicenseExpress,
		"Basic Management":               LicenseBasic,
		"Secured Component Verification": LicenseUnknown,
		"":                               LicenseUnknown,
	}
	for in, want := range cases {
		if got := ParseLicenseTier(in); got != want {
			t.Errorf("ParseLicenseTier(%q) = %q, want %q", in, got, want)
		}
	}
	if !LicenseDatacenter.Above(LicenseEnterprise) || LicenseUnknown.Above(LicenseBasic) {
		t.Fatal("tier ordering wrong")
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		err  error
		want ErrorClass
	}{
		{nil, ClassNone},
		{fmt.Errorf("x: %w", ErrTimeout), ClassTimeout},
		{context.DeadlineExceeded, ClassTimeout},
		{fmt.Errorf("x: %w", ErrPinMismatch), ClassTLS},
		{fmt.Errorf("x: %w", ErrAuth), ClassAuth},
		{fmt.Errorf("x: %w", ErrBMC), ClassBMC},
		{fmt.Errorf("x: %w", ErrNotFound), ClassNotFound},
		{fmt.Errorf("x: %w", ErrUnsupported), ClassUnsupported},
		{fmt.Errorf("x: %w", ErrUnreachable), ClassUnreachable},
		{fmt.Errorf("x: %w", ErrResponseTooLarge), ClassProtocol},
		{fmt.Errorf("x: %w", ErrDecode), ClassProtocol},
		{fmt.Errorf("x: %w", ErrMethodNotAllowed), ClassProtocol},
		{fmt.Errorf("x: %w", ErrInvalidConfig), ClassConfig},
		{errors.New("other"), ClassOther},
	}
	for _, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("Classify(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

func TestSentinelMessagesAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range []error{ErrTimeout, ErrPinMismatch, ErrAuth, ErrBMC, ErrNotFound,
		ErrUnsupported, ErrUnreachable, ErrResponseTooLarge, ErrDecode, ErrMethodNotAllowed, ErrInvalidConfig} {
		if !strings.HasPrefix(e.Error(), "bmc: ") || seen[e.Error()] {
			t.Errorf("bad sentinel %q", e)
		}
		seen[e.Error()] = true
	}
}

func TestCapabilitiesResetTypesCopy(t *testing.T) {
	in := []string{"On", "ForceOff"}
	c := NewCapabilities(CapabilityParams{
		Flags:      CapabilityFlags{RedfishVersion: "1.4.0", ProbedAt: time.Unix(1, 0)},
		ResetTypes: in,
	})
	in[0] = "mutated"
	got := c.ResetTypes()
	if got[0] != "On" {
		t.Fatal("capabilities share input")
	}
	got[0] = "mutated"
	if c.ResetTypes()[0] != "On" {
		t.Fatal("capabilities leak internal slice")
	}
	if c.Flags().RedfishVersion != "1.4.0" {
		t.Fatalf("flags: %+v", c.Flags())
	}
}
