package bmcsec

import (
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		cmp  int
		ok   bool
	}{
		{"2.86.86.86", "7.00.00.182", -1, true},
		{"7.10.30.00", "7.00.00.182", 1, true},
		{"7.10", "7.10.0", 0, true},
		{"10.0", "9.9", 1, true},
		{"2.86.86.86", "2.86.86.86", 0, true},
		{"1.2a", "1.2", 0, false},
		{"", "1", 0, false},
		{"1..2", "1", 0, false},
	}
	for _, c := range cases {
		if cmp, ok := CompareVersions(c.a, c.b); cmp != c.cmp || ok != c.ok {
			t.Errorf("CompareVersions(%q, %q) = %d, %v", c.a, c.b, cmp, ok)
		}
	}
}

func TestBMCFirmware(t *testing.T) {
	p := good()
	in := goodInputs()
	f := expect(t, p, in, "fw.bmc", Pass, "Version 7.10.30.00 (minimum known good 7.00.00.182).")
	if f.Subject != "7.10.30.00" || f.Evidence[1] != "The BMC does not report this version's release date." {
		t.Fatalf("finding %+v", f)
	}
	p.Redfish.Firmware.BMCVersion = "2.86.86.86"
	p.Redfish.Firmware.BMCReleased = bmc.FactOf(now.AddDate(-3, -2, 0), "x")
	f = expect(t, p, in, "fw.bmc", Warn, "older than the minimum known good 7.00.00.182 (security.min_firmware.idrac9).")
	if f.Evidence[1] != "Released 2023-08-21, 3 years ago." {
		t.Fatalf("evidence %v", f.Evidence)
	}
	p.Redfish.Firmware.BMCReleased = bmc.FactOf(now.AddDate(0, -3, 0), "x")
	expect(t, p, in, "fw.bmc", Warn, "less than a year ago")
	in.MinFirmware = ""
	expect(t, p, in, "fw.bmc", Info, "No minimum known good version is configured (security.min_firmware.idrac9).")
	in.MinFirmware = "v7"
	expect(t, p, in, "fw.bmc", Unknown, "cannot be compared")
	p.Redfish.Firmware = bmc.FirmwareFacts{Read: bmc.Section{State: bmc.ReadForbidden}}
	expect(t, p, in, "fw.bmc", CantRead, "")
}

func TestBIOSVersion(t *testing.T) {
	expect(t, good(), goodInputs(), "fw.bios", Info, "BIOS 2.20.0 (cs).")
	p := good()
	p.Redfish.Firmware.BIOSVersion = bmc.Fact[string]{}
	expect(t, p, goodInputs(), "fw.bios", Unknown, "")
}

func licensesOf(p bmc.Posture, list ...bmc.LicenseEntry) bmc.Posture {
	p.Redfish.Licenses = bmc.LicenseFacts{Read: ok()}.WithLicenses(list)
	return p
}

func TestLicense(t *testing.T) {
	prod := bmc.LicenseEntry{Description: "iDRAC9 Enterprise License", Type: "Production"}
	expiredTrial := bmc.LicenseEntry{Description: "iDRAC9 Enterprise Evaluation License", Type: "Trial", Expires: now.AddDate(-7, 0, 0)}
	f := expect(t, licensesOf(good(), expiredTrial, prod), goodInputs(), "fw.license", Info, "Expired trial still installed")
	if len(f.Evidence) != 2 || f.Evidence[1] != "iDRAC9 Enterprise License (Production, no expiry)." {
		t.Fatalf("evidence %v", f.Evidence)
	}
	soon := bmc.LicenseEntry{Description: "Trial", Type: "Evaluation", Expires: now.Add(10 * 24 * time.Hour)}
	f = expect(t, licensesOf(good(), soon), goodInputs(), "fw.license", Warn, "expires on 2026-10-31, in 10 days.")
	if f.Subject != `["Trial","Evaluation","2026-10-31"]` {
		t.Fatalf("subject %q", f.Subject)
	}
	later := bmc.LicenseEntry{Description: "Datacenter Trial", Type: "Trial", Expires: now.Add(90 * 24 * time.Hour)}
	expect(t, licensesOf(good(), later), goodInputs(), "fw.license", Info, "Trial license Datacenter Trial until 2027-01-19.")
	term := bmc.LicenseEntry{Description: "Term", Type: "Production", Expires: now.Add(-24 * time.Hour)}
	expect(t, licensesOf(good(), term), goodInputs(), "fw.license", Warn, "Expired: Term")
	yearly := bmc.LicenseEntry{Description: "Term", Type: "Production", Expires: now.Add(400 * 24 * time.Hour)}
	expect(t, licensesOf(good(), yearly), goodInputs(), "fw.license", Pass, "Term until 2027-11-25.")
	expect(t, licensesOf(good()), goodInputs(), "fw.license", Info, "No license is installed.")
	p := good()
	p.Redfish.Licenses = bmc.LicenseFacts{Read: bmc.Section{State: bmc.ReadAbsent}}
	expect(t, p, goodInputs(), "fw.license", Unknown, "does not report its licenses")
	p.Redfish.Licenses = bmc.LicenseFacts{Read: bmc.Section{State: bmc.ReadForbidden}}
	expect(t, p, goodInputs(), "fw.license", CantRead, "")
}

func TestNetworkChecks(t *testing.T) {
	p := good()
	expect(t, p, goodInputs(), "net.ip_filter", Pass, "Only 192.0.2.0/28 may connect (attr).")
	p.Redfish.Network.IPFilterRange = bmc.Fact[string]{}
	expect(t, p, goodInputs(), "net.ip_filter", Pass, "The IP filter is on")
	p.Redfish.Network.IPFilter = on(false, "Dell attribute IPBlocking.1.RangeEnable")
	expect(t, p, goodInputs(), "net.ip_filter", Warn, "Any address can reach the BMC")
	p.Redfish.Network.IPFilter = bmc.Fact[bool]{}
	p.Redfish.Attributes = bmc.Section{State: bmc.ReadForbidden}
	expect(t, p, goodInputs(), "net.ip_filter", CantRead, "")
	p.Redfish.Attributes = bmc.Section{}
	expect(t, p, goodInputs(), "net.ip_filter", Unknown, "a firewall in front of it")

	p = good()
	p.Redfish.Network.DHCP, p.Redfish.Network.IPv6 = on(true, "attr"), on(true, "attr")
	expect(t, p, goodInputs(), "net.dhcp", Info, "from DHCP")
	expect(t, p, goodInputs(), "net.ipv6", Info, "IPv6 is on")
	p.Redfish.Network.IPv6 = bmc.Fact[bool]{}
	p.Redfish.Attributes = bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassProtocol}
	expect(t, p, goodInputs(), "net.ipv6", Unknown, "unexpected answer")
}

// TestLicenseExpiryArithmetic: a licence that expired less than a day ago is expired
// (not "expires in 0 days"), and the warning threshold is strict at 30 whole days.
func TestLicenseExpiryArithmetic(t *testing.T) {
	today := bmc.LicenseEntry{Description: "Term", Type: "Production", Expires: now.Add(-10 * time.Hour)}
	expect(t, licensesOf(good(), today), goodInputs(), "fw.license", Warn, "Expired: Term (2026-10-21).")
	trial := bmc.LicenseEntry{Description: "Eval", Type: "Trial", Expires: now.Add(-10 * time.Hour)}
	expect(t, licensesOf(good(), trial), goodInputs(), "fw.license", Info, "Expired trial still installed: Eval (expired 2026-10-21).")
	edge := bmc.LicenseEntry{Description: "Term", Type: "Production", Expires: now.Add(30 * 24 * time.Hour)}
	expect(t, licensesOf(good(), edge), goodInputs(), "fw.license", Pass, "Term until 2026-11-20.")
	edge.Expires = now.Add(30*24*time.Hour - time.Second)
	expect(t, licensesOf(good(), edge), goodInputs(), "fw.license", Warn, "Term expires on 2026-11-20, in 29 days.")
}
