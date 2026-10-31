package bmcsec

import (
	"fmt"
	"strings"
	"time"

	"oob-manager/internal/bmc"
)

// licenseWarnDays: a license closer than this to its expiry is a warning.
const licenseWarnDays = 30

func firmwareEntries() []entry {
	return []entry{
		{check: Check{ID: "fw.bmc", Group: GroupFirmware, Title: "BMC firmware",
			Why: "BMC firmware updates include security fixes, and BMCs are rarely updated: many run code that is years old.",
			Fix: "Update to the vendor's current firmware. Set security.min_firmware for this BMC kind in config.yaml to the oldest version " +
				"you accept; oob-manager compares against it and never looks anything up online.",
			Dell: "Dell publishes iDRAC firmware per server model; Dell System Update or the iDRAC's own update page installs it."},
			eval: bmcFirmware},
		{check: Check{ID: "fw.bios", Group: GroupFirmware, Title: "BIOS version",
			Why: "BIOS updates fix vulnerabilities in the host firmware (UEFI, CPU microcode) that the operating system cannot.",
			Fix: "Keep the BIOS at the vendor's current version."},
			eval: biosVersion},
		{check: Check{ID: "fw.license", Group: GroupFirmware, Title: "License",
			Why: "Features a trial license enables (often the graphical console) stop when it ends, and an expired trial left installed " +
				"makes the license page misleading.",
			Fix:  "Install a permanent license before a trial ends, and remove expired trials.",
			Dell: "The license page of the web interface, or racadm license view."},
			eval: licenses},
	}
}

func bmcFirmware(c evalCtx) outcome {
	f := c.p.Redfish.Firmware
	if !f.Read.OK() || f.BMCVersion == "" {
		return unread(f.Read, "the BMC firmware version")
	}
	v := f.BMCVersion
	ev := releaseLine(f.BMCReleased, c.now)
	key := "security.min_firmware." + c.in.Kind
	if c.in.MinFirmware == "" {
		return out(Info, v, append([]string{"Version " + v + ". No minimum known good version is configured (" + key + ")."}, ev...)...)
	}
	cmp, ok := CompareVersions(v, c.in.MinFirmware)
	switch {
	case !ok:
		return out(Unknown, v, append([]string{"Version " + v + " cannot be compared with " + c.in.MinFirmware + " (" + key + ")."}, ev...)...)
	case cmp < 0:
		return out(Warn, v, append([]string{"Version " + v + " is older than the minimum known good " + c.in.MinFirmware + " (" + key + ")."}, ev...)...)
	default:
		return out(Pass, v, append([]string{"Version " + v + " (minimum known good " + c.in.MinFirmware + ")."}, ev...)...)
	}
}

func releaseLine(f bmc.Fact[time.Time], now time.Time) []string {
	if !f.Known {
		return []string{"The BMC does not report this version's release date."}
	}
	years := int(now.Sub(f.Value).Hours() / (24 * 365))
	age := "less than a year ago"
	if years >= 1 {
		age = plural(years, "year", "years") + " ago"
	}
	return []string{"Released " + f.Value.Format(dateFmt) + ", " + age + "."}
}

func biosVersion(c evalCtx) outcome {
	b := c.p.Redfish.Firmware.BIOSVersion
	if !b.Known {
		return out(Unknown, "", "The BIOS version was not read.")
	}
	return out(Info, b.Value, "BIOS "+b.Value+from(b.Source)+".")
}

func trial(e bmc.LicenseEntry) bool {
	t, d := strings.ToLower(e.Type), strings.ToLower(e.Description)
	return strings.Contains(t, "trial") || strings.Contains(t, "evaluation") || strings.Contains(d, "evaluation") ||
		strings.Contains(d, "trial")
}

// licenseNote judges one license: its result, its evidence line and its subject.
func licenseNote(e bmc.LicenseEntry, now time.Time) (Result, string, string) {
	name := orNone(e.Description)
	subject := jsonList([]string{e.Description, e.Type, e.Expires.Format(dateFmt)}) // injective: text may hold any separator
	if e.Expires.IsZero() {
		return Pass, name + " (" + orNone(e.Type) + ", no expiry).", subject
	}
	expired := e.Expires.Before(now) // not the day count: an expiry hours ago is 0 days, and expired
	days := int(e.Expires.Sub(now) / (24 * time.Hour))
	switch {
	case expired && trial(e):
		return Info, "Expired trial still installed: " + name + " (expired " + e.Expires.Format(dateFmt) + ").", subject
	case expired:
		return Warn, "Expired: " + name + " (" + e.Expires.Format(dateFmt) + ").", subject
	case days < licenseWarnDays:
		return Warn, fmt.Sprintf("%s expires on %s, in %s.", name, e.Expires.Format(dateFmt), plural(days, "day", "days")), subject
	case trial(e):
		return Info, "Trial license " + name + " until " + e.Expires.Format(dateFmt) + ".", subject
	default:
		return Pass, name + " until " + e.Expires.Format(dateFmt) + ".", subject
	}
}

func licenses(c evalCtx) outcome {
	l := c.p.Redfish.Licenses
	if l.Read.State == bmc.ReadAbsent {
		return out(Unknown, "", "This BMC does not report its licenses over Redfish.")
	}
	if !l.Read.OK() {
		return unread(l.Read, "the licenses")
	}
	list := l.Licenses()
	if len(list) == 0 {
		return out(Info, "", "No license is installed.")
	}
	worst, subject := Pass, ""
	var ev []string
	for _, e := range list {
		r, line, s := licenseNote(e, c.now)
		ev = append(ev, line)
		if r.Rank() > worst.Rank() {
			worst, subject = r, s
		}
	}
	return out(worst, subject, ev...)
}
