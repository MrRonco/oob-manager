package firmware

import (
	"strings"

	"oob-manager/internal/bmc"
)

// nameKeyword maps a word in a component name to its kind. Order matters: the first
// match wins, so a drive named after where it sits ("Disk 0 in Backplane 1 of RAID
// Controller 1") is a drive. Vendor
// keywords (Dell "iDRAC", "PERC", ...) live in the vendor driver.
type nameKeyword struct {
	word string
	kind bmc.FirmwareKind
}

func nameKeywords() []nameKeyword {
	return []nameKeyword{
		{"bios", bmc.FirmwareBIOS},
		{"remote access controller", bmc.FirmwareBMC},
		{"bmc", bmc.FirmwareBMC},
		{"cpld", bmc.FirmwareCPLD},
		{"disk", bmc.FirmwareDrive},
		{"ssd", bmc.FirmwareDrive},
		{"hdd", bmc.FirmwareDrive},
		{"nvme", bmc.FirmwareDrive},
		{"backplane", bmc.FirmwareEnclosure},
		{"enclosure", bmc.FirmwareEnclosure},
		{"power supply", bmc.FirmwarePSU},
		{"psu", bmc.FirmwarePSU},
		{"ethernet", bmc.FirmwareNIC},
		{"network", bmc.FirmwareNIC},
		{"raid", bmc.FirmwareStorage},
		{"storage controller", bmc.FirmwareStorage},
	}
}

// KindFromName classifies a component by keywords in its name ("" when none matches).
// Words match on letter boundaries, so "psu" does not match inside "capsule".
func KindFromName(name string) bmc.FirmwareKind {
	n := strings.ToLower(name)
	for _, k := range nameKeywords() {
		if containsWord(n, k.word) {
			return k.kind
		}
	}
	return ""
}

func containsWord(s, w string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(w)
		if (start == 0 || !isLetter(s[start-1])) && (end == len(s) || !isLetter(s[end])) {
			return true
		}
		i = start + 1
	}
}

func isLetter(b byte) bool { return b >= 'a' && b <= 'z' }

// KindFromRelated classifies a generic Redfish SoftwareInventory by the resource its
// RelatedItem links to ("" when the link says nothing).
func KindFromRelated(uri string) bmc.FirmwareKind {
	segs := strings.Split(strings.Trim(strings.ReplaceAll(uri, "#", ""), "/"), "/")
	has := func(s string) bool {
		for _, x := range segs {
			if strings.EqualFold(x, s) {
				return true
			}
		}
		return false
	}
	switch {
	case len(segs) < 4:
		return ""
	case has("Drives"):
		return bmc.FirmwareDrive
	case has("PowerSupplies"):
		return bmc.FirmwarePSU
	case has("EthernetInterfaces"), has("NetworkAdapters"):
		return bmc.FirmwareNIC
	case has("Storage"), has("StorageControllers"):
		return bmc.FirmwareStorage
	case has("Processors"):
		return bmc.FirmwareOther
	case segs[2] == "Managers":
		return bmc.FirmwareBMC
	case segs[2] == "Systems" && (len(segs) == 4 || has("Bios")):
		return bmc.FirmwareBIOS
	case segs[2] == "Chassis" && len(segs) == 4:
		return bmc.FirmwareEnclosure
	default:
		return ""
	}
}
