package dellredfish

import (
	"path"
	"strconv"
	"strings"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/textclean"
)

// maxFQDDLen caps an FQDD taken from a member ID (the store holds 128 bytes).
const maxFQDDLen = 128

// knownComponent names Dell component IDs whose meaning is confirmed by the FQDDs in the
// iDRAC9 fixture. A switch, not a map, so there is no package-level mutable state.
func knownComponent(id string) string {
	switch id {
	case "159":
		return "BIOS"
	case "25227":
		return "iDRAC"
	case "28897":
		return "Lifecycle Controller"
	case "27763":
		return "CPLD"
	case "18981":
		return "OS Driver Pack"
	case "25806":
		return "Diagnostics"
	case "101734":
		return "OS Collector"
	default:
		return ""
	}
}

func isFirmwareState(s string) bool {
	switch s {
	case "Installed", "Current", "Previous", "Available":
		return true
	default:
		return false
	}
}

// parseFirmwareMembers derives firmware items from Dell FirmwareInventory member IDs
// (<State>-<ComponentID>-<Version>[__<FQDD>]) so the inventory needs one GET instead of
// one per component. Any member in an unknown format defers to per-member GETs.
func parseFirmwareMembers(members []string) ([]bmc.FirmwareItem, bool) {
	out := make([]bmc.FirmwareItem, 0, len(members))
	for _, m := range members {
		item, ok := parseFirmwareID(m)
		if !ok {
			return nil, false
		}
		out = append(out, item)
	}
	return out, true
}

func parseFirmwareID(uri string) (bmc.FirmwareItem, bool) {
	id := path.Base(uri)
	head, rawFQDD, _ := strings.Cut(id, "__")
	fqdd := textclean.Clean(rawFQDD, maxFQDDLen) // BMC text: format characters out (review S-L1)
	parts := strings.SplitN(head, "-", 3)
	if len(parts) != 3 || !isFirmwareState(parts[0]) || parts[2] == "" {
		return bmc.FirmwareItem{}, false
	}
	if _, err := strconv.ParseUint(parts[1], 10, 32); err != nil {
		return bmc.FirmwareItem{}, false
	}
	return bmc.FirmwareItem{
		ID:          id,
		Name:        componentName(parts[1], fqdd),
		Version:     parts[2],
		State:       parts[0],
		ComponentID: parts[1],
		FQDD:        fqdd,
	}, true
}

func componentName(comp, fqdd string) string {
	if n := knownComponent(comp); n != "" {
		return n
	}
	if fqdd != "" {
		return fqdd
	}
	return "Component " + comp
}
