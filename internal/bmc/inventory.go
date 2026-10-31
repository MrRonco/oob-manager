package bmc

import (
	"slices"
	"strings"
	"time"
)

// FirmwareItem is one installed/current/previous firmware component.
type FirmwareItem struct {
	ID          string // Redfish member ID
	Name        string
	Version     string
	State       string // Dell: "Installed", "Current", "Previous", "Available"; empty if unknown
	ComponentID string // Dell component ID, e.g. "25227" (iDRAC)
	FQDD        string // Dell FQDD when reported, e.g. "iDRAC.Embedded.1-1"
	// The fields below are set by the firmware scan (FirmwareScanner). Detailed reports
	// that the member document was read (ReleaseDate, Updateable and Identity come from
	// it); Named that Name is the document's own (otherwise it is the driver's fallback).
	Kind        FirmwareKind // "" when the driver could not classify it
	ReleaseDate time.Time    // zero when the BMC does not report one
	Updateable  bool
	Identity    string // catalog key, e.g. Dell "DCIM:firmware:14E4:165F:1028:088F"
	Detailed    bool
	Named       bool
}

// LicenseTier is a BMC licence level.
type LicenseTier string

// Licence tiers, lowest to highest by tierRank.
const (
	LicenseUnknown    LicenseTier = "unknown"
	LicenseBasic      LicenseTier = "Basic"
	LicenseExpress    LicenseTier = "Express"
	LicenseEnterprise LicenseTier = "Enterprise"
	LicenseDatacenter LicenseTier = "Datacenter"
)

// ParseLicenseTier extracts a tier from a licence description such as
// "iDRAC9 x5 Enterprise License". Anything unrecognised is LicenseUnknown.
func ParseLicenseTier(desc string) LicenseTier {
	d := strings.ToLower(desc)
	for _, t := range []LicenseTier{LicenseDatacenter, LicenseEnterprise, LicenseExpress, LicenseBasic} {
		if strings.Contains(d, strings.ToLower(string(t))) {
			return t
		}
	}
	return LicenseUnknown
}

func tierRank(t LicenseTier) int {
	switch t {
	case LicenseBasic:
		return 1
	case LicenseExpress:
		return 2
	case LicenseEnterprise:
		return 3
	case LicenseDatacenter:
		return 4
	default:
		return 0
	}
}

// Above reports whether t is a strictly higher tier than o.
func (t LicenseTier) Above(o LicenseTier) bool { return tierRank(t) > tierRank(o) }

// License is the licence picture for a BMC.
type License struct {
	Tier        LicenseTier
	Source      string // "LicenseService", "unavailable", ...
	Description string // the licence name the tier was derived from
	// GraphicalConsole is the Manager's GraphicalConsole.ServiceEnabled; on BMCs without a
	// licence API (iDRAC8) it is the best hint that an Enterprise-level licence is present.
	GraphicalConsole bool
}

// InventoryInfo holds the scalar inventory fields.
type InventoryInfo struct {
	Manufacturer      string
	Model             string
	SerialNumber      string
	SKU               string // Dell: service tag
	BIOSVersion       string
	BMCModel          string
	BMCFirmware       string
	MemoryGiB         float64
	ProcessorCount    int
	ProcessorModel    string
	LogicalProcessors int
	// SystemID is the vendor's system ID for firmware catalogs (Dell OEM SystemID 2191 →
	// "088F"; "" when the BMC does not report one, such as iDRAC8).
	SystemID string
}

// InventoryParams are the inputs to NewInventory. Slices are copied.
type InventoryParams struct {
	InventoryInfo
	Firmware []FirmwareItem
	License  License
}

// Inventory is an immutable hardware/firmware inventory.
type Inventory struct {
	info     InventoryInfo
	firmware []FirmwareItem
	license  License
}

// NewInventory builds an Inventory, copying slices.
func NewInventory(p InventoryParams) Inventory {
	return Inventory{info: p.InventoryInfo, firmware: slices.Clone(p.Firmware), license: p.License}
}

// Info returns the scalar fields.
func (i Inventory) Info() InventoryInfo { return i.info }

// Firmware returns a copy of the firmware list.
func (i Inventory) Firmware() []FirmwareItem { return slices.Clone(i.firmware) }

// License returns the licence information.
func (i Inventory) License() License { return i.license }

// WithLicense returns a copy with the licence replaced.
func (i Inventory) WithLicense(l License) Inventory {
	out := i
	out.firmware = slices.Clone(i.firmware)
	out.license = l
	return out
}

// WithFirmware returns a copy with the firmware list replaced.
func (i Inventory) WithFirmware(fw []FirmwareItem) Inventory {
	out := i
	out.firmware = slices.Clone(fw)
	return out
}
