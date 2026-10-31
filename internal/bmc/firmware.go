package bmc

import (
	"context"
	"slices"
)

// FirmwareKind classifies a firmware component (docs/tech_doc.md §38). It is a closed
// enum; the store's CHECK list and config validation use FirmwareKinds.
type FirmwareKind string

// Firmware kinds, in display order.
const (
	FirmwareBMC       FirmwareKind = "bmc"
	FirmwareBIOS      FirmwareKind = "bios"
	FirmwareCPLD      FirmwareKind = "cpld"
	FirmwareNIC       FirmwareKind = "nic"
	FirmwareStorage   FirmwareKind = "storage"
	FirmwareDrive     FirmwareKind = "drive"
	FirmwareEnclosure FirmwareKind = "enclosure"
	FirmwarePSU       FirmwareKind = "psu"
	FirmwareLC        FirmwareKind = "lc"
	FirmwareOther     FirmwareKind = "other"
)

// FirmwareKinds returns every kind in display order (a fresh slice).
func FirmwareKinds() []FirmwareKind {
	return []FirmwareKind{FirmwareBMC, FirmwareBIOS, FirmwareCPLD, FirmwareNIC, FirmwareStorage, FirmwareDrive,
		FirmwareEnclosure, FirmwarePSU, FirmwareLC, FirmwareOther}
}

// ParseFirmwareKind validates a kind name exactly.
func ParseFirmwareKind(s string) (FirmwareKind, bool) {
	k := FirmwareKind(s)
	return k, slices.Contains(FirmwareKinds(), k)
}

// Rank is the display position of k; unknown kinds sort last.
func (k FirmwareKind) Rank() int {
	if i := slices.Index(FirmwareKinds(), k); i >= 0 {
		return i
	}
	return len(FirmwareKinds())
}

// Label is the kind as the UI shows it.
func (k FirmwareKind) Label() string {
	switch k {
	case FirmwareBMC:
		return "BMC"
	case FirmwareBIOS:
		return "BIOS"
	case FirmwareCPLD:
		return "CPLD"
	case FirmwareNIC:
		return "Network"
	case FirmwareStorage:
		return "Storage controller"
	case FirmwareDrive:
		return "Drive"
	case FirmwareEnclosure:
		return "Backplane or enclosure"
	case FirmwarePSU:
		return "Power supply"
	case FirmwareLC:
		return "Lifecycle and service tools"
	case FirmwareOther:
		return "Other"
	default:
		return string(k)
	}
}

// FirmwareScan is one read-only pass over a BMC's firmware inventory: the items (from
// member IDs, with member documents where they were read), how many members the
// collection listed and whether every listed member was considered (not cut by the
// member cap or the tier budget). It is immutable.
type FirmwareScan struct {
	items      []FirmwareItem
	listed     int
	complete   bool
	docsRead   int
	docsFailed int
}

// NewFirmwareScan builds a scan, copying items.
func NewFirmwareScan(items []FirmwareItem, listed int, complete bool) FirmwareScan {
	return FirmwareScan{items: slices.Clone(items), listed: max(listed, 0), complete: complete}
}

// WithDocs returns a copy carrying how many member documents were read and failed.
func (s FirmwareScan) WithDocs(read, failed int) FirmwareScan {
	out := s
	out.items = slices.Clone(s.items)
	out.docsRead, out.docsFailed = read, failed
	return out
}

// Items returns a copy of the items.
func (s FirmwareScan) Items() []FirmwareItem { return slices.Clone(s.items) }

// Listed is the member count the collection reported (or listed).
func (s FirmwareScan) Listed() int { return s.listed }

// Complete reports that every listed member was considered.
func (s FirmwareScan) Complete() bool { return s.complete }

// DocsRead counts the member documents read.
func (s FirmwareScan) DocsRead() int { return s.docsRead }

// DocsFailed counts the member documents that could not be read (a 404 is not counted).
func (s FirmwareScan) DocsFailed() int { return s.docsFailed }

// MaxFirmwareMembers caps the FirmwareInventory members one scan considers.
const MaxFirmwareMembers = 64

// FirmwareScanner is the optional firmware-view reader (discovered by type assertion,
// like FanController). It only reads: the FirmwareInventory collection and, for the
// members need selects, their member documents. need gets each item as derived from the
// member list (ComponentID, FQDD and State set on Dell) and returns whether its member
// document should be read; a driver that cannot derive items without the documents
// reads them all (bounded). A scan cut short by ctx keeps what it read and reports
// Complete=false; the error is for a scan that could not list the collection.
type FirmwareScanner interface {
	ScanFirmware(ctx context.Context, need func(FirmwareItem) bool) (FirmwareScan, error)
}
