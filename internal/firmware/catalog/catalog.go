// Package catalog is the vendor firmware catalog check (docs/plans/08-update-checker.md,
// building on plan 03 §9): the types a vendor source parses into, the UpdateSource a
// vendor implements, and the read-side Catalog the firmware view asks. A catalog returns
// versions and their metadata, never images: nothing here fetches a package, stages or
// applies anything, or talks to a BMC (CLAUDE.md rule 11). Fetching the catalog itself is
// opt-in and lives in internal/fwcatalog.
package catalog

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Key identifies a component for a catalog lookup: the PCI identity (Dell
// IdentityInfoValue on iDRAC9), the vendor component ID and the system ID. iDRAC8
// reports only the component ID, which a catalog can still match.
type Key struct {
	VendorID, DeviceID, SubVendorID, SubDeviceID string
	ComponentID, SystemID                        string
}

// KeyFromIdentity builds a key from a Dell identity "DCIM:firmware:VEN:DEV:SUBVEN:SUBDEV"
// (anything else keeps only the component and system IDs).
func KeyFromIdentity(identity, componentID, systemID string) Key {
	k := Key{ComponentID: componentID, SystemID: systemID}
	parts := strings.Split(identity, ":")
	if len(parts) == 6 {
		k.VendorID, k.DeviceID, k.SubVendorID, k.SubDeviceID = parts[2], parts[3], parts[4], parts[5]
	}
	return k
}

// Criticality is a vendor's rating of a release (Dell's values: 1, 2, 3).
type Criticality int

// Criticalities. The zero value is unknown and never stored.
const (
	CriticalityUnknown     Criticality = 0
	CriticalityRecommended Criticality = 1
	CriticalityUrgent      Criticality = 2
	CriticalityOptional    Criticality = 3
)

// Valid reports one of the three known ratings.
func (c Criticality) Valid() bool { return c >= CriticalityRecommended && c <= CriticalityOptional }

// String is the API and CSV value ("urgent", "recommended", "optional"; "" unknown).
func (c Criticality) String() string {
	switch c {
	case CriticalityRecommended:
		return "recommended"
	case CriticalityUrgent:
		return "urgent"
	case CriticalityOptional:
		return "optional"
	default:
		return ""
	}
}

// Label is the UI text ("Urgent").
func (c Criticality) Label() string {
	s := c.String()
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// Release is one vendor package for a component.
type Release struct {
	Version     string
	Date        time.Time // zero: not reported
	Criticality Criticality
	Name        string
	// PackagePath is the vendor's package path, shown to a human; nothing ever fetches it.
	PackagePath    string
	DetailsURL     string
	RebootRequired bool
}

// Device is what a release applies to: the vendor component ID and, optionally, a PCI
// identity (empty when the vendor gives none).
type Device struct {
	ComponentID                                  string
	VendorID, DeviceID, SubVendorID, SubDeviceID string
}

// HasPCI reports a PCI identity.
func (d Device) HasPCI() bool { return d.VendorID != "" || d.DeviceID != "" }

// Entry is one release for one system and device: the unit the store keeps.
type Entry struct {
	SystemID string
	Device
	Release
}

// Manifest describes one catalog publication.
type Manifest struct {
	Version, ReleaseID, Identifier, BaseLocation string
	Published                                    time.Time // zero: not reported
}

// Snapshot is a parsed catalog: its manifest, how many components it lists in total, the
// models it names per system ID (for the model-name fallback), and the entries kept for
// the wanted systems.
type Snapshot struct {
	Manifest   Manifest
	Components int
	Models     map[string][]string // system ID → display names ("PowerEdge R7xx")
	Entries    []Entry
}

// SystemKey is how a source identifies a server's model.
type SystemKey struct {
	Source   string // "dell"
	SystemID string // the vendor's system ID ("088F"); "" when only the model is known
	Model    string // the BMC-reported model ("PowerEdge R7xx")
	ByModel  bool   // the system ID came from the model name, not from the BMC
}

// Match is a lookup result: the newest comparable release, how many packages matched
// and how the system was identified.
type Match struct {
	Latest     Release
	Candidates int
	By         string // "system_id", "model_name" or "override"
}

// Info describes the imported catalog; the zero value is "none imported".
type Info struct {
	Name       string
	ImportedAt time.Time
	Entries    int
}

// Imported reports whether a catalog is present.
func (i Info) Imported() bool { return i.Name != "" }

// Text is the line the firmware page shows.
func (i Info) Text() string {
	if !i.Imported() {
		return "Catalog: none imported"
	}
	return fmt.Sprintf("Catalog: %s (%d entries)", i.Name, i.Entries)
}

// Catalog looks up the newest known release of a component. Implementations must not
// reach the network.
type Catalog interface {
	Lookup(ctx context.Context, k Key) (Match, bool, error)
	Info(ctx context.Context) (Info, error)
}

// Null returns the catalog used until an import exists: it knows nothing.
func Null() Catalog { return nullCatalog{} }

type nullCatalog struct{}

func (nullCatalog) Lookup(context.Context, Key) (Match, bool, error) { return Match{}, false, nil }

func (nullCatalog) Info(context.Context) (Info, error) { return Info{}, nil }

// SafeDetailsURL returns raw when it is an https link on dell.com or a subdomain (no user
// info), else "": the only vendor links the UI and the API pass on (plan 08 §10).
func SafeDetailsURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if h != "dell.com" && !strings.HasSuffix(h, ".dell.com") {
		return ""
	}
	return u.String()
}
