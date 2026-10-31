package firmware

import (
	"time"

	"oob-manager/internal/firmware/catalog"
)

// UpdateState is what the vendor catalog says about a component (plan 08 §8.2), a closed
// enum shown in the API ("update") and CSV.
type UpdateState string

// Update states.
const (
	UpdateNone          UpdateState = ""               // no catalog in use, or not judged
	UpdateCurrent       UpdateState = "none"           // running ≥ the newest the vendor lists
	UpdateAvailable     UpdateState = "available"      // a newer release (Recommended or Optional)
	UpdateUrgent        UpdateState = "urgent"         // a newer release rated Urgent
	UpdateSkipped       UpdateState = "skipped"        // an admin skipped exactly this latest version
	UpdateCannotCompare UpdateState = "cannot_compare" // packages exist but no version orders against running
	UpdateNotInCatalog  UpdateState = "not_in_catalog" // the catalog lists no package for this component
)

// Skip is an admin's "skip this version" for one component.
type Skip struct {
	Version, Comment, By string
	At                   time.Time
}

// Update is the catalog's verdict on one component.
type Update struct {
	State      UpdateState
	Latest     catalog.Release // zero when the catalog lists nothing comparable
	Candidates int             // packages that matched the component
	MatchedBy  string          // "system_id", "model_name" or "override"
	// StoredIsLatest: the image the BMC already holds (Dell "Current", v0.8.1) is the
	// latest release, so it only needs installing.
	StoredIsLatest bool
	Skip           *Skip // set when State is UpdateSkipped, or a skip is recorded for an older version
}

// Flag is the update's flag (FlagNone when it raises none).
func (u Update) Flag() Flag {
	switch u.State {
	case UpdateUrgent:
		return FlagUpdateUrgent
	case UpdateAvailable:
		return FlagUpdateAvailable
	default:
		return FlagNone
	}
}

// Newer reports an update that is newer than running and not skipped.
func (u Update) Newer() bool { return u.State == UpdateAvailable || u.State == UpdateUrgent }

// Coverage is how well the catalog covers one server (plan 08 §8.3).
type Coverage struct {
	State      CoverageState
	SystemID   string    // the vendor system ID used
	MatchedBy  string    // how it was found
	Newest     time.Time // newest release listed for the system (legacy line)
	Components int       // components judged
	Matched    int       // components with at least one package
	Updates    int       // newer releases, not skipped
	Urgent     int       // of which rated Urgent
}

// CoverageState is the server line's case.
type CoverageState string

// Coverage states.
const (
	CoverageNone      CoverageState = ""           // no catalog in use (or no index)
	CoverageNoBMCType CoverageState = "no_source"  // the BMC kind has no vendor catalog (generic Redfish)
	CoverageUnknown   CoverageState = "unknown"    // the system could not be identified
	CoverageNotListed CoverageState = "not_listed" // the catalog lists nothing for the system
	CoverageLegacy    CoverageState = "legacy"     // only old entries and nothing matched (end of support)
	CoverageNormal    CoverageState = "normal"
)

// UpdateIndex judges components against the catalog in use. Implementations must not
// reach the network (internal/fwcatalog builds one from the store).
type UpdateIndex interface {
	Update(s ServerInfo, c Component) Update
	Coverage(s ServerInfo, comps []Component) Coverage
}

// withUpdate adds the update's flag to v, keeping the flags worst first.
func withUpdate(v Verdict, u Update) Verdict {
	if f := u.Flag(); f != FlagNone {
		v.Flags = append(v.Flags, f)
		sortFlags(v.Flags)
	}
	return v
}
