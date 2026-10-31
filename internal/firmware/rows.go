package firmware

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"oob-manager/internal/bmc"
)

// Record is a stored component with its bookkeeping times. DocReadAt is when its member
// document was last read (zero: never; names are refreshed after DocRefresh).
type Record struct {
	Component
	FirstSeen, LastSeen, DocReadAt time.Time
}

// Row is one line of the firmware view: a component of a server and its verdict.
type Row struct {
	Server ServerInfo
	Component
	Verdict
	Update              Update // the vendor catalog's verdict (zero: no catalog in use)
	Display             string // the name to show (DisplayName)
	FirstSeen, LastSeen time.Time
}

// fallbackName is the Dell driver's name for a component without a known name.
var fallbackName = regexp.MustCompile(`^Component (.+)$`)

// DisplayName is the name to show: the member document's, else the admin's
// firmware.names entry, else the driver's known name, else "Unnamed component (ID x)".
func (p Policy) DisplayName(c Component) string {
	if c.Named && c.Name != "" {
		return c.Name
	}
	if n := p.Name(c.ComponentID); n != "" {
		return n
	}
	if c.Name == "" || fallbackName.MatchString(c.Name) {
		return "Unnamed component (ID " + c.ComponentID + ")"
	}
	return c.Name
}

// BuildRows evaluates a server's records, with the catalog's verdict when idx is set.
func BuildRows(p Policy, s ServerInfo, recs []Record, now time.Time, idx UpdateIndex) []Row {
	out := make([]Row, 0, len(recs))
	for _, r := range recs {
		row := Row{Server: s, Component: r.Component, Verdict: p.Evaluate(s, r.Component, now),
			Display: p.DisplayName(r.Component), FirstSeen: r.FirstSeen, LastSeen: r.LastSeen}
		if idx != nil {
			row.Update = idx.Update(s, r.Component)
			row.Verdict = withUpdate(row.Verdict, row.Update)
		}
		out = append(out, row)
	}
	return out
}

// SortRows orders rows problems first (worst flag), then by kind, component name,
// server and key.
func SortRows(rows []Row) {
	slices.SortStableFunc(rows, func(a, b Row) int {
		return cmp.Or(cmp.Compare(a.Primary().rank(), b.Primary().rank()), cmp.Compare(a.Kind.Rank(), b.Kind.Rank()),
			cmp.Compare(a.Display, b.Display), cmp.Compare(a.Server.Name, b.Server.Name), cmp.Compare(a.Server.ID, b.Server.ID),
			cmp.Compare(a.ComponentID, b.ComponentID), cmp.Compare(a.FQDD, b.FQDD))
	})
}

// Filter selects rows. Every set field must match; Text is a case-insensitive
// substring of the name, IDs, versions or the server.
type Filter struct {
	ServerID string
	Kind     bmc.FirmwareKind
	Flagged  bool
	Updates  bool // only rows with a newer vendor release (not skipped)
	Text     string
}

// Active reports whether any field is set.
func (f Filter) Active() bool { return f != Filter{} }

// Match reports whether r passes f.
func (f Filter) Match(r Row) bool {
	if (f.ServerID != "" && r.Server.ID != f.ServerID) || (f.Kind != "" && r.Kind != f.Kind) ||
		(f.Flagged && !r.Primary().Flagged()) || (f.Updates && !r.Update.Newer()) {
		return false
	}
	q := strings.ToLower(strings.TrimSpace(f.Text))
	if q == "" {
		return true
	}
	for _, s := range []string{r.Display, r.ComponentID, r.FQDD, r.Running, r.Previous, r.Staged, r.Server.Name, r.Server.ID} {
		if strings.Contains(strings.ToLower(s), q) {
			return true
		}
	}
	return false
}

// ReleaseText renders a release date as "2025-09 (1 y 1 mo ago)" ("" when unknown).
// The age is information, not a verdict.
func ReleaseText(at, now time.Time) string {
	if at.IsZero() {
		return ""
	}
	at, now = at.UTC(), now.UTC()
	month := at.Format("2006-01")
	months := (now.Year()-at.Year())*12 + int(now.Month()) - int(at.Month())
	if now.Day() < at.Day() {
		months--
	}
	switch {
	case at.After(now):
		return month
	case months <= 0:
		return month + " (this month)"
	case months < 12:
		return fmt.Sprintf("%s (%d mo ago)", month, months)
	default:
		return fmt.Sprintf("%s (%d y %d mo ago)", month, months/12, months%12)
	}
}
