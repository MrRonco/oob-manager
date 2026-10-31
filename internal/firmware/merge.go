package firmware

import (
	"cmp"
	"slices"
	"time"

	"oob-manager/internal/bmc"
)

// Key identifies one component of one server: the vendor component ID (Dell) or the
// Redfish member ID (generic), plus the FQDD when the BMC reports one, so two NICs with
// the same component ID are two rows.
type Key struct {
	ComponentID string
	FQDD        string
}

// Members records which Dell member states a scan listed for a component (zero for
// generic members and for rows read from the store): an incomplete scan that misses one
// of them is told apart from one that lists both at the same version.
type Members uint8

// Dell member states a scan can list.
const (
	MemberInstalled Members = 1 << iota
	MemberCurrent
)

// Has reports whether every state of m was listed.
func (s Members) Has(m Members) bool { return s&m == m }

// Component is one firmware component as last read, with its states merged:
// Running is what the device runs (Dell "Installed", else the generic member, else
// Dell "Current" when nothing better is known), Previous the rollback copy, Staged an
// image waiting for a reboot (Dell "Available"), and Stored the image the BMC holds in
// its firmware store (Dell "Current", OEM status AvailableForInstallation) when it
// differs from the running version: an image that was never installed.
type Component struct {
	Key
	Kind bmc.FirmwareKind
	// Name is the best name known; Named reports that it came from the member document
	// (otherwise it is the driver's fallback, e.g. "Component 101068").
	Name                              string
	Named                             bool
	Running, Previous, Staged, Stored string
	ReleaseDate                       time.Time // of the running version; zero when not reported
	Updateable                        bool
	Identity                          string
	Members                           Members // the Dell states this scan listed; never stored
}

// NotApplied reports a stored image newer than the running version: an update the BMC
// holds but never installed. An older or unorderable stored image is shown, not flagged.
func (c Component) NotApplied() bool {
	if c.Stored == "" {
		return false
	}
	order, ok := CompareVersions(c.Stored, c.Running)
	return ok && order > 0
}

// group collects the items of one key.
type group struct {
	key                                   Key
	current, installed, generic, previous string
	staged                                string
	members                               Members
	items                                 []bmc.FirmwareItem
}

// Merge turns a scan's items into one Component per key, in display order (kind, then
// name, then key). Items without any identifier are dropped. Of several items with the
// same state for one key, the first wins.
func Merge(items []bmc.FirmwareItem) []Component {
	var order []Key
	groups := map[Key]*group{}
	for _, it := range items {
		k := Key{ComponentID: cmp.Or(it.ComponentID, it.ID), FQDD: it.FQDD}
		if k.ComponentID == "" {
			continue
		}
		g, ok := groups[k]
		if !ok {
			g = &group{key: k}
			groups[k] = g
			order = append(order, k)
		}
		g.add(it)
	}
	out := make([]Component, 0, len(order))
	for _, k := range order {
		out = append(out, groups[k].component())
	}
	slices.SortStableFunc(out, func(a, b Component) int {
		return cmp.Or(cmp.Compare(a.Kind.Rank(), b.Kind.Rank()), cmp.Compare(a.Name, b.Name),
			cmp.Compare(a.ComponentID, b.ComponentID), cmp.Compare(a.FQDD, b.FQDD))
	})
	return out
}

func firstOf(cur *string, v string) {
	if *cur == "" {
		*cur = v
	}
}

func (g *group) add(it bmc.FirmwareItem) {
	g.items = append(g.items, it)
	switch it.State {
	case "Current":
		firstOf(&g.current, it.Version)
		g.members |= MemberCurrent
	case "Installed":
		firstOf(&g.installed, it.Version)
		g.members |= MemberInstalled
	case "Previous":
		firstOf(&g.previous, it.Version)
	case "Available":
		firstOf(&g.staged, it.Version)
	default:
		firstOf(&g.generic, it.Version)
	}
}

// running is the version the device runs and the state it came from: Dell "Installed"
// (the "Current" member is the image in the BMC's store), else a generic member, else
// "Current" as a last resort.
func (g *group) running() (string, string) {
	switch {
	case g.installed != "":
		return g.installed, "Installed"
	case g.generic != "":
		return g.generic, ""
	default:
		return g.current, "Current"
	}
}

func (g *group) component() Component {
	run, state := g.running()
	c := Component{Key: g.key, Running: run, Previous: g.previous, Staged: g.staged, Members: g.members}
	if g.current != "" && g.installed != "" && g.current != g.installed {
		c.Stored = g.current
	}
	best := g.best(state)
	c.Name, c.Kind = best.Name, best.Kind
	if doc, ok := g.document(state); ok {
		if doc.Named && doc.Name != "" {
			c.Name, c.Named = doc.Name, true
		}
		c.Updateable, c.Identity = doc.Updateable, doc.Identity
		c.Kind = cmp.Or(doc.Kind, c.Kind)
		if doc.State == state {
			c.ReleaseDate = doc.ReleaseDate
		}
	}
	c.Kind = cmp.Or(c.Kind, bmc.FirmwareOther)
	return c
}

// best is the item of the running state (else the first item): its fallback name and
// kind are the driver's best guess.
func (g *group) best(state string) bmc.FirmwareItem {
	for _, it := range g.items {
		if it.State == state {
			return it
		}
	}
	return g.items[0]
}

// document is the member document to take the name and details from: the running
// state's if it was read, else any read one.
func (g *group) document(state string) (bmc.FirmwareItem, bool) {
	var other bmc.FirmwareItem
	found := false
	for _, it := range g.items {
		if !it.Detailed {
			continue
		}
		if it.State == state {
			return it, true
		}
		if !found {
			other, found = it, true
		}
	}
	return other, found
}
