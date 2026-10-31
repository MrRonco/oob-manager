package firmware

import (
	"cmp"
	"slices"
	"time"

	"oob-manager/internal/bmc"
)

// Fields a change can be about (firmware_changes.field).
const (
	FieldRunning  = "running"
	FieldPrevious = "previous"
	FieldStaged   = "staged"
)

// DocRefresh is how long a member document's name and details are trusted before the
// next scan reads the document again.
const DocRefresh = 30 * 24 * time.Hour

// Change is one version change between two scans of a server. A component that
// appeared has Before ""; one that disappeared has After "".
type Change struct {
	Key
	Name          string
	Field         string
	Before, After string
}

func fields(c Component) [3]string { return [3]string{c.Running, c.Previous, c.Staged} }

func fieldNames() [3]string { return [3]string{FieldRunning, FieldPrevious, FieldStaged} }

// Diff lists the changes from old to next, ordered by key and field. The first scan of
// a server (old empty) is no change. A component missing from next counts as removed
// only when the scan was complete (every member listed and considered).
func Diff(old, next []Component, complete bool) []Change {
	if len(old) == 0 {
		return nil
	}
	before := map[Key]Component{}
	for _, c := range old {
		before[c.Key] = c
	}
	var out []Change
	seen := map[Key]bool{}
	for _, n := range next {
		seen[n.Key] = true
		o := before[n.Key] // zero when new: every set field appears
		out = append(out, fieldChanges(n.Key, n.Name, fields(o), fields(n))...)
	}
	if complete {
		for _, o := range old {
			if !seen[o.Key] {
				out = append(out, fieldChanges(o.Key, o.Name, fields(o), [3]string{})...)
			}
		}
	}
	slices.SortStableFunc(out, func(a, b Change) int {
		return cmp.Or(cmp.Compare(a.ComponentID, b.ComponentID), cmp.Compare(a.FQDD, b.FQDD),
			cmp.Compare(fieldRank(a.Field), fieldRank(b.Field)))
	})
	return out
}

func fieldRank(f string) int {
	names := fieldNames()
	return slices.Index(names[:], f)
}

func fieldChanges(k Key, name string, before, after [3]string) []Change {
	var out []Change
	for i, f := range fieldNames() {
		if before[i] != after[i] {
			out = append(out, Change{Key: k, Name: name, Field: f, Before: before[i], After: after[i]})
		}
	}
	return out
}

// Sticky keeps what an earlier scan learnt from the member document when this scan
// did not read it: name, kind, updateable and identity; the release date only while
// the running version is the same.
func Sticky(stored Record, scanned Component) Component {
	if scanned.Named || !stored.Named {
		return scanned
	}
	out := scanned
	out.Name, out.Named, out.Kind = stored.Name, true, stored.Kind
	out.Updateable, out.Identity = stored.Updateable, stored.Identity
	out.ReleaseDate = time.Time{}
	if stored.Running == scanned.Running {
		out.ReleaseDate = stored.ReleaseDate
	}
	return out
}

// NeedsDocument reports whether a scan should read item's member document: the
// component is new or unnamed, its details are older than DocRefresh, or its running
// version changed (the release date belongs to the version).
func NeedsDocument(stored Record, found bool, item bmc.FirmwareItem, now time.Time) bool {
	switch {
	case !found, !stored.Named, now.Sub(stored.DocReadAt) > DocRefresh:
		return true
	case item.State == "Previous" || item.State == "Available":
		return false
	case item.State == "Current":
		// The image in the BMC's store. With a known stored image the component has an
		// Installed- member that carries the running version; otherwise a different
		// version is either a new stored image or the running version of a component
		// listed only as Current- (one read tells them apart: the next scan knows).
		return stored.Stored == "" && item.Version != stored.Running
	default:
		return item.Version != stored.Running
	}
}
