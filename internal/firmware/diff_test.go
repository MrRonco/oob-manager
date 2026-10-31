package firmware

import (
	"slices"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

func TestDiff(t *testing.T) {
	old := []Component{
		{Key: Key{ComponentID: "159"}, Name: "BIOS", Running: "2.18.1", Previous: "2.17.0"},
		{Key: Key{ComponentID: "25227"}, Name: "iDRAC", Running: "2.86.86.86"},
		{Key: Key{ComponentID: "gone"}, Name: "Gone", Running: "1.0", Staged: "1.1"},
	}
	next := []Component{
		{Key: Key{ComponentID: "159"}, Name: "BIOS", Running: "2.19.0", Previous: "2.18.1", Staged: "2.20.0"},
		{Key: Key{ComponentID: "25227"}, Name: "iDRAC", Running: "2.86.86.86"},
		{Key: Key{ComponentID: "new", FQDD: "NIC.1"}, Name: "New NIC", Running: "3.0"},
	}
	got := Diff(old, next, true)
	want := []Change{
		{Key: Key{ComponentID: "159"}, Name: "BIOS", Field: FieldRunning, Before: "2.18.1", After: "2.19.0"},
		{Key: Key{ComponentID: "159"}, Name: "BIOS", Field: FieldPrevious, Before: "2.17.0", After: "2.18.1"},
		{Key: Key{ComponentID: "159"}, Name: "BIOS", Field: FieldStaged, Before: "", After: "2.20.0"},
		{Key: Key{ComponentID: "gone"}, Name: "Gone", Field: FieldRunning, Before: "1.0", After: ""},
		{Key: Key{ComponentID: "gone"}, Name: "Gone", Field: FieldStaged, Before: "1.1", After: ""},
		{Key: Key{ComponentID: "new", FQDD: "NIC.1"}, Name: "New NIC", Field: FieldRunning, Before: "", After: "3.0"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("diff\n got %+v\nwant %+v", got, want)
	}
	// An incomplete scan never reports a component as removed.
	partial := Diff(old, next, false)
	for _, c := range partial {
		if c.ComponentID == "gone" {
			t.Fatalf("incomplete scan removed %+v", c)
		}
	}
	if len(Diff(nil, next, true)) != 0 {
		t.Fatal("the first scan of a server is not a change")
	}
}

func TestStickyAndNeeds(t *testing.T) {
	rel := time.Date(2025, 9, 27, 0, 0, 0, 0, time.UTC)
	stored := Record{Component: Component{Key: Key{ComponentID: "105897", FQDD: "NIC.Embedded.1-1-1"}, Kind: bmc.FirmwareNIC,
		Name: "Broadcom BCM5720", Named: true, Running: "23.31.1", ReleaseDate: rel, Updateable: true, Identity: "DCIM:x"},
		DocReadAt: now.AddDate(0, 0, -1)}
	scanned := Component{Key: stored.Key, Kind: bmc.FirmwareNIC, Name: "NIC.Embedded.1-1-1", Running: "23.31.1"}
	got := Sticky(stored, scanned)
	if got.Name != "Broadcom BCM5720" || !got.Named || !got.ReleaseDate.Equal(rel) || !got.Updateable || got.Identity != "DCIM:x" {
		t.Fatalf("sticky %+v", got)
	}
	scanned.Running = "23.40.0"
	if got := Sticky(stored, scanned); !got.ReleaseDate.IsZero() || got.Name != "Broadcom BCM5720" {
		t.Fatalf("a new running version drops the old release date: %+v", got)
	}
	fresh := scanned
	fresh.Named, fresh.Name = true, "Broadcom new name"
	if got := Sticky(stored, fresh); got.Name != "Broadcom new name" {
		t.Fatalf("a document read in this scan wins: %+v", got)
	}

	it := bmc.FirmwareItem{ComponentID: "105897", FQDD: "NIC.Embedded.1-1-1", State: "Current", Version: "23.31.1"}
	if NeedsDocument(stored, true, it, now) {
		t.Error("a named, fresh, unchanged component needs no document")
	}
	if !NeedsDocument(stored, false, it, now) {
		t.Error("an unknown component needs its document")
	}
	stale := stored
	stale.DocReadAt = now.Add(-DocRefresh - time.Hour)
	if !NeedsDocument(stale, true, it, now) {
		t.Error("names are refreshed after DocRefresh")
	}
	unnamed := stored
	unnamed.Named = false
	if !NeedsDocument(unnamed, true, it, now) {
		t.Error("an unnamed component is tried again")
	}
	changed := it
	changed.Version = "23.40.0"
	if !NeedsDocument(stored, true, changed, now) {
		t.Error("a changed running version re-reads the document (release date)")
	}
	prev := changed
	prev.State = "Previous"
	if NeedsDocument(stored, true, prev, now) {
		t.Error("a rollback image's version is not the running one")
	}
}

// TestNeedsDocumentStoredImage (review C-M2): a component whose BMC holds an image it
// never installed lists a Current- member with that version; it is not a version change
// and must not re-read the document at every scan.
func TestNeedsDocumentStoredImage(t *testing.T) {
	stored := Record{Component: Component{Key: Key{ComponentID: "101434"}, Name: "Backplane 0", Named: true,
		Running: "2.23", Stored: "2.25"}, DocReadAt: now.Add(-time.Hour)}
	if NeedsDocument(stored, true, bmc.FirmwareItem{ComponentID: "101434", State: "Installed", Version: "2.23"}, now) {
		t.Error("the Installed member is unchanged")
	}
	if NeedsDocument(stored, true, bmc.FirmwareItem{ComponentID: "101434", State: "Current", Version: "2.25"}, now) {
		t.Error("the Current member carries the stored image's version")
	}
	if NeedsDocument(stored, true, bmc.FirmwareItem{ComponentID: "101434", State: "Current", Version: "2.30"}, now) {
		t.Error("a new stored image is not a running version change")
	}
	if !NeedsDocument(stored, true, bmc.FirmwareItem{ComponentID: "101434", State: "Installed", Version: "2.25"}, now) {
		t.Error("a new Installed version is a change")
	}
	only := Record{Component: Component{Key: Key{ComponentID: "3"}, Named: true, Running: "3.1"}, DocReadAt: now.Add(-time.Hour)}
	if !NeedsDocument(only, true, bmc.FirmwareItem{ComponentID: "3", State: "Current", Version: "3.2"}, now) {
		t.Error("a Current- only component's running version comes from that member")
	}
}
