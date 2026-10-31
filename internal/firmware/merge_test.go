package firmware

import (
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

func item(state, comp, version, fqdd string) bmc.FirmwareItem {
	return bmc.FirmwareItem{ID: state + "-" + comp + "-" + version, State: state, ComponentID: comp, Version: version,
		FQDD: fqdd, Name: "Component " + comp}
}

func byKey(cs []Component) map[Key]Component {
	out := map[Key]Component{}
	for _, c := range cs {
		out[c.Key] = c
	}
	return out
}

func TestMergeDellStates(t *testing.T) {
	rel := time.Date(2025, 9, 27, 0, 0, 0, 0, time.UTC)
	detailed := item("Installed", "101434", "2.23", "")
	detailed.Name, detailed.Detailed, detailed.Named, detailed.Kind, detailed.Updateable = "Backplane 0", true, true, bmc.FirmwareEnclosure, true
	prevDoc := item("Previous", "159", "2.18.1", "")
	prevDoc.Detailed, prevDoc.Named, prevDoc.Name, prevDoc.ReleaseDate = true, true, "BIOS", rel.AddDate(-1, 0, 0)
	items := []bmc.FirmwareItem{
		item("Current", "101434", "2.25", ""), // an image stored on the BMC, never installed (iDRAC8 capture)
		detailed,
		item("Current", "159", "2.19.0", ""),
		item("Installed", "159", "2.19.0", ""),
		prevDoc,
		item("Available", "159", "2.20.0", ""),
		item("Installed", "25227", "2.86.86.86", ""),
		item("Previous", "25227", "2.85.85.85", ""),
		item("Previous", "777", "1.0", ""), // only a rollback copy
		item("Current", "105897", "23.31.1", "NIC.Embedded.1-1-1"),
		item("Current", "105897", "23.31.1", "NIC.Embedded.2-1-1"),
	}
	got := byKey(Merge(items))
	if len(got) != 6 {
		t.Fatalf("%d components: %+v", len(got), got)
	}
	bp := got[Key{ComponentID: "101434"}]
	if bp.Running != "2.23" || bp.Stored != "2.25" || bp.Name != "Backplane 0" || !bp.Named ||
		bp.Kind != bmc.FirmwareEnclosure || !bp.Updateable || !bp.NotApplied() {
		t.Errorf("backplane %+v", bp)
	}
	bios := got[Key{ComponentID: "159"}]
	if bios.Running != "2.19.0" || bios.Previous != "2.18.1" || bios.Staged != "2.20.0" || bios.Stored != "" || bios.NotApplied() {
		t.Errorf("bios %+v", bios)
	}
	if !bios.ReleaseDate.IsZero() {
		t.Error("the previous image's release date is not the running version's")
	}
	if bios.Name != "BIOS" || !bios.Named {
		t.Errorf("a document of any state names the component: %+v", bios)
	}
	if d := got[Key{ComponentID: "25227"}]; d.Running != "2.86.86.86" || d.Previous != "2.85.85.85" || d.Named {
		t.Errorf("idrac %+v", d)
	}
	if r := got[Key{ComponentID: "777"}]; r.Running != "" || r.Previous != "1.0" {
		t.Errorf("rollback only %+v", r)
	}
	if a, b := got[Key{"105897", "NIC.Embedded.1-1-1"}], got[Key{"105897", "NIC.Embedded.2-1-1"}]; a.Running != "23.31.1" || b.Running != "23.31.1" {
		t.Errorf("one row per FQDD: %+v %+v", a, b)
	}
}

func TestMergeReleaseDateFromRunning(t *testing.T) {
	rel := time.Date(2024, 7, 25, 0, 0, 0, 0, time.UTC)
	inst := item("Installed", "102301", "23.0.8", "NIC.Slot.2-1-1")
	inst.Detailed, inst.Named, inst.ReleaseDate, inst.Identity, inst.Name = true, true, rel, "DCIM:firmware:8086:1572:1028:0000", "X710"
	got := Merge([]bmc.FirmwareItem{item("Current", "102301", "23.0.8", "NIC.Slot.2-1-1"), inst})
	if len(got) != 1 || !got[0].ReleaseDate.Equal(rel) || got[0].Identity == "" || got[0].Name != "X710" {
		t.Fatalf("%+v", got)
	}
}

func TestMergeGenericItems(t *testing.T) {
	items := []bmc.FirmwareItem{
		{ID: "BMC", Name: "BMC Firmware", Version: "1.2.3", Detailed: true, Named: true, Kind: bmc.FirmwareBMC},
		{ID: "BIOS", Name: "", Version: "4.5"},
	}
	got := byKey(Merge(items))
	if b := got[Key{ComponentID: "BMC"}]; b.Running != "1.2.3" || b.Kind != bmc.FirmwareBMC {
		t.Errorf("bmc %+v", b)
	}
	if b := got[Key{ComponentID: "BIOS"}]; b.Running != "4.5" || b.Kind != bmc.FirmwareOther || b.Named {
		t.Errorf("an item without a kind is other: %+v", b)
	}
}

func TestMergeOrderAndSkips(t *testing.T) {
	items := []bmc.FirmwareItem{
		{ID: "", ComponentID: "", Version: "1"}, // no key at all: dropped
		{ID: "z", Version: "1", Kind: bmc.FirmwareOther, Name: "z"},
		{ID: "a", Version: "1", Kind: bmc.FirmwareBIOS, Name: "a"},
		item("Current", "1", "1.0", ""),
		item("Current", "1", "9.0", ""), // a second Current for one key: the first wins
	}
	got := Merge(items)
	if len(got) != 3 || got[0].Kind != bmc.FirmwareBIOS || got[2].ComponentID != "z" {
		t.Fatalf("order %+v", got)
	}
	if one := byKey(got)[Key{ComponentID: "1"}]; one.Running != "1.0" {
		t.Fatalf("first Current wins: %+v", one)
	}
}

func TestMergeDocumentWithoutName(t *testing.T) {
	cur := item("Current", "159", "2.20.0", "BIOS.Setup.1-1")
	cur.Name, cur.Detailed, cur.Updateable = "BIOS", true, true // the driver kept its fallback: Named is false
	got := Merge([]bmc.FirmwareItem{cur})
	if len(got) != 1 || got[0].Name != "BIOS" || got[0].Named || !got[0].Updateable {
		t.Fatalf("%+v", got)
	}
}

// TestMergeStoredImage: Dell "Installed-" is what runs and "Current-" the image the BMC
// holds. A stored image older than the running one, or one that cannot be ordered, is
// kept for display but is not "not applied"; a component with only a Current- member
// shows it as running (nothing better is known).
func TestMergeStoredImage(t *testing.T) {
	got := byKey(Merge([]bmc.FirmwareItem{
		item("Current", "1", "1.0", ""), item("Installed", "1", "2.0", ""),
		item("Current", "2", "A07", ""), item("Installed", "2", "1.4.2", ""),
		item("Current", "3", "3.1", ""),
		item("Installed", "4", "4.2", ""), item("Current", "4", "4.2", ""),
	}))
	if c := got[Key{ComponentID: "1"}]; c.Running != "2.0" || c.Stored != "1.0" || c.NotApplied() {
		t.Errorf("older stored image: %+v", c)
	}
	if c := got[Key{ComponentID: "2"}]; c.Running != "1.4.2" || c.Stored != "A07" || c.NotApplied() {
		t.Errorf("incomparable stored image: %+v", c)
	}
	if c := got[Key{ComponentID: "3"}]; c.Running != "3.1" || c.Stored != "" {
		t.Errorf("Current- only: %+v", c)
	}
	if c := got[Key{ComponentID: "4"}]; c.Running != "4.2" || c.Stored != "" || c.NotApplied() {
		t.Errorf("stored image equal to the running one: %+v", c)
	}
}
