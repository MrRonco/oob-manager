package ui

import (
	"cmp"
	"fmt"
	"net/http"
	"regexp"
	"slices"

	"oob-manager/internal/bmc"
)

type firmwareRow struct {
	Name, Version, State, ComponentID, FQDD string
	Unnamed                                 bool
}

// firmwareColumns hides firmware columns that are empty on every row (UX-10, UX-19).
type firmwareColumns struct{ ComponentID, FQDD bool }

// inventoryView is the Inventory tab: identity, license, capabilities (what this BMC
// supports and what this version of oob-manager offers on it) and firmware.
type inventoryView struct {
	Head          serverHead
	Nav           serverNav
	HasInventory  bool
	Info          []kv
	License       []kv
	LicenseNote   string
	BMC           []kv
	Capabilities  []actionRow
	Firmware      []firmwareRow
	FirmwareCols  firmwareColumns
	InventoryNote string
	PollTook      string
	// FW is the firmware view's section (tech_doc §38); nil lists Firmware as before.
	FW *fwSection
}

func (s *server) inventoryPage(w http.ResponseWriter, r *http.Request, sess session) {
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	iv := inventoryView{Head: s.headFor(v, sess).tab("inventory"), Nav: s.navFor(v, sess, "inventory"), HasInventory: v.HasInventory,
		Capabilities: s.actionRows(v, sess.id.Principal()), PollTook: fmtPollDuration(v.LastPollDuration),
		InventoryNote: s.overdueNote("Inventory", v.InventoryOverdue, v.InventoryAsOf, sess.tf())}
	if v.HasInventory {
		iv.Info = infoRows(v.Inventory.Info())
		iv.License, iv.LicenseNote = licenseRows(v.Inventory.License()), licenseNote(v.Inventory.License())
		iv.Firmware, iv.FirmwareCols = firmwareRows(v.Inventory.Firmware())
	}
	if v.HasCapabilities {
		iv.BMC = bmcRows(v.Capabilities.Flags(), sess.tf())
	}
	iv.FW = s.firmwareSection(r, v, sess)
	d := s.serverLayout(sess, v, v.Name+": inventory", "Inventory", iv)
	s.render(w, r, http.StatusOK, pageInventory, d)
}

func infoRows(i bmc.InventoryInfo) []kv {
	mem := dash
	if i.MemoryGiB > 0 {
		mem = fmt.Sprintf("%.0f GiB", i.MemoryGiB)
	}
	cpus := dash
	if i.ProcessorCount > 0 {
		cpus = fmt.Sprintf("%d × %s (%d threads)", i.ProcessorCount, orUnnamed(i.ProcessorModel), i.LogicalProcessors)
	}
	return []kv{
		{"Manufacturer", i.Manufacturer},
		{"Model", i.Model},
		{"Service tag", i.SKU},
		{"Serial number", i.SerialNumber},
		{"BIOS", i.BIOSVersion},
		{"BMC", i.BMCModel},
		{"BMC firmware", i.BMCFirmware},
		{"Memory", mem},
		{"Processors", cpus},
	}
}

func orUnnamed(s string) string {
	if s == "" {
		return "unnamed model"
	}
	return s
}

// licenseRows: an unknown tier and an "unavailable" source are not data; they become
// "Not reported" with an explanatory note (UI review F-10).
func licenseRows(l bmc.License) []kv {
	tier := string(l.Tier)
	if l.Tier == bmc.LicenseUnknown {
		tier = dash
	}
	source := l.Source
	if source == "unavailable" {
		source = dash
	}
	return []kv{
		{"Tier", tier},
		{"Source", source},
		{"License", l.Description},
		{"Graphical console", yesNo(l.GraphicalConsole)},
	}
}

func licenseNote(l bmc.License) string {
	if l.Source == "unavailable" || l.Source == "" {
		return "This BMC has no license API, so its tier cannot be read."
	}
	return ""
}

func bmcRows(f bmc.CapabilityFlags, tf timeFmt) []kv {
	return []kv{
		{"Product", f.Product},
		{"Redfish version", f.RedfishVersion},
		{"System Event Log", yesNo(f.SEL)},
		{"Serial console", yesNo(f.SerialConsole)},
		{"Graphical console", yesNo(f.GraphicalConsole)},
		{"Probed", tf.full(f.ProbedAt)},
	}
}

// unnamedComponent is the driver's fallback name for a Dell component without a known
// name ("Component 101068").
var unnamedComponent = regexp.MustCompile(`^Component (\d+)$`)

// firmwareRows sorts by component then state (Installed and Current before Previous),
// so the versions of one component sit together.
func firmwareRows(fw []bmc.FirmwareItem) ([]firmwareRow, firmwareColumns) {
	out := make([]firmwareRow, 0, len(fw))
	var cols firmwareColumns
	for _, f := range fw {
		r := firmwareRow{Name: f.Name, Version: f.Version, State: f.State, ComponentID: f.ComponentID, FQDD: f.FQDD}
		if m := unnamedComponent.FindStringSubmatch(f.Name); m != nil {
			r.Name, r.Unnamed = "Unnamed component (ID "+m[1]+")", true
		}
		cols = firmwareColumns{ComponentID: cols.ComponentID || r.ComponentID != "", FQDD: cols.FQDD || r.FQDD != ""}
		out = append(out, r)
	}
	slices.SortStableFunc(out, func(a, b firmwareRow) int {
		return cmp.Or(cmp.Compare(boolRank(a.Unnamed), boolRank(b.Unnamed)), cmp.Compare(a.Name, b.Name),
			cmp.Compare(stateRank(a.State), stateRank(b.State)))
	})
	return out, cols
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

func stateRank(s string) int {
	switch s {
	case "Installed", "Current":
		return 0
	case "Previous":
		return 2
	default:
		return 1
	}
}
