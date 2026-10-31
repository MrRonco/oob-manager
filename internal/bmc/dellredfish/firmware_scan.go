package dellredfish

import (
	"context"
	"errors"
	"strings"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/firmware"
)

// dellDocument is a Dell FirmwareInventory member: the standard SoftwareInventory fields
// plus the part of Oem.Dell.DellSoftwareInventory the view uses.
type dellDocument struct {
	redfish.FirmwareDocument
	Oem struct {
		Dell struct {
			DellSoftwareInventory struct {
				ComponentType     string   `json:"ComponentType"`
				IdentityInfoValue []string `json:"IdentityInfoValue"`
			} `json:"DellSoftwareInventory"`
		} `json:"Dell"`
	} `json:"Oem"`
}

// ScanFirmware implements bmc.FirmwareScanner (docs/tech_doc.md §38). The versions come
// from the member IDs (one GET); then, for each component need selects, the member
// document of its running state (Installed, else Current, else Available, else Previous)
// names it: one GET per component, not per member. A document that is absent or cannot
// be decoded leaves the ID-derived item as it is. Only GETs are sent.
func (d *Driver) ScanFirmware(ctx context.Context, need func(bmc.FirmwareItem) bool) (bmc.FirmwareScan, error) {
	uris, listed, err := d.base.FirmwareMembers(ctx)
	if err != nil {
		return bmc.FirmwareScan{}, err
	}
	parsed, ok := parseFirmwareMembers(uris)
	if !ok {
		return d.base.ScanFirmware(ctx, need)
	}
	items := make([]bmc.FirmwareItem, len(parsed))
	for i, it := range parsed {
		it.Kind = dellKind(it.ComponentID, it.FQDD, "", "")
		items[i] = it
	}
	complete := len(uris) == listed
	read, failed := 0, 0
	for _, i := range documentsToRead(items, need) {
		var doc dellDocument
		err := d.base.GetJSON(ctx, uris[i], &doc)
		if ctx.Err() != nil {
			complete = false
			break
		}
		if err != nil {
			if !errors.Is(err, bmc.ErrNotFound) {
				failed++
			}
			continue
		}
		read++
		items[i] = applyDell(items[i], doc)
	}
	return bmc.NewFirmwareScan(items, listed, complete).WithDocs(read, failed), nil
}

func applyDell(it bmc.FirmwareItem, doc dellDocument) bmc.FirmwareItem {
	inv := doc.Oem.Dell.DellSoftwareInventory
	out := doc.Apply(bmc.FirmwareItem{ID: it.ID, Name: it.Name, Version: it.Version, State: it.State,
		ComponentID: it.ComponentID, FQDD: it.FQDD,
		Kind: dellKind(it.ComponentID, it.FQDD, inv.ComponentType, doc.Name)})
	if len(inv.IdentityInfoValue) > 0 {
		out.Identity = redfish.CleanIdentity(inv.IdentityInfoValue[0])
	}
	return out
}

// statePreference orders the members of one component for the document read.
func statePreference(s string) int {
	switch s {
	case "Installed":
		return 0
	case "Current":
		return 1
	case "Available":
		return 2
	default:
		return 3
	}
}

// documentsToRead picks, per component (component ID and FQDD), the index of the member
// whose document to read, for the components need asks for (nil: all), in list order.
func documentsToRead(items []bmc.FirmwareItem, need func(bmc.FirmwareItem) bool) []int {
	type pick struct {
		idx    int
		wanted bool
	}
	picks := map[firmware.Key]*pick{}
	var order []firmware.Key
	for i, it := range items {
		k := firmware.Key{ComponentID: it.ComponentID, FQDD: it.FQDD}
		p, ok := picks[k]
		if !ok {
			p = &pick{idx: i}
			picks[k] = p
			order = append(order, k)
		} else if statePreference(it.State) < statePreference(items[p.idx].State) {
			p.idx = i
		}
		wanted := need == nil || need(it) // every item is asked: a version change of any state counts
		p.wanted = p.wanted || wanted
	}
	var out []int
	for _, k := range order {
		if picks[k].wanted {
			out = append(out, picks[k].idx)
		}
	}
	return out
}

// fqddKind classifies by the FQDD prefix (iDRAC9 and later).
func fqddKind(fqdd string) bmc.FirmwareKind {
	prefixes := []struct {
		p string
		k bmc.FirmwareKind
	}{
		{"iDRAC.", bmc.FirmwareBMC}, {"BIOS.", bmc.FirmwareBIOS}, {"CPLD.", bmc.FirmwareCPLD}, {"NIC.", bmc.FirmwareNIC},
		{"RAID.", bmc.FirmwareStorage}, {"AHCI.", bmc.FirmwareStorage}, {"NonRAID.", bmc.FirmwareStorage},
		{"Disk.", bmc.FirmwareDrive}, {"Enclosure.", bmc.FirmwareEnclosure}, {"PSU.", bmc.FirmwarePSU},
		{"USC.", bmc.FirmwareLC}, {"LC.", bmc.FirmwareLC}, {"DriverPack", bmc.FirmwareLC}, {"Diagnostics", bmc.FirmwareLC},
		{"OSCollector", bmc.FirmwareLC}, {"ServiceModule", bmc.FirmwareLC},
	}
	for _, x := range prefixes {
		if strings.HasPrefix(fqdd, x.p) {
			return x.k
		}
	}
	return ""
}

// knownKind classifies the Dell component IDs whose meaning the iDRAC9 FQDDs confirm.
func knownKind(id string) bmc.FirmwareKind {
	switch id {
	case "159":
		return bmc.FirmwareBIOS
	case "25227":
		return bmc.FirmwareBMC
	case "27763":
		return bmc.FirmwareCPLD
	case "28897", "18981", "25806", "101734", "104684":
		return bmc.FirmwareLC
	default:
		return ""
	}
}

// dellKind classifies a Dell component, in order: the FQDD prefix, the known component
// IDs, DellSoftwareInventory.ComponentType, Dell words in the name (iDRAC8 has no
// FQDDs), then the generic name keywords. "" when nothing says (the merge files it
// under "other"). Any other FQDD means "other": it names a device the tables do not know.
func dellKind(componentID, fqdd, componentType, name string) bmc.FirmwareKind {
	if k := fqddKind(fqdd); k != "" {
		return k
	}
	if fqdd != "" {
		return bmc.FirmwareOther
	}
	if k := knownKind(componentID); k != "" {
		return k
	}
	switch componentType {
	case "BIOS":
		return bmc.FirmwareBIOS
	case "APAC":
		return bmc.FirmwareLC
	}
	n := strings.ToLower(name)
	for _, w := range []struct {
		word string
		kind bmc.FirmwareKind
	}{
		{"idrac", bmc.FirmwareBMC}, {"lifecycle", bmc.FirmwareLC}, {"perc", bmc.FirmwareStorage},
		{"hba", bmc.FirmwareStorage}, {"boss", bmc.FirmwareStorage}, {"bp13g", bmc.FirmwareEnclosure},
		{"bp14g", bmc.FirmwareEnclosure}, {"bp15g", bmc.FirmwareEnclosure}, {"bp16g", bmc.FirmwareEnclosure},
	} {
		if strings.Contains(n, w.word) {
			return w.kind
		}
	}
	return firmware.KindFromName(name)
}

var _ bmc.FirmwareScanner = (*Driver)(nil)
