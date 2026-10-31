package redfish

import (
	"context"
	"path"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/textclean"
	"oob-manager/internal/firmware"
)

// Firmware scan bounds (docs/tech_doc.md §38). BMC strings are cleaned and capped.
const (
	// MaxFirmwareMembers caps the members one scan considers (the inventory's cap).
	MaxFirmwareMembers = bmc.MaxFirmwareMembers
	maxNameLen         = 128
	maxVersionLen      = 64
	maxIdentityLen     = 128
)

// FirmwareDocument is the part of a SoftwareInventory member document the firmware view
// reads. Vendor drivers embed it to decode their OEM block from the same GET.
type FirmwareDocument struct {
	ID          string `json:"Id"`
	Name        string `json:"Name"`
	Version     string `json:"Version"`
	Updateable  *bool  `json:"Updateable"`
	ReleaseDate string `json:"ReleaseDate"`
	RelatedItem []struct {
		ID string `json:"@odata.id"`
	} `json:"RelatedItem"`
}

// Apply fills it from the document: the cleaned name (Named when it has one), release
// date, updateable flag and, when it has none, a kind from RelatedItem or the name.
func (doc FirmwareDocument) Apply(it bmc.FirmwareItem) bmc.FirmwareItem {
	it.Detailed = true
	if n := textclean.Clean(doc.Name, maxNameLen); n != "" {
		it.Name, it.Named = n, true
	}
	if t, err := time.Parse(time.RFC3339, doc.ReleaseDate); err == nil {
		it.ReleaseDate = t.UTC()
	}
	it.Updateable = doc.Updateable != nil && *doc.Updateable
	for _, r := range doc.RelatedItem {
		if it.Kind == "" {
			it.Kind = firmware.KindFromRelated(r.ID)
		}
	}
	if it.Kind == "" && it.Named {
		it.Kind = firmware.KindFromName(it.Name)
	}
	return it
}

// CleanVersion is a BMC version string as stored (cleaned, at most 64 bytes).
func CleanVersion(v string) string { return textclean.Clean(v, maxVersionLen) }

// CleanIdentity is a catalog identity as stored (cleaned, at most 128 bytes).
func CleanIdentity(v string) string { return textclean.Clean(v, maxIdentityLen) }

// FirmwareMembers lists the FirmwareInventory collection: at most MaxFirmwareMembers
// member URIs and the count the BMC reports (Members@odata.count, else the list
// length). An absent collection is empty.
func (d *Driver) FirmwareMembers(ctx context.Context) ([]string, int, error) {
	disc, err := d.discovered(ctx)
	if err != nil {
		return nil, 0, err
	}
	col, _, err := optional[collectionDoc](ctx, d, disc.res.FirmwareInventory)
	if err != nil {
		return nil, 0, err
	}
	uris := col.uris()
	listed := len(uris)
	if col.Count != nil && *col.Count > listed {
		listed = *col.Count
	}
	if len(uris) > MaxFirmwareMembers {
		uris = uris[:MaxFirmwareMembers]
	}
	return uris, listed, nil
}

// ScanFirmware implements bmc.FirmwareScanner for any Redfish BMC: every member
// document is read (the items exist only through them), so need is not consulted.
// A missing or unreadable document leaves that member out and the scan incomplete (a
// later scan must not take it for removed). Only GETs are sent.
func (d *Driver) ScanFirmware(ctx context.Context, _ func(bmc.FirmwareItem) bool) (bmc.FirmwareScan, error) {
	uris, listed, err := d.FirmwareMembers(ctx)
	if err != nil {
		return bmc.FirmwareScan{}, err
	}
	complete := len(uris) == listed
	var items []bmc.FirmwareItem
	read, failed := 0, 0
	for _, m := range uris {
		var doc FirmwareDocument
		err := d.GetJSON(ctx, m, &doc)
		if ctx.Err() != nil {
			complete = false
			break
		}
		if err != nil {
			complete = false
			if !isAbsent(err) {
				failed++
			}
			continue
		}
		read++
		id := clean(doc.ID)
		if id == "" {
			id = path.Base(m)
		}
		items = append(items, doc.Apply(bmc.FirmwareItem{ID: id, Version: CleanVersion(doc.Version)}))
	}
	return bmc.NewFirmwareScan(items, listed, complete).WithDocs(read, failed), nil
}

var _ bmc.FirmwareScanner = (*Driver)(nil)
