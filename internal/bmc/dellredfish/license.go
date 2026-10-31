package dellredfish

import (
	"context"
	"errors"
	"strings"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfish"
)

// Licence sources.
const (
	SourceLicenseService = "LicenseService"
	SourceUnavailable    = "unavailable" // no licence API (iDRAC8)
)

const maxLicenses = 16

type licenseServiceDoc struct {
	Licenses struct {
		ID string `json:"@odata.id"`
	} `json:"Licenses"`
}

type licenseDoc struct {
	Name        string `json:"Name"`
	Description string `json:"Description"`
	LicenseType string `json:"LicenseType"`
}

// licenseChoice is the best licence seen so far. On equal tiers a Production licence
// beats a Trial/Evaluation one (the R240 carries an expired Enterprise trial next to
// its perpetual Enterprise licence).
type licenseChoice struct {
	tier       bmc.LicenseTier
	desc       string
	production bool
}

func (c licenseChoice) better(tier bmc.LicenseTier, production bool) bool {
	if tier.Above(c.tier) {
		return true
	}
	return tier == c.tier && tier != bmc.LicenseUnknown && production && !c.production
}

// License reports the licence tier. iDRAC9 exposes the DMTF LicenseService; iDRAC8 has
// none, so its tier is "unknown" and GraphicalConsole (Manager.GraphicalConsole
// ServiceEnabled, which needs Enterprise on iDRAC8) is the best available hint.
func (d *Driver) License(ctx context.Context) (bmc.License, error) {
	caps, err := d.base.Capabilities(ctx)
	if err != nil {
		return bmc.License{}, err
	}
	res, err := d.base.Resources(ctx)
	if err != nil {
		return bmc.License{}, err
	}
	gc := caps.Flags().GraphicalConsole
	if res.LicenseService == "" {
		return bmc.License{Tier: bmc.LicenseUnknown, Source: SourceUnavailable, GraphicalConsole: gc}, nil
	}
	tier, desc, err := d.bestLicense(ctx, res.LicenseService)
	if err != nil {
		return bmc.License{}, err
	}
	return bmc.License{Tier: tier, Source: SourceLicenseService, Description: desc, GraphicalConsole: gc}, nil
}

func (d *Driver) bestLicense(ctx context.Context, service string) (bmc.LicenseTier, string, error) {
	uri, err := d.licensesURI(ctx, service)
	if err != nil {
		return bmc.LicenseUnknown, "", err
	}
	members, err := d.base.Members(ctx, uri)
	if errors.Is(err, bmc.ErrNotFound) {
		return bmc.LicenseUnknown, "", nil
	}
	if err != nil {
		return bmc.LicenseUnknown, "", err
	}
	best := licenseChoice{tier: bmc.LicenseUnknown}
	for i, m := range members {
		if i >= maxLicenses {
			break
		}
		var lic licenseDoc
		err := d.base.GetJSON(ctx, m, &lic)
		if errors.Is(err, bmc.ErrNotFound) {
			continue
		}
		if err != nil {
			return bmc.LicenseUnknown, "", err
		}
		prod := strings.EqualFold(lic.LicenseType, "Production")
		for _, text := range []string{lic.Description, lic.Name} {
			if t := bmc.ParseLicenseTier(text); best.better(t, prod) {
				best = licenseChoice{tier: t, desc: text, production: prod}
			}
		}
	}
	return best.tier, best.desc, nil
}

// licensesURI follows LicenseService.Licenses, falling back to the DSP0268 location.
func (d *Driver) licensesURI(ctx context.Context, service string) (string, error) {
	var doc licenseServiceDoc
	err := d.base.GetJSON(ctx, service, &doc)
	switch {
	case err == nil && doc.Licenses.ID != "":
		return doc.Licenses.ID, nil
	case err == nil || errors.Is(err, bmc.ErrNotFound):
		return service + "/Licenses", nil
	default:
		return "", err
	}
}

// compile-time check that the generic driver offers what this package relies on.
var _ interface {
	Capabilities(context.Context) (bmc.Capabilities, error)
	Resources(context.Context) (redfish.Resources, error)
} = (*redfish.Driver)(nil)
