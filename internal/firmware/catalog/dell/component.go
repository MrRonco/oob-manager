package dell

import (
	"encoding/xml"
	"fmt"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/bmc/textclean"
	"oob-manager/internal/firmware/catalog"
)

// Element paths read inside a SoftwareComponent; everything else is skipped token-wise
// (descriptions, revision history, FMP wrappers, operating systems, payloads).
const (
	pathName        = "Name/Display"
	pathType        = "ComponentType"
	pathCriticality = "Criticality"
	pathInfo        = "ImportantInfo"
	pathDevice      = "SupportedDevices/Device"
	pathPCI         = "SupportedDevices/Device/PCIInfo"
	pathBrand       = "SupportedSystems/Brand"
	pathBrandName   = "SupportedSystems/Brand/Display"
	pathModel       = "SupportedSystems/Brand/Model"
	pathModelName   = "SupportedSystems/Brand/Model/Display"
)

type pci struct{ vendor, device, subVendor, subDevice string }

type device struct {
	componentID string
	pcis        []pci
}

type model struct{ id, display string }

// component collects one SoftwareComponent while its tokens stream past.
type component struct {
	version, dateTime, releaseDate, path, reboot string
	ctype, name, criticality, details            string
	devices                                      []device
	brand, modelID, modelName                    string
	models                                       []model
	lang                                         string // lang of the Display being read
	nameBuf, brandBuf, modelBuf                  strings.Builder
}

func newComponent(attrs []xml.Attr) *component {
	return &component{
		version: attr(attrs, "vendorVersion"), dateTime: attr(attrs, "dateTime"),
		releaseDate: attr(attrs, "releaseDate"), path: attr(attrs, "path"), reboot: attr(attrs, "rebootRequired"),
	}
}

func (c *component) start(path string, attrs []xml.Attr, lim catalog.Limits) error {
	switch path {
	case pathType:
		c.ctype = attr(attrs, "value")
	case pathCriticality:
		c.criticality = attr(attrs, "value")
	case pathInfo:
		c.details = attr(attrs, "URL")
	case pathDevice:
		if len(c.devices) >= lim.MaxDevices {
			return fmt.Errorf("%w: more than %d devices in a component", catalog.ErrSize, lim.MaxDevices)
		}
		c.devices = append(c.devices, device{componentID: attr(attrs, "componentID")})
	case pathPCI:
		d := &c.devices[len(c.devices)-1]
		if len(d.pcis) >= lim.MaxPCI {
			return fmt.Errorf("%w: more than %d PCI identities in a device", catalog.ErrSize, lim.MaxPCI)
		}
		d.pcis = append(d.pcis, pci{attr(attrs, "vendorID"), attr(attrs, "deviceID"), attr(attrs, "subVendorID"), attr(attrs, "subDeviceID")})
	case pathBrand:
		c.brand = ""
		c.brandBuf.Reset()
	case pathModel:
		if len(c.models) >= lim.MaxModels {
			return fmt.Errorf("%w: more than %d models in a component", catalog.ErrSize, lim.MaxModels)
		}
		c.modelID = attr(attrs, "systemID")
		c.modelBuf.Reset()
	case pathName, pathBrandName, pathModelName:
		c.lang = attr(attrs, "lang")
	}
	return nil
}

// text receives character data at path; only English Display text is kept.
func (c *component) text(path, s string) {
	if c.lang != "" && c.lang != "en" {
		return
	}
	switch path {
	case pathName:
		c.nameBuf.WriteString(s)
	case pathBrandName:
		c.brandBuf.WriteString(s)
	case pathModelName:
		c.modelBuf.WriteString(s)
	}
}

func (c *component) end(path string) {
	switch path {
	case pathName:
		if c.name == "" {
			c.name = textclean.Clean(c.nameBuf.String(), maxName)
		}
		c.lang = ""
	case pathBrandName:
		c.brand = textclean.Clean(c.brandBuf.String(), maxName)
		c.lang = ""
	case pathModelName:
		c.modelName = textclean.Clean(c.modelBuf.String(), maxName)
		c.lang = ""
	case pathModel:
		id := strings.ToUpper(strings.TrimSpace(c.modelID))
		if systemIDPattern.MatchString(id) { // a malformed system ID drops that model only
			c.models = append(c.models, model{id: id, display: strings.TrimSpace(c.brand + " " + c.modelName)})
		}
		c.modelID, c.modelName = "", ""
	}
}

// release is the component as a Release; false skips it (not firmware, or no usable
// version or criticality).
func (c *component) release() (catalog.Release, bool) {
	if !firmwareTypes[c.ctype] {
		return catalog.Release{}, false
	}
	version := textclean.Clean(c.version, maxVersion)
	crit, err := strconv.Atoi(strings.TrimSpace(c.criticality))
	if version == "" || version != strings.TrimSpace(c.version) || err != nil || !catalog.Criticality(crit).Valid() {
		return catalog.Release{}, false
	}
	return catalog.Release{
		Version: version, Date: c.date(), Criticality: catalog.Criticality(crit), Name: c.name,
		PackagePath: textclean.Clean(c.path, maxPath), DetailsURL: textclean.Clean(c.details, maxURL),
		RebootRequired: c.reboot == "true",
	}, true
}

// date is dateTime (RFC 3339), else releaseDate ("September 24, 2026"), else zero.
func (c *component) date() time.Time {
	if t, err := time.Parse(time.RFC3339, c.dateTime); err == nil {
		return t.UTC()
	}
	if t, err := time.Parse("January 2, 2006", strings.TrimSpace(c.releaseDate)); err == nil {
		return t.UTC()
	}
	return time.Time{}
}

// variants expands the devices into one catalog.Device per PCI identity (or one without
// PCI). Devices whose identifiers fail validation are dropped.
func (c *component) variants() []catalog.Device {
	var out []catalog.Device
	for _, d := range c.devices {
		cid := strings.TrimSpace(d.componentID)
		if !componentIDPat.MatchString(cid) {
			continue
		}
		if len(d.pcis) == 0 {
			out = append(out, catalog.Device{ComponentID: cid})
			continue
		}
		for _, p := range d.pcis {
			if !validPCI(p) {
				continue
			}
			out = append(out, catalog.Device{ComponentID: cid, VendorID: strings.ToUpper(p.vendor),
				DeviceID: strings.ToUpper(p.device), SubVendorID: strings.ToUpper(p.subVendor),
				SubDeviceID: strings.ToUpper(p.subDevice)})
		}
	}
	return out
}

func validPCI(p pci) bool {
	for _, v := range []string{p.vendor, p.device, p.subVendor, p.subDevice} {
		if v != "" && !hexIDPattern.MatchString(v) {
			return false
		}
	}
	return p.vendor != "" && p.device != ""
}
