package config

import (
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"oob-manager/internal/bmc"
	"oob-manager/internal/firmware"
)

// Firmware view bounds (docs/tech_doc.md §38).
const (
	MaxFirmwareRules = 200
	MaxFirmwareNames = 200
	maxStaleYears    = 50
)

// FirmwareConfig is the `firmware:` section of the read-only firmware view. It is
// file-only, like security.min_firmware: which versions are acceptable is not a browser
// setting. The BMC's own minimum is NOT here: it is security.min_firmware (one source of
// truth, shared with the fw.bmc security check), so a minimum rule may not use kind bmc.
type FirmwareConfig struct {
	// StaleAfter flags releases older than this ("3y", "400d" or a Go duration; "" or
	// "0": off, the default). Age is information, not a verdict.
	StaleAfter string `yaml:"stale_after"`
	// Names are display names per component ID for components no member document names.
	Names map[string]string `yaml:"names"`
	// Minimum are the "minimum known good" rules (at most MaxFirmwareRules).
	Minimum []FirmwareRule `yaml:"minimum"`
	// Catalog is the file-only part of the vendor update check (CatalogConfig).
	Catalog CatalogConfig `yaml:"catalog"`
}

// FirmwareRule is one firmware.minimum entry. Every key that is set must match; at
// least one is required. fqdd may end in "*" (prefix match).
type FirmwareRule struct {
	BMCKind     string `yaml:"bmc_kind"`
	Kind        string `yaml:"kind"`
	Model       string `yaml:"model"`
	ComponentID string `yaml:"component_id"`
	FQDD        string `yaml:"fqdd"`
	Version     string `yaml:"version"`
	Note        string `yaml:"note"`
}

var (
	firmwareIDPattern   = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	firmwareFQDDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,127}\*?$`)
	staleDays           = regexp.MustCompile(`^([0-9]{1,5})(y|d)$`)
)

// StaleAge is stale_after as a duration (0: off; an invalid value is refused at load).
func (f FirmwareConfig) StaleAge() time.Duration {
	d, _ := parseStaleAfter(f.StaleAfter)
	return d
}

func parseStaleAfter(s string) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, true
	}
	if m := staleDays.FindStringSubmatch(s); m != nil {
		n, _ := strconv.Atoi(m[1])
		day := 24 * time.Hour
		if m[2] == "y" {
			return time.Duration(n) * firmware.Year, n <= maxStaleYears
		}
		return time.Duration(n) * day, n <= maxStaleYears*365
	}
	d, err := time.ParseDuration(s)
	return d, err == nil && d > 0 && d <= maxStaleYears*firmware.Year
}

func validateFirmware(p problems, f FirmwareConfig) problems {
	if _, ok := parseStaleAfter(f.StaleAfter); !ok {
		p = p.add("firmware.stale_after %q must be 0, <years>y, <days>d or a duration, at most %dy", f.StaleAfter, maxStaleYears)
	}
	if len(f.Names) > MaxFirmwareNames {
		p = p.add("firmware.names holds %d entries; at most %d", len(f.Names), MaxFirmwareNames)
	}
	for id, name := range f.Names {
		if !firmwareIDPattern.MatchString(id) || !plainText(name, 1, 128) {
			p = p.add("firmware.names[%q]: the key is a component ID and the name 1-128 characters of plain text", id)
		}
	}
	p = validateCatalog(p, f.Catalog)
	if len(f.Minimum) > MaxFirmwareRules {
		return p.add("firmware.minimum holds %d rules; at most %d", len(f.Minimum), MaxFirmwareRules)
	}
	for i, r := range f.Minimum {
		p = validateFirmwareRule(p, i, r)
	}
	return p
}

func validateFirmwareRule(p problems, i int, r FirmwareRule) problems {
	at := "firmware.minimum[" + strconv.Itoa(i) + "]"
	if r.BMCKind == "" && r.Kind == "" && r.Model == "" && r.ComponentID == "" && r.FQDD == "" {
		p = p.add("%s needs at least one of bmc_kind, kind, model, component_id, fqdd", at)
	}
	switch BMCKind(r.BMCKind) {
	case "", KindIDRAC8, KindIDRAC9, KindRedfish:
	default:
		p = p.add("%s.bmc_kind %q must be idrac8, idrac9 or redfish", at, r.BMCKind)
	}
	if k, ok := bmc.ParseFirmwareKind(r.Kind); r.Kind != "" && !ok {
		p = p.add("%s.kind %q is not a firmware kind", at, r.Kind)
	} else if k == bmc.FirmwareBMC {
		p = p.add("%s.kind bmc: set the BMC's own minimum in security.min_firmware.<kind> (one source of truth)", at)
	}
	if r.Model != "" && !plainText(r.Model, 1, 128) {
		p = p.add("%s.model must be 1-128 characters of plain text", at)
	}
	if r.ComponentID != "" && !firmwareIDPattern.MatchString(r.ComponentID) {
		p = p.add("%s.component_id %q must be 1-128 of A-Z a-z 0-9 . _ : -", at, r.ComponentID)
	}
	if r.FQDD != "" && !firmwareFQDDPattern.MatchString(r.FQDD) {
		p = p.add("%s.fqdd %q: a device descriptor, optionally ending in * (prefix match)", at, r.FQDD)
	}
	if bmcOnlyRule(r) {
		p = p.add("%s matches only the BMC's own firmware, which firmware.minimum never judges: set "+
			"security.min_firmware.<kind> instead (one source of truth)", at)
	}
	if _, ok := firmware.CompareVersions(r.Version, r.Version); !ok || len(r.Version) > 64 {
		p = p.add("%s.version %q must be a firmware version such as 2.20.0 (letters and digits between dots)", at, r.Version)
	}
	if r.Note != "" && !plainText(r.Note, 1, 200) {
		p = p.add("%s.note must be at most 200 characters of plain text", at)
	}
	return p
}

// plainText: n bytes in [lo, hi], no control or format characters.
func plainText(s string, lo, hi int) bool {
	if len(s) < lo || len(s) > hi {
		return false
	}
	return !strings.ContainsFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) })
}

// bmcOnlyRule reports a rule that names the Dell iDRAC's own firmware (component 25227, an
// iDRAC. FQDD): the view judges that row by security.min_firmware only (review C-L2).
func bmcOnlyRule(r FirmwareRule) bool {
	return r.ComponentID == "25227" || strings.HasPrefix(r.FQDD, "iDRAC.")
}
