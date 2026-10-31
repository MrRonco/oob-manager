package config

import (
	"net/url"
	"regexp"
	"slices"
	"strings"

	"oob-manager/internal/egress"
)

// Runtime-managed keys of the firmware update check (Settings › General; a key in
// config.yaml wins and locks it).
const (
	KeyCatalogEnabled    = "firmware.catalog.enabled"
	KeyCatalogCheckEvery = "firmware.catalog.check_every"
	KeyCatalogNotify     = "firmware.catalog.notify"
)

// CatalogKeys are the update check's General keys, in display order.
func CatalogKeys() []string {
	return []string{KeyCatalogEnabled, KeyCatalogCheckEvery, KeyCatalogNotify}
}

// Bounds and defaults of the update check's runtime keys.
const (
	MinCatalogCheckDays     = 1
	MaxCatalogCheckDays     = 30
	DefaultCatalogCheckDays = 7
	DefaultCatalogNotify    = "urgent"
)

// CatalogNotifyLevels are the values of firmware.catalog.notify: urgent updates only,
// every update, or none.
func CatalogNotifyLevels() []string { return []string{"urgent", "all", "off"} }

// Bounds of firmware.catalog (docs/plans/08-update-checker.md §5–8).
const (
	MaxCatalogSystems  = 200
	maxCatalogURL      = 512
	maxCatalogKeysPath = 1024
	maxCatalogNetworks = 32
)

var catalogSystemIDPattern = regexp.MustCompile(`^[0-9A-F]{4}$`)

// CatalogConfig is `firmware.catalog:`, the file-only part of the firmware update check.
// Whether the check runs, how often and what it notifies are runtime-managed (Settings ›
// General); what it may reach and whom it trusts are not browser settings: a
// browser-editable URL is an SSRF primitive and a browser-editable trust root would let
// a stolen admin session make any catalog "verified".
type CatalogConfig struct {
	// Enabled turns the online check on (runtime-managed; default off). CheckEvery is the
	// interval in days (1–30, default 7); Notify caps what is notified (urgent, all, off).
	Enabled    *bool  `yaml:"enabled"`
	CheckEvery int    `yaml:"check_every"`
	Notify     string `yaml:"notify"`
	// URL is the catalog to fetch (https only; "" = the vendor default). Its detached
	// signature is URL + ".sign".
	URL string `yaml:"url"`
	// ExtraKeysFile is a file of armored PGP public keys trusted besides the embedded
	// vendor key (key rotation, a re-signed private mirror).
	ExtraKeysFile string `yaml:"extra_keys_file"`
	// AllowedNetworks lets the fetch reach these private networks (a LAN mirror); public
	// addresses are always allowed.
	AllowedNetworks []string `yaml:"allowed_networks"`
	// AllowUnsigned accepts an unsigned catalog file uploaded by an admin or imported
	// from the CLI (Dell Repository Manager custom catalogs). The online fetch never does.
	AllowUnsigned bool `yaml:"allow_unsigned"`
	// Systems maps a server ID to its vendor system ID ("088F") when the BMC's own
	// report is missing or wrong.
	Systems map[string]string `yaml:"systems"`
}

func catalogDefaults(c CatalogConfig) CatalogConfig {
	if c.CheckEvery == 0 {
		c.CheckEvery = DefaultCatalogCheckDays
	}
	c.Notify = orDefault(c.Notify, DefaultCatalogNotify)
	return c
}

// validateCatalogGeneral checks the runtime keys (the file and the browser alike).
func validateCatalogGeneral(p problems, g General) problems {
	p = intIn(p, KeyCatalogCheckEvery, g.CatalogCheckDays, MinCatalogCheckDays, MaxCatalogCheckDays)
	if !slices.Contains(CatalogNotifyLevels(), g.CatalogNotify) {
		p = p.add("%s %q must be one of urgent, all, off", KeyCatalogNotify, g.CatalogNotify)
	}
	return p
}

func validateCatalog(p problems, c CatalogConfig) problems {
	if c.URL != "" {
		if reason := catalogURLProblem(c.URL); reason != "" {
			p = p.add("firmware.catalog.url: %s", reason)
		}
	}
	if len(c.ExtraKeysFile) > maxCatalogKeysPath || strings.ContainsRune(c.ExtraKeysFile, 0) {
		p = p.add("firmware.catalog.extra_keys_file must be a path of at most %d bytes", maxCatalogKeysPath)
	}
	if len(c.AllowedNetworks) > maxCatalogNetworks {
		p = p.add("firmware.catalog.allowed_networks holds %d entries; at most %d", len(c.AllowedNetworks), maxCatalogNetworks)
	} else if _, err := egress.ParseNetworks(c.AllowedNetworks); err != nil {
		p = p.add("firmware.catalog.allowed_networks: %v", err)
	}
	if len(c.Systems) > MaxCatalogSystems {
		p = p.add("firmware.catalog.systems holds %d entries; at most %d", len(c.Systems), MaxCatalogSystems)
	}
	for id, sys := range c.Systems {
		if !idPattern.MatchString(id) || !catalogSystemIDPattern.MatchString(sys) {
			p = p.add("firmware.catalog.systems[%q]: the key is a server ID and the value 4 upper-case hex digits (e.g. 088F)", id)
		}
	}
	return p
}

// catalogURLProblem returns why a catalog URL is refused ("" = fine): https, a host, no
// user info, no fragment, at most 512 bytes.
func catalogURLProblem(raw string) string {
	if len(raw) > maxCatalogURL {
		return "longer than 512 bytes"
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return "not a URL"
	case u.Scheme != "https":
		return "must start with https://"
	case u.Host == "" || u.Hostname() == "":
		return "has no host"
	case u.User != nil:
		return "must not carry user info"
	case u.Fragment != "" || u.RawQuery != "":
		return "must not carry a query or fragment"
	}
	return ""
}
