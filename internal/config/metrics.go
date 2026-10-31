package config

import (
	"net/netip"
	"strings"
)

// MetricsConfig is the `metrics:` section (tech_doc §29). It is file-only: the scrape
// endpoint and who may reach it are not changeable from a browser session.
type MetricsConfig struct {
	// Enabled mounts GET /metrics (default false: the path answers 404).
	Enabled bool `yaml:"enabled"`
	// AllowNetworks lists CIDRs (or single IPs) that may scrape. Empty allows any
	// client address; a read-only API token is required either way.
	AllowNetworks []string `yaml:"allow_networks"`
	// IncludeInventory adds model, serial, service tag, BIOS and BMC firmware and the
	// licence tier as labels of oob_server_info (default false: no identifiers).
	IncludeInventory bool `yaml:"include_inventory"`
}

// Networks returns the parsed allowlist (single IPs become /32 or /128 prefixes).
// It assumes a validated config and skips anything unparsable.
func (m MetricsConfig) Networks() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range m.AllowNetworks {
		if p, ok := parseNetwork(s); ok {
			out = append(out, p)
		}
	}
	return out
}

func parseNetwork(s string) (netip.Prefix, bool) {
	if !validNetwork(s) {
		return netip.Prefix{}, false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err == nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), true
}

func validateMetrics(p problems, m MetricsConfig) problems {
	for _, s := range m.AllowNetworks {
		if !validNetwork(s) {
			p = p.add("metrics.allow_networks: %q is not an IP address or CIDR", s)
		}
	}
	return p
}
