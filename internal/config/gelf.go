package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Runtime-managed Integrations keys (Settings → Integrations, tech_doc §34). Unlike the
// General keys they are not their own config.yaml paths: FilePath maps them.
const (
	KeyGELFEnabled    = "gelf.enabled"
	KeyGELFAddress    = "gelf.address"
	KeyGELFTransport  = "gelf.transport"
	KeyGELFServerName = "gelf.server_name"
	KeyGELFPin        = "gelf.pin_sha256"
)

// GELF transports. UDP is deliberately not offered (no delivery signal, no TLS).
const (
	TransportTCP = "tcp"
	TransportTLS = "tls"
)

// IntegrationKeys returns the Integrations section's keys in display order (fresh slice).
func IntegrationKeys() []string {
	return []string{KeyGELFEnabled, KeyGELFAddress, KeyGELFTransport, KeyGELFServerName, KeyGELFPin}
}

// FilePath is the config.yaml path that sets a runtime-managed key. General keys are
// their own path; the GELF keys live under audit.gelf, and "enabled" is a non-empty
// audit.gelf.address.
func FilePath(key string) string {
	switch key {
	case KeyGELFEnabled:
		return "audit.gelf.address"
	case KeyGELFAddress, KeyGELFTransport, KeyGELFServerName, KeyGELFPin:
		return "audit." + key
	default:
		return key
	}
}

// GELF is the audit shipping target: one value per IntegrationKeys entry.
type GELF struct {
	Enabled    bool
	Address    string // host:port; host an IP literal or a DNS name
	Transport  string // TransportTCP or TransportTLS
	ServerName string // TLS SNI; "" sends the host when it is a name
	PinSHA256  string // SPKI SHA-256 (hex) of the leaf or an issuing CA; required for tls
}

// GELF returns the file's GELF target. An empty address means the file does not set
// a target at all: the defaults apply to every key (the browser may set them).
func (c Config) GELF() GELF {
	g := c.Audit.GELF
	if g.Address == "" {
		return GELF{Transport: TransportTCP}
	}
	return GELF{Enabled: g.Address != "", Address: g.Address, Transport: orDefault(g.Transport, TransportTCP),
		ServerName: g.ServerName, PinSHA256: strings.ToLower(g.PinSHA256)}
}

// DefaultGELFNetworks is where a GELF server may be when audit.gelf.allowed_networks is
// not set: the private ranges (RFC 1918 and ULA), because log servers live on the LAN.
func DefaultGELFNetworks() []netip.Prefix {
	return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("fc00::/7")}
}

// GELFNetworks returns audit.gelf.allowed_networks as masked prefixes (single IPs as /32
// or /128), or the defaults when the key is absent. The config is validated, so every
// entry parses.
func (c Config) GELFNetworks() []netip.Prefix {
	list := c.Audit.GELF.AllowedNetworks
	if list == nil {
		return DefaultGELFNetworks()
	}
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		if p, ok := parseNetwork(s); ok {
			out = append(out, p)
		}
	}
	return out
}

// GELFAddrAllowed applies the static part of the GELF destination policy to one
// address: never loopback, unspecified, link-local, multicast, broadcast or an
// IPv4-mapped form, and inside nets. (The integrations service also refuses the app's
// own listen endpoints and checks every DNS answer when it dials.)
func GELFAddrAllowed(a netip.Addr, nets []netip.Prefix) error {
	switch {
	case !a.IsValid() || a.Zone() != "" || a.Is4In6():
		return fmt.Errorf("%s is not a plain IP address", a)
	case a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsMulticast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return fmt.Errorf("%s is a loopback, link-local, multicast, broadcast or unspecified address", a)
	}
	for _, n := range nets {
		if n.Contains(a) {
			return nil
		}
	}
	return fmt.Errorf("%s is outside audit.gelf.allowed_networks (add its range there, for example %s)", a,
		netip.PrefixFrom(a, a.BitLen()))
}

// ValidateGELF checks g's shape. The same function validates config.yaml and values
// saved from the browser; messages name the config.yaml keys. A disabled target is a
// draft: its fields are shape-checked, but an address and a TLS pin are only required
// once it is enabled.
func ValidateGELF(g GELF) []string {
	var p problems
	if g.Address == "" && g.Enabled {
		p = p.add("audit.gelf.address is required to ship audit rows")
	}
	if g.Address != "" {
		p = validateGELFAddress(p, g.Address)
	}
	if g.Transport != "" && g.Transport != TransportTCP && g.Transport != TransportTLS {
		p = p.add("audit.gelf.transport %q must be tcp or tls (UDP is not supported)", g.Transport)
	}
	if g.ServerName != "" && !validDNSName(g.ServerName) {
		p = p.add("audit.gelf.server_name %q must be a DNS name", g.ServerName)
	}
	if g.PinSHA256 != "" && !validPin(g.PinSHA256) {
		p = p.add("audit.gelf.pin_sha256 must be 64 lower-case hex digits")
	}
	if g.Enabled && g.Transport == TransportTLS && g.PinSHA256 == "" {
		p = p.add("audit.gelf.pin_sha256 is required with transport tls (the pin is the only trust anchor)")
	}
	return p
}

func validateGELFAddress(p problems, addr string) problems {
	host, port, err := net.SplitHostPort(addr)
	n, perr := strconv.Atoi(port)
	switch {
	case err != nil || host == "":
		return p.add("audit.gelf.address %q must be host:port", addr)
	case perr != nil || strings.TrimLeft(port, "0123456789") != "" || n < 1 || n > 65535:
		return p.add("audit.gelf.address %q: the port must be 1 to 65535", addr)
	}
	if a, aerr := netip.ParseAddr(host); aerr == nil {
		if a.Zone() != "" {
			return p.add("audit.gelf.address %q: IPv6 zones are not allowed", addr)
		}
		return p
	}
	if !validHostName(host) {
		p = p.add("audit.gelf.address %q: the host must be an IP address or a DNS name", addr)
	}
	return p
}

func validPin(s string) bool {
	if len(s) != 64 {
		return false
	}
	return strings.Trim(s, "0123456789abcdef") == ""
}

// validHostName is validDNSName that also accepts "_" in labels: container and service
// names (Docker Compose, some internal DNS) carry it and resolvers answer for them. It
// is only a name to resolve (every answer is checked); TLS names stay LDH (server_name).
func validHostName(h string) bool {
	return validDNSName(strings.ReplaceAll(h, "_", "x"))
}

// validDNSName accepts LDH labels (no IP literals, no IDN tricks), at most 253 chars.
func validDNSName(h string) bool {
	if _, err := netip.ParseAddr(h); err == nil {
		return false
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" || len(h) > 253 {
		return false
	}
	for _, l := range strings.Split(h, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' ||
			strings.Trim(strings.ToLower(l), "abcdefghijklmnopqrstuvwxyz0123456789-") != "" {
			return false
		}
	}
	return true
}

// validateAudit checks the file's GELF target, its allowed networks and, for an IP
// literal address, the static destination policy.
func validateAudit(p problems, a AuditConfig) problems {
	for _, n := range a.GELF.AllowedNetworks {
		pfx, ok := parseNetwork(n)
		switch {
		case !ok:
			p = p.add("audit.gelf.allowed_networks: %q is not an IP address or CIDR", n)
		case pfx.Bits() == 0:
			p = p.add("audit.gelf.allowed_networks %q would allow every address", n)
		}
	}
	// The raw fields are shape-checked even without an address (a typo must not load);
	// they apply only with one.
	raw := GELF{Enabled: a.GELF.Address != "", Address: a.GELF.Address,
		Transport: orDefault(a.GELF.Transport, TransportTCP), ServerName: a.GELF.ServerName,
		PinSHA256: strings.ToLower(a.GELF.PinSHA256)}
	p = append(p, ValidateGELF(raw)...)
	g := Config{Audit: a}.GELF()
	if !g.Enabled {
		return p
	}
	host, _, err := net.SplitHostPort(g.Address)
	if err != nil {
		return p
	}
	if addr, aerr := netip.ParseAddr(host); aerr == nil && len(p) == 0 {
		if perr := GELFAddrAllowed(addr, Config{Audit: a}.GELFNetworks()); perr != nil {
			p = p.add("audit.gelf.address: %v", perr)
		}
	}
	return p
}
