// Package egress is the outbound destination policy shared by everything that reaches
// beyond the BMC network: notification targets (tech_doc §26) and the firmware vendor
// catalog (plan 08 §6.1). A host name is resolved once, every answer must pass the
// policy, and the connection goes to the checked address, so a DNS rebinding answer can
// never be dialled. Messages name the rule, never the resolved addresses.
package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

// ErrBlocked is returned when a destination fails the policy. Its message names the
// rule, never the resolved addresses.
var ErrBlocked = errors.New("egress: destination not allowed")

// DNSError is a host name that did not resolve (or resolved to nothing).
type DNSError struct{ msg string }

func (e *DNSError) Error() string { return e.msg }

// Resolver looks up a host name. *net.Resolver satisfies it; tests use a fake to
// simulate DNS rebinding.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Policy is one outbound destination policy (for example notifications.allowed_networks).
//
//   - An address inside Allowed is always permitted (this is how LAN destinations, such
//     as a self-hosted ntfy, a mail relay or a catalog mirror, are enabled).
//   - Otherwise only public unicast addresses are permitted, and only over TLS.
//   - Plaintext (http, SMTP without TLS) is only ever permitted to Allowed addresses.
//   - A host name is resolved once; if ANY answer is not permitted the destination is
//     refused, and the connection goes to the checked address (no second lookup, so a
//     DNS rebinding answer can never be dialled).
type Policy struct {
	Allowed  []netip.Prefix
	Resolver Resolver
	// Setting is the config key of Allowed, named in refusals ("" = "the allowed networks").
	Setting string
}

func (p Policy) setting() string {
	if p.Setting == "" {
		return "the allowed networks"
	}
	return p.Setting
}

// ParseNetworks parses CIDRs or single IPs ("192.0.2.7" = /32).
func ParseNetworks(items []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(items))
	for _, s := range items {
		p, err := parseNetwork(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func parseNetwork(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil || p.Addr().Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("egress: %q is not a CIDR", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("egress: %q is not an IP address or CIDR", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Resolve checks host and returns the one address to dial. plaintext reports a
// connection without TLS, which only an Allowed address may receive.
func (p Policy) Resolve(ctx context.Context, host string, plaintext bool) (netip.Addr, error) {
	if host == "" {
		return netip.Addr{}, fmt.Errorf("%w: empty host", ErrBlocked)
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if a.Zone() != "" {
			return netip.Addr{}, fmt.Errorf("%w: zoned addresses are not allowed", ErrBlocked)
		}
		return a.Unmap(), p.Permit(a.Unmap(), plaintext)
	}
	if !ValidHostname(host) {
		return netip.Addr{}, fmt.Errorf("%w: invalid host name", ErrBlocked)
	}
	addrs, err := p.lookup(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if err := p.Permit(a.Unmap(), plaintext); err != nil {
			return netip.Addr{}, err
		}
	}
	return addrs[0].Unmap(), nil
}

func (p Policy) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	r := p.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, &DNSError{msg: "egress: host name did not resolve"}
	}
	if len(addrs) == 0 {
		return nil, &DNSError{msg: "egress: host name has no addresses"}
	}
	return addrs, nil
}

// Permit applies the policy to one address.
func (p Policy) Permit(a netip.Addr, plaintext bool) error {
	for _, n := range p.Allowed {
		if n.Contains(a) {
			return nil
		}
	}
	if plaintext {
		return fmt.Errorf("%w: plaintext is only allowed to %s", ErrBlocked, p.setting())
	}
	if !PublicUnicast(a) {
		return fmt.Errorf("%w: private, local or reserved address (add it to %s)", ErrBlocked, p.setting())
	}
	return nil
}

// specialPurpose lists non-public ranges that netip's predicates do not cover.
var specialPurpose = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),   // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, incl. broadcast
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 (can embed a private IPv4)
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("2002::/16"),       // 6to4 (can embed a private IPv4)
	netip.MustParsePrefix("100::/64"),        // discard
	netip.MustParsePrefix("::/96"),           // IPv4-compatible (deprecated; can embed any IPv4)
	netip.MustParsePrefix("fec0::/10"),       // site-local (deprecated, RFC 3879)
	netip.MustParsePrefix("2001::/32"),       // Teredo (embeds an obfuscated IPv4)
	netip.MustParsePrefix("2001:2::/48"),     // benchmarking
	netip.MustParsePrefix("2001:10::/28"),    // ORCHID (deprecated)
	netip.MustParsePrefix("2001:20::/28"),    // ORCHIDv2
	netip.MustParsePrefix("3fff::/20"),       // documentation (RFC 9637)
	netip.MustParsePrefix("5f00::/16"),       // SRv6 SIDs
	netip.MustParsePrefix("::ffff:0:0:0/96"), // IPv4/IPv6 translation (RFC 2765)
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast (deprecated)
}

// PublicUnicast reports a globally routable unicast address. An IPv4-mapped IPv6
// address is judged as the IPv4 address it carries.
func PublicUnicast(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsUnspecified() || a.IsMulticast() ||
		a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() {
		return false
	}
	for _, n := range specialPurpose {
		if n.Contains(a) {
			return false
		}
	}
	return true
}

// ValidHostname accepts LDH labels only (no IDN tricks, no trailing junk).
func ValidHostname(h string) bool {
	h = strings.TrimSuffix(h, ".")
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if !validLabel(label) {
			return false
		}
	}
	return true
}

func validLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for _, r := range l {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}
