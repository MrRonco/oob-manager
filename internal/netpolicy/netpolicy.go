// Package netpolicy decides which addresses may be a BMC (settings_design.md §3, BMC
// address policy). An address typed in the browser becomes a destination the app dials
// (fingerprint fetch, test connection, polling), so it is checked strictly: an IP literal
// in its one canonical spelling, never a special-purpose range or the app itself, and
// inside the settings.bmc_networks allowlist. Hostnames are never accepted (decision 3).
package netpolicy

import (
	"errors"
	"net/netip"
	"slices"
)

// Errors. Each wraps into an *Error whose Reason is safe to show to an admin.
var (
	ErrNotIP        = errors.New("netpolicy: not an IP address literal")
	ErrZone         = errors.New("netpolicy: IPv6 zone not allowed")
	ErrMapped       = errors.New("netpolicy: IPv4-mapped IPv6 address not allowed")
	ErrNotCanonical = errors.New("netpolicy: address not in canonical form")
	ErrSpecial      = errors.New("netpolicy: special-purpose address")
	ErrSelf         = errors.New("netpolicy: the app's own address")
	ErrOutside      = errors.New("netpolicy: outside the allowed networks")
)

// Error is a refused address with an admin-facing reason.
type Error struct {
	kind   error
	reason string
}

func (e *Error) Error() string { return e.kind.Error() + ": " + e.reason }

// Unwrap makes errors.Is(err, ErrOutside) and friends work.
func (e *Error) Unwrap() error { return e.kind }

// Reason is the sentence for the form ("the address is outside settings.bmc_networks").
func (e *Error) Reason() string { return e.reason }

func refuse(kind error, reason string) error { return &Error{kind: kind, reason: reason} }

// Policy is the allowlist (settings.bmc_networks) and the addresses that are always
// refused (the app's own listen addresses).
type Policy struct {
	Networks []netip.Prefix
	Deny     []netip.Addr
}

// Allows reports whether addr is inside one of the allowed networks.
func (p Policy) Allows(addr netip.Addr) bool {
	return slices.ContainsFunc(p.Networks, func(n netip.Prefix) bool { return n.Contains(addr) })
}

// CheckBMCAddr parses raw and applies the policy. It returns the parsed address only
// when every rule passes: no alternative spellings (127.1, 0x7f.1, 2130706433,
// 010.0.0.1, upper-case or expanded IPv6), no zone, no IPv4-mapped IPv6, no loopback,
// unspecified, multicast, link-local (incl. 169.254.169.254) or broadcast address, not
// one of p.Deny, and inside p.Networks.
func CheckBMCAddr(raw string, p Policy) (netip.Addr, error) {
	addr, err := netip.ParseAddr(raw)
	switch {
	case err != nil:
		return netip.Addr{}, refuse(ErrNotIP, "enter an IP address such as 192.0.2.10 or fd00::10 (no host names)")
	case addr.Zone() != "":
		return netip.Addr{}, refuse(ErrZone, "IPv6 zones (%eth0) are not allowed")
	case addr.Is4In6():
		return netip.Addr{}, refuse(ErrMapped, "write an IPv4 address in dotted form, not as ::ffff:…")
	case addr.String() != raw:
		return netip.Addr{}, refuse(ErrNotCanonical, "write the address as "+addr.String())
	}
	if special(addr) {
		return netip.Addr{}, refuse(ErrSpecial, "loopback, link-local, multicast, broadcast and unspecified addresses cannot be a BMC")
	}
	if slices.Contains(p.Deny, addr) {
		return netip.Addr{}, refuse(ErrSelf, "this is the console's own address")
	}
	if !p.Allows(addr) {
		return netip.Addr{}, refuse(ErrOutside, "the address is outside settings.bmc_networks")
	}
	return addr, nil
}

// special reports the special-purpose ranges a BMC can never be in.
func special(a netip.Addr) bool {
	return a.IsLoopback() || a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a == netip.IPv4Unspecified() ||
		a == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}
