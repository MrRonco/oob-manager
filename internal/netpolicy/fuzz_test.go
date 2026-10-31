package netpolicy

import (
	"net/netip"
	"testing"
)

// FuzzCheckBMCAddr: an accepted string re-formats to itself (no alternative spellings),
// is inside the allowlist, is not denied and is never a special-purpose address.
func FuzzCheckBMCAddr(f *testing.F) {
	for _, s := range []string{"192.0.2.10", "127.1", "0x7f.0.0.1", "010.0.0.1", "2130706433", "::ffff:192.0.2.10",
		"FD00::10", "fd00::10", "fe80::1%eth0", "169.254.169.254", "255.255.255.255", "0.0.0.0", "192.0.2.10 "} {
		f.Add(s)
	}
	p := Policy{
		Networks: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("fd00::/8"), netip.MustParsePrefix("0.0.0.0/0")},
		Deny:     []netip.Addr{netip.MustParseAddr("192.0.2.45")},
	}
	f.Fuzz(func(t *testing.T, raw string) {
		a, err := CheckBMCAddr(raw, p)
		if err != nil {
			return
		}
		switch {
		case a.String() != raw:
			t.Fatalf("accepted %q, which formats as %q", raw, a.String())
		case a.Zone() != "" || a.Is4In6() || special(a):
			t.Fatalf("accepted a special address %q", raw)
		case !p.Allows(a) || a == p.Deny[0]:
			t.Fatalf("accepted %q outside the policy", raw)
		}
	})
}
