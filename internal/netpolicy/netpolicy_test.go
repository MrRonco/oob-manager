package netpolicy

// repopolicy:allow private-addresses -- tests which BMC addresses the RFC 1918 default of bmc_networks admits

import (
	"errors"
	"net/netip"
	"testing"
)

func policy() Policy {
	return Policy{
		Networks: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.0.2.0/24"),
			netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
			netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("255.255.255.0/24")},
		Deny: []netip.Addr{netip.MustParseAddr("192.0.2.45")},
	}
}

func TestCheckBMCAddrAccepts(t *testing.T) {
	for _, raw := range []string{"10.20.30.40", "192.0.2.12", "fd00::50", "fd12:3456::1"} {
		got, err := CheckBMCAddr(raw, policy())
		if err != nil || got.String() != raw {
			t.Errorf("%q: %v %v", raw, got, err)
		}
	}
}

// TestCheckBMCAddrHostile is the design's hostile table (settings_design.md §5): every
// alternative spelling of an address, every special-purpose range and anything outside
// the allowlist is refused, even when the allowlist itself would contain it.
func TestCheckBMCAddrHostile(t *testing.T) {
	cases := map[string]error{
		"":                      ErrNotIP,
		"127.1":                 ErrNotIP,
		"0x7f.1":                ErrNotIP,
		"0x7f000001":            ErrNotIP,
		"2130706433":            ErrNotIP,
		"010.0.0.1":             ErrNotIP,
		"10.0.0.1 ":             ErrNotIP,
		"bmc.example.test":      ErrNotIP,
		"localhost":             ErrNotIP,
		"10.0.0.1:443":          ErrNotIP,
		"[fd00::1]":             ErrNotIP,
		"http://10.0.0.1":       ErrNotIP,
		"fe80::1%eth0":          ErrZone,
		"::ffff:127.0.0.1":      ErrMapped,
		"::ffff:10.0.0.1":       ErrMapped,
		"FD00::1":               ErrNotCanonical,
		"fd00:0::1":             ErrNotCanonical,
		"127.0.0.1":             ErrSpecial,
		"::1":                   ErrSpecial,
		"0.0.0.0":               ErrSpecial,
		"::":                    ErrSpecial,
		"169.254.169.254":       ErrSpecial,
		"169.254.1.1":           ErrSpecial,
		"fe80::1":               ErrSpecial,
		"224.0.0.1":             ErrSpecial,
		"ff02::1":               ErrSpecial,
		"255.255.255.255":       ErrSpecial,
		"192.0.2.45":            ErrSelf,
		"8.8.8.8":               ErrOutside,
		"172.16.0.1":            ErrOutside,
		"2001:db8::1":           ErrOutside,
		"10.0.0.1\n":            ErrNotIP,
		"10.0.0.1/32":           ErrNotIP,
		"1.2.3.4.5":             ErrNotIP,
		"[::ffff:7f00:1]":       ErrNotIP,
		"::ffff:7f00:1":         ErrMapped,
		"0:0:0:0:0:ffff:7f00:1": ErrMapped,
	}
	for raw, want := range cases {
		if _, err := CheckBMCAddr(raw, policy()); !errors.Is(err, want) {
			t.Errorf("%q: err = %v, want %v", raw, err, want)
		}
	}
}

func TestEmptyAllowlistRefusesEverything(t *testing.T) {
	if _, err := CheckBMCAddr("10.0.0.1", Policy{}); !errors.Is(err, ErrOutside) {
		t.Fatalf("err = %v", err)
	}
}

func TestErrorsAreShowable(t *testing.T) {
	_, err := CheckBMCAddr("8.8.8.8", policy())
	var pe *Error
	if !errors.As(err, &pe) || pe.Reason() == "" || pe.Error() == "" {
		t.Fatalf("err = %#v", err)
	}
	// The message names the rule, never echoes more than the input.
	if got := pe.Reason(); got != "the address is outside settings.bmc_networks" {
		t.Fatalf("reason = %q", got)
	}
}

func TestPolicyContains(t *testing.T) {
	p := policy()
	if !p.Allows(netip.MustParseAddr("10.1.2.3")) || p.Allows(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("Allows")
	}
}
