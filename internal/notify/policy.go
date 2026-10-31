package notify

import (
	"context"
	"errors"
	"net/netip"

	"oob-manager/internal/egress"
)

// ErrBlocked is returned when a destination fails the SSRF policy (internal/egress).
var ErrBlocked = egress.ErrBlocked

// Resolver looks up a host name. *net.Resolver satisfies it; tests use a fake to
// simulate DNS rebinding.
type Resolver = egress.Resolver

// Policy is the notification destination policy (notifications.allowed_networks), the
// shared egress policy (internal/egress) under that setting's name.
type Policy struct {
	Allowed  []netip.Prefix
	Resolver Resolver
}

// ParseNetworks parses CIDRs or single IPs ("192.0.2.7" = /32).
func ParseNetworks(items []string) ([]netip.Prefix, error) { return egress.ParseNetworks(items) }

func (p Policy) egress() egress.Policy {
	return egress.Policy{Allowed: p.Allowed, Resolver: p.Resolver, Setting: "notifications.allowed_networks"}
}

// resolve checks host and returns the one address to dial; a name that does not resolve
// is the dns class.
func (p Policy) resolve(ctx context.Context, host string, plaintext bool) (netip.Addr, error) {
	a, err := p.egress().Resolve(ctx, host, plaintext)
	var de *egress.DNSError
	if errors.As(err, &de) {
		return a, &deliveryError{class: classDNS, err: err}
	}
	return a, err
}
