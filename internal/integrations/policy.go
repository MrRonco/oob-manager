package integrations

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"oob-manager/internal/config"
)

// Error classes of a refused or unresolvable destination.
const (
	ClassPolicy = "policy"
	ClassDNS    = "dns"
	// ClassAudit: the started row could not be written, so nothing was done.
	ClassAudit = "audit"
)

// PolicyError is a refused destination. Reason is safe to show to an admin; it names
// the rule, never a resolved address the admin did not type.
type PolicyError struct {
	Class  string
	Reason string
}

func (e *PolicyError) Error() string { return "integrations: " + e.Class + ": " + e.Reason }

// ErrorClass reports the class (the shipper records it as its last error).
func (e *PolicyError) ErrorClass() string { return e.Class }

// Resolver looks up a host name (*net.Resolver satisfies it; tests use fakes).
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// DialFunc opens a TCP connection to an "ip:port" the policy has checked.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Policy is the GELF destination policy (security.md T10): every address, typed or
// resolved, must be inside Allowed (audit.gelf.allowed_networks, file-only), is never
// loopback, link-local, multicast, broadcast or unspecified, and is never one of the
// app's own listen endpoints (Self). A host name is resolved on every dial and EVERY
// answer must pass, or the name is refused; the connection then goes to the checked
// address, so a DNS rebinding answer is never dialled.
type Policy struct {
	Allowed []netip.Prefix
	Self    []netip.AddrPort
	// Deny lists the BMC addresses of the effective server registry, read per check
	// (servers come and go in the browser); nil denies none.
	Deny     func() []netip.Addr
	Resolver Resolver
}

// Resolve checks hostport ("host:port") and returns the first endpoint to dial.
func (p Policy) Resolve(ctx context.Context, hostport string) (netip.AddrPort, error) {
	all, err := p.ResolveAll(ctx, hostport)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return all[0], nil
}

// ResolveAll checks hostport and returns every endpoint it may be dialled at, in the
// resolver's order (one for an IP literal). Every answer has passed the policy.
func (p Policy) ResolveAll(ctx context.Context, hostport string) ([]netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	port, perr := strconv.ParseUint(portStr, 10, 16)
	if err != nil || perr != nil || port == 0 || host == "" {
		return nil, &PolicyError{Class: ClassPolicy, Reason: "the address must be host:port"}
	}
	if a, aerr := netip.ParseAddr(host); aerr == nil {
		ap := netip.AddrPortFrom(a, uint16(port))
		if perr := p.permit(ap); perr != nil {
			return nil, perr
		}
		return []netip.AddrPort{ap}, nil
	}
	if probs := config.ValidateGELF(config.GELF{Address: hostport}); len(probs) > 0 {
		return nil, &PolicyError{Class: ClassPolicy, Reason: "the host must be an IP address or a DNS name"}
	}
	addrs, err := p.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]netip.AddrPort, 0, len(addrs))
	for _, a := range addrs {
		ap := netip.AddrPortFrom(a, uint16(port))
		out = append(out, ap)
		if err := p.permit(ap); err != nil {
			return nil, &PolicyError{Class: ClassPolicy,
				Reason: "the name " + host + " resolves to an address that is not allowed"}
		}
	}
	return out, nil
}

func (p Policy) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	r := p.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		return nil, &PolicyError{Class: ClassDNS, Reason: "the name " + host + " did not resolve"}
	}
	return addrs, nil
}

// permit applies the policy to one endpoint (IPv4-mapped answers are refused, not
// unmapped, as config.GELFAddrAllowed does).
func (p Policy) permit(ap netip.AddrPort) error {
	if err := config.GELFAddrAllowed(ap.Addr(), p.Allowed); err != nil {
		return &PolicyError{Class: ClassPolicy, Reason: reasonOf(err)}
	}
	if slices.Contains(p.Self, ap) {
		return &PolicyError{Class: ClassPolicy, Reason: "that is this console's own address and port"}
	}
	if p.Deny != nil && slices.Contains(p.Deny(), ap.Addr()) {
		return &PolicyError{Class: ClassPolicy, Reason: "that is the address of a BMC this console manages"}
	}
	return nil
}

func reasonOf(err error) string {
	var pe *PolicyError
	if errors.As(err, &pe) {
		return pe.Reason
	}
	return err.Error()
}

// Dialer wraps base (nil: net.Dialer) so every connection is checked first (the
// shipper's Dial hook); a name with several allowed answers is tried in order. The
// returned error carries ErrorClass.
func (p Policy) Dialer(base DialFunc) DialFunc {
	if base == nil {
		base = (&net.Dialer{}).DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		all, err := p.ResolveAll(ctx, addr)
		if err != nil {
			return nil, err
		}
		var last error
		for i, ap := range all { // every one already checked: try them in order
			actx, cancel := attemptContext(ctx, len(all)-i)
			c, derr := base(actx, network, ap.String())
			cancel()
			if derr == nil {
				return c, nil
			}
			last = derr
		}
		return nil, last
	}
}

// minAttempt is the least time one address of a name gets when several are tried.
const minAttempt = 500 * time.Millisecond

// attemptContext gives one of left remaining attempts its share of ctx's remaining time
// (at least minAttempt), so a black-holed first answer cannot use up the whole dial
// timeout and starve the others.
func attemptContext(ctx context.Context, left int) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok || left <= 1 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, max(time.Until(deadline)/time.Duration(left), minAttempt))
}

// SelfEndpoints lists the app's own listen endpoints: every address in addrs combined
// with every port in ports (the listen port and the public_url port).
func SelfEndpoints(addrs []netip.Addr, ports []uint16) []netip.AddrPort {
	out := make([]netip.AddrPort, 0, len(addrs)*len(ports))
	for _, a := range addrs {
		for _, port := range ports {
			out = append(out, netip.AddrPortFrom(a.Unmap(), port))
		}
	}
	return out
}
