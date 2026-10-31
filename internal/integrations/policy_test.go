package integrations

// repopolicy:allow private-addresses -- tests the private-network egress policy of integration targets

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"oob-manager/internal/config"
)

// fakeResolver answers per call: answers[0] first, then answers[1], ... (a DNS rebinding
// server); err fails every lookup.
type fakeResolver struct {
	answers [][]netip.Addr
	calls   atomic.Int32
	err     error
}

func (f *fakeResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	if f.err != nil {
		return nil, f.err
	}
	i := int(f.calls.Add(1)) - 1
	return f.answers[min(i, len(f.answers)-1)], nil
}

func addrs(s ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(s))
	for _, a := range s {
		out = append(out, netip.MustParseAddr(a))
	}
	return out
}

func testPolicy(r Resolver) Policy {
	return Policy{Allowed: config.DefaultGELFNetworks(), Resolver: r,
		Self: SelfEndpoints(addrs("10.0.0.2"), []uint16{8443})}
}

func TestPolicyHostileTable(t *testing.T) {
	p := testPolicy(&fakeResolver{answers: [][]netip.Addr{addrs("10.0.0.9")}})
	refused := []string{
		"127.0.0.1:12201", "[::1]:12201", "0.0.0.0:12201", "169.254.169.254:12201", "[fe80::1]:12201",
		"224.0.0.1:12201", "255.255.255.255:12201", "[::ffff:10.0.0.1]:12201", "8.8.8.8:12201",
		"192.0.2.30:12201", "10.0.0.2:8443", "10.0.0.9", "10.0.0.9:0", "10.0.0.9:99999", ":12201",
		"bad name:12201", "[fe80::1%eth0]:12201",
	}
	for _, hp := range refused {
		_, err := p.Resolve(context.Background(), hp)
		var pe *PolicyError
		if !errors.As(err, &pe) || pe.Class != ClassPolicy || pe.Reason == "" {
			t.Errorf("%s: %v", hp, err)
		}
	}
	for hp, want := range map[string]string{"10.0.0.2:12201": "10.0.0.2:12201", "[fd00::30]:12201": "[fd00::30]:12201",
		"logs.example.test:12201": "10.0.0.9:12201"} {
		ap, err := p.Resolve(context.Background(), hp)
		if err != nil || ap.String() != want {
			t.Errorf("%s: %v %v", hp, ap, err)
		}
	}
}

// TestPolicyNameRefusedWhenAnyAnswerIsBad: one disallowed answer refuses the name.
func TestPolicyNameRefusedWhenAnyAnswerIsBad(t *testing.T) {
	p := testPolicy(&fakeResolver{answers: [][]netip.Addr{addrs("10.0.0.9", "127.0.0.1")}})
	_, err := p.Resolve(context.Background(), "logs.example.test:12201")
	var pe *PolicyError
	if !errors.As(err, &pe) || pe.Class != ClassPolicy {
		t.Fatalf("mixed answers: %v", err)
	}
	failing := testPolicy(&fakeResolver{err: errors.New("nxdomain")})
	if _, err := failing.Resolve(context.Background(), "logs.example.test:12201"); !errors.As(err, &pe) || pe.Class != ClassDNS {
		t.Fatalf("lookup failure: %v", err)
	}
	empty := testPolicy(&fakeResolver{answers: [][]netip.Addr{{}}})
	if _, err := empty.Resolve(context.Background(), "logs.example.test:12201"); !errors.As(err, &pe) || pe.Class != ClassDNS {
		t.Fatalf("no answers: %v", err)
	}
}

// TestDialerDialsTheCheckedAddress: the name is resolved on every dial, and the
// connection goes to the address that was checked, never to a second lookup's answer.
func TestDialerDialsTheCheckedAddress(t *testing.T) {
	r := &fakeResolver{answers: [][]netip.Addr{addrs("10.0.0.9"), addrs("127.0.0.1")}}
	var dialled []string
	base := func(_ context.Context, _, addr string) (net.Conn, error) {
		dialled = append(dialled, addr)
		return nil, errors.New("test: not connecting")
	}
	d := testPolicy(r).Dialer(base)
	_, _ = d(context.Background(), "tcp", "logs.example.test:12201")
	_, err := d(context.Background(), "tcp", "logs.example.test:12201") // now rebinds to loopback
	var pe *PolicyError
	if !errors.As(err, &pe) {
		t.Fatalf("rebinding answer: %v", err)
	}
	if len(dialled) != 1 || dialled[0] != "10.0.0.9:12201" || r.calls.Load() != 2 {
		t.Fatalf("dialled %v after %d lookups", dialled, r.calls.Load())
	}
	if (&PolicyError{Class: ClassPolicy, Reason: "x"}).ErrorClass() != ClassPolicy || pe.Error() == "" {
		t.Fatal("error class")
	}
}

func TestDefaultDialerAndResolver(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Loopback is refused even when listed; the default dialer is only reached for an
	// allowed address, which here has nothing listening.
	p := Policy{Allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}
	if _, err := p.Dialer(nil)(context.Background(), "tcp", ln.Addr().String()); err == nil {
		t.Fatal("loopback dialled")
	}
	if _, err := (Policy{}).Resolve(context.Background(), "nonexistent.invalid:1"); err == nil {
		t.Fatal(".invalid resolved")
	}
}

func TestSelfEndpoints(t *testing.T) {
	got := SelfEndpoints(addrs("10.0.0.2", "::ffff:10.0.0.3"), []uint16{8443, 443})
	if len(got) != 4 || got[0].String() != "10.0.0.2:8443" || got[3].String() != "10.0.0.3:443" {
		t.Fatalf("%v", got)
	}
}

// TestPolicyDeniesManagedBMCs: a BMC address of the registry is refused on any port, so
// neither the audit stream nor a certificate fetch is ever aimed at a BMC.
func TestPolicyDeniesManagedBMCs(t *testing.T) {
	p := testPolicy(&fakeResolver{answers: [][]netip.Addr{addrs("10.0.0.50")}})
	p.Deny = func() []netip.Addr { return addrs("10.0.0.50") }
	if _, err := p.Resolve(context.Background(), "bmc.example.test:5901"); err == nil {
		t.Fatal("a name resolving to a BMC was allowed")
	}
	for _, hp := range []string{"10.0.0.50:443", "10.0.0.50:12201"} {
		var pe *PolicyError
		if _, err := p.Resolve(context.Background(), hp); !errors.As(err, &pe) || !strings.Contains(pe.Reason, "BMC") {
			t.Errorf("%s: %v", hp, err)
		}
	}
	if _, err := p.Resolve(context.Background(), "10.0.0.51:12201"); err != nil {
		t.Fatalf("another address refused: %v", err)
	}
}
