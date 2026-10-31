package notify

// repopolicy:allow private-addresses -- tests the private-network egress policy of notification targets

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// fakeResolver answers from a fixed table and counts lookups.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	calls   int
}

func (f *fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	a, ok := f.answers[host]
	if !ok {
		return nil, errors.New("no such host")
	}
	return a, nil
}

func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

func TestPolicyHostileDestinations(t *testing.T) {
	p := Policy{Resolver: &fakeResolver{answers: map[string][]netip.Addr{
		"push.example.net":     addrs("93.184.216.34"),
		"rebind.example.net":   addrs("93.184.216.34", "10.0.0.5"),
		"metadata.example.net": addrs("169.254.169.254"),
		"loop.example.net":     addrs("::1"),
		"mapped.example.net":   addrs("::ffff:127.0.0.1"),
	}}}
	blocked := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0",
		"100.64.0.1", "::1", "fe80::1", "fc00::1", "ff02::1", "224.0.0.1", "255.255.255.255", "192.0.2.10",
		"::ffff:10.0.0.1", "64:ff9b::a00:1", "2002:a00:1::1", "rebind.example.net", "metadata.example.net",
		"loop.example.net", "mapped.example.net", "bad_host!", "-lead.example.net", ""}
	for _, h := range blocked {
		if _, err := p.resolve(context.Background(), h, false); err == nil {
			t.Errorf("%q allowed", h)
		}
	}
	for _, h := range []string{"93.184.216.34", "2606:4700::1", "push.example.net"} {
		if _, err := p.resolve(context.Background(), h, false); err != nil {
			t.Errorf("%q refused: %v", h, err)
		}
	}
	if _, err := p.resolve(context.Background(), "fe80::1%eth0", false); err == nil {
		t.Error("zoned address allowed")
	}
	if _, err := p.resolve(context.Background(), "unknown.example.net", false); ErrorClass(err) != classDNS {
		t.Errorf("unresolvable host: %v", err)
	}
}

func TestPolicyAllowlistAndPlaintext(t *testing.T) {
	allowed, err := ParseNetworks([]string{"192.168.10.0/24", "10.9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{Allowed: allowed}
	ctx := context.Background()
	if _, err := p.resolve(ctx, "192.168.10.7", true); err != nil {
		t.Errorf("allowlisted LAN plaintext refused: %v", err)
	}
	if _, err := p.resolve(ctx, "10.9.9.9", false); err != nil {
		t.Errorf("allowlisted single IP refused: %v", err)
	}
	if _, err := p.resolve(ctx, "10.9.9.8", false); !errors.Is(err, ErrBlocked) {
		t.Errorf("outside the /32: %v", err)
	}
	if _, err := p.resolve(ctx, "93.184.216.34", true); !errors.Is(err, ErrBlocked) {
		t.Errorf("plaintext to the internet allowed: %v", err)
	}
	for _, bad := range []string{"10.0.0.0/33", "nonsense", "fe80::/10%eth0", "fe80::1%eth0"} {
		if _, err := ParseNetworks([]string{bad}); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

// TestDNSRebindingDialsTheCheckedAddress: the resolver is asked once, and the dialler
// is given the IP literal that passed the policy, never the host name.
func TestDNSRebindingDialsTheCheckedAddress(t *testing.T) {
	res := &fakeResolver{answers: map[string][]netip.Addr{"hook.example.net": addrs("127.0.0.1")}}
	var dialled []string
	tr := Transport{Policy: Policy{Allowed: loopback, Resolver: res},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialled = append(dialled, addr)
			return nil, errors.New("stop here")
		}}
	_, _ = tr.withDefaults().dialChecked(context.Background(), "hook.example.net:8443", false)
	if res.calls != 1 || len(dialled) != 1 || dialled[0] != "127.0.0.1:8443" {
		t.Fatalf("lookups %d, dialled %v", res.calls, dialled)
	}
	// A rebinding answer (public first, private second) is refused before any dial.
	res.answers["hook.example.net"] = addrs("93.184.216.34", "192.168.0.1")
	tr.Policy.Allowed = nil
	if _, err := tr.withDefaults().dialChecked(context.Background(), "hook.example.net:443", false); !errors.Is(err, ErrBlocked) || len(dialled) != 1 {
		t.Fatalf("rebinding answer: err %v, dialled %v", err, dialled)
	}
}

func TestPrivateReceiverBlockedWithoutAllowlist(t *testing.T) {
	r := newReceiver(t, true)
	tr := transportFor(r)
	tr.Policy.Allowed = nil
	d := NewDispatcher(DispatchConfig{Transport: tr, Logger: quiet(), Attempts: 1})
	err := d.SendNow(context.Background(), target(KindWebhook, r.srv.URL+"/x"), Secrets{}, testEvent())
	if ErrorClass(err) != classBlocked || r.count() != 0 {
		t.Fatalf("class %q, receiver saw %d", ErrorClass(err), r.count())
	}
	if !strings.Contains(err.Error(), "allowed_networks") {
		t.Fatalf("error should name the rule: %v", err)
	}
}

func TestHTTPNeedsOptInAndAllowlist(t *testing.T) {
	r := newReceiver(t, false)
	tg := target(KindNtfy, r.srv.URL+"/x")
	if err := Validate(tg, Secrets{}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("http without opt-in validated: %v", err)
	}
	d := NewDispatcher(DispatchConfig{Transport: transportFor(r), Logger: quiet(), Attempts: 1})
	if err := d.SendNow(context.Background(), tg, Secrets{}, testEvent()); ErrorClass(err) != classBlocked || r.count() != 0 {
		t.Fatalf("http sent without opt-in: %v", err)
	}
	tg.AllowPlaintext = true
	if err := d.SendNow(context.Background(), tg, Secrets{}, testEvent()); err != nil || r.count() != 1 {
		t.Fatalf("opted-in LAN http: %v", err)
	}
	tr := transportFor(r)
	tr.Policy.Allowed = nil
	d = NewDispatcher(DispatchConfig{Transport: tr, Logger: quiet(), Attempts: 1})
	if err := d.SendNow(context.Background(), tg, Secrets{}, testEvent()); ErrorClass(err) != classBlocked {
		t.Fatalf("opt-in without allowlist: %v", err)
	}
}

func TestTLSFailureIsClassified(t *testing.T) {
	r := newReceiver(t, true)
	tr := transportFor(r)
	tr.TLS = nil // system roots do not trust the test certificate
	d := NewDispatcher(DispatchConfig{Transport: tr, Logger: quiet(), Attempts: 1})
	err := d.SendNow(context.Background(), target(KindNtfy, r.srv.URL+"/x"), Secrets{}, testEvent())
	if ErrorClass(err) != classTLS || retryable(err) {
		t.Fatalf("class %q retry %v", ErrorClass(err), retryable(err))
	}
}
