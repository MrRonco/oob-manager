package egress

// repopolicy:allow private-addresses -- tests egress address classification, private ranges included

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

type fakeResolver map[string][]netip.Addr

func (f fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := f[host]; ok {
		return a, nil
	}
	return nil, errors.New("no such host")
}

func TestPolicyRefusesNonPublicAndRebinding(t *testing.T) {
	p := Policy{Setting: "firmware.catalog.allowed_networks", Resolver: fakeResolver{
		"cdn.example.net":    {netip.MustParseAddr("93.184.216.34")},
		"rebind.example.net": {netip.MustParseAddr("93.184.216.34"), netip.MustParseAddr("10.0.0.5")},
		"empty.example.net":  {},
	}}
	ctx := context.Background()
	for _, h := range []string{"127.0.0.1", "10.1.2.3", "192.0.2.10", "169.254.169.254", "::1", "fe80::1%eth0",
		"rebind.example.net", "bad_host!", ""} {
		if _, err := p.Resolve(ctx, h, false); !errors.Is(err, ErrBlocked) {
			t.Errorf("%q: %v", h, err)
		}
	}
	_, err := p.Resolve(ctx, "10.1.2.3", false)
	if err == nil || !strings.Contains(err.Error(), "firmware.catalog.allowed_networks") {
		t.Errorf("the refusal names the setting: %v", err)
	}
	if a, err := p.Resolve(ctx, "cdn.example.net", false); err != nil || a.String() != "93.184.216.34" {
		t.Errorf("public host: %v %v", a, err)
	}
	var dns *DNSError
	for _, h := range []string{"unknown.example.net", "empty.example.net"} {
		if _, err := p.Resolve(ctx, h, false); !errors.As(err, &dns) {
			t.Errorf("%q: want a DNSError, got %v", h, err)
		}
	}
	if _, err := (Policy{}).Resolve(ctx, "10.0.0.1", false); err == nil || !strings.Contains(err.Error(), "the allowed networks") {
		t.Errorf("default setting name: %v", err)
	}
}

func TestPolicyAllowlistPermitsPlaintextOnlyThere(t *testing.T) {
	allowed, err := ParseNetworks([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	p := Policy{Allowed: allowed}
	if err := p.Permit(netip.MustParseAddr("192.0.2.9"), true); err != nil {
		t.Errorf("allowlisted plaintext: %v", err)
	}
	if err := p.Permit(netip.MustParseAddr("93.184.216.34"), true); !errors.Is(err, ErrBlocked) {
		t.Errorf("plaintext to the internet: %v", err)
	}
	if _, err := ParseNetworks([]string{"nonsense"}); err == nil {
		t.Error("bad network parsed")
	}
}

func TestDialerDialsTheCheckedAddress(t *testing.T) {
	var dialled []string
	d := Dialer{Policy: Policy{Resolver: fakeResolver{"cdn.example.net": {netip.MustParseAddr("93.184.216.34")}}},
		Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
			dialled = append(dialled, addr)
			return nil, errors.New("stop")
		}}
	_, _ = d.DialContext(context.Background(), "cdn.example.net:443", false)
	if len(dialled) != 1 || dialled[0] != "93.184.216.34:443" {
		t.Fatalf("dialled %v", dialled)
	}
	if _, err := d.DialContext(context.Background(), "no-port", false); !errors.Is(err, ErrBadAddress) {
		t.Errorf("bad address: %v", err)
	}
}

func TestClientDoesNotFollowRedirects(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example.net/x", http.StatusFound)
	}))
	defer srv.Close()
	allowed, _ := ParseNetworks([]string{"127.0.0.0/8"})
	tr, ok := srv.Client().Transport.(*http.Transport)
	if !ok {
		t.Fatal("not an *http.Transport")
	}
	c := NewClient(ClientConfig{Dialer: Dialer{Policy: Policy{Allowed: allowed}}, TLS: tr.TLSClientConfig})
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d: the redirect was followed", resp.StatusCode)
	}
	if tlsCfg := TLSConfig(nil, "x"); tlsCfg.MinVersion < 0x0303 || tlsCfg.ServerName != "x" {
		t.Errorf("TLS floor: %+v", tlsCfg)
	}
}

// TestPublicUnicastRefusesTunnelAndLegacyRanges: addresses that are not ordinary public
// unicast, or that can carry an IPv4 address of any kind inside them, are not public.
func TestPublicUnicastRefusesTunnelAndLegacyRanges(t *testing.T) {
	for _, s := range []string{
		"fec0::1",      // deprecated site-local (RFC 3879)
		"feff:ffff::1", // still inside fec0::/10
		"2001::1",      // Teredo (embeds an obfuscated IPv4)
		"2001:0:4136:e378:8000:63bf:3fff:fdd2",
		"::10.0.0.1",       // IPv4-compatible (deprecated), private inside
		"::9.9.9.9",        // IPv4-compatible, public inside: still refused
		"::ffff:192.0.2.1", // IPv4-mapped documentation address
		"::ffff:10.0.0.1",  // IPv4-mapped private address
		"3fff::1",          // documentation (RFC 9637)
		"2001:10::1",       // ORCHID (deprecated)
		"2001:20::1",       // ORCHIDv2
		"2001:2::1",        // benchmarking
		"::ffff:0:a00:1",   // IPv4/IPv6 translation (RFC 2765)
		"5f00::1",          // SRv6 SIDs
		"192.88.99.1",      // 6to4 relay anycast (deprecated)
	} {
		if PublicUnicast(netip.MustParseAddr(s)) {
			t.Errorf("%s reported as public unicast", s)
		}
	}
	for _, s := range []string{"9.9.9.9", "::ffff:9.9.9.9", "2620:fe::fe", "2001:4860::8888"} {
		if !PublicUnicast(netip.MustParseAddr(s)) {
			t.Errorf("%s not reported as public unicast", s)
		}
	}
}
