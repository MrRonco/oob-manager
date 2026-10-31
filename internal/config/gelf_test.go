package config

// repopolicy:allow private-addresses -- tests that a GELF address must be on a private network

import (
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// withGELF is validYAML with its audit.gelf line replaced by line.
func withGELF(line string) string {
	return regexp.MustCompile(`(?m)^  gelf: .*$`).ReplaceAllLiteralString(validYAML(), "  "+line)
}

func TestValidateGELF(t *testing.T) {
	ok := []GELF{
		{},
		{Enabled: true, Address: "192.0.2.30:12201", Transport: TransportTCP},
		{Enabled: true, Address: "logs.example.test:12201", Transport: TransportTLS, PinSHA256: testPin},
		{Enabled: true, Address: "[fd00::30]:12201", Transport: TransportTLS, ServerName: "logs.example.test", PinSHA256: testPin},
		{Address: "192.0.2.30:12201", Transport: TransportTLS}, // disabled draft: the pin may come later
	}
	for _, g := range ok {
		if p := ValidateGELF(g); len(p) > 0 {
			t.Errorf("%+v: %v", g, p)
		}
	}
	bad := map[string]GELF{
		"enabled without address": {Enabled: true, Transport: TransportTCP},
		"no port":                 {Enabled: true, Address: "192.0.2.30", Transport: TransportTCP},
		"port zero":               {Enabled: true, Address: "192.0.2.30:0", Transport: TransportTCP},
		"port too big":            {Enabled: true, Address: "192.0.2.30:65536", Transport: TransportTCP},
		"port not digits":         {Enabled: true, Address: "192.0.2.30:+80", Transport: TransportTCP},
		"zone":                    {Enabled: true, Address: "[fe80::1%eth0]:12201", Transport: TransportTCP},
		"bad host":                {Enabled: true, Address: "logs server:12201", Transport: TransportTCP},
		"long host":               {Enabled: true, Address: strings.Repeat("a", 254) + ":1", Transport: TransportTCP},
		"udp":                     {Enabled: true, Address: "192.0.2.30:12201", Transport: "udp"},
		"tls without pin":         {Enabled: true, Address: "192.0.2.30:12201", Transport: TransportTLS},
		"bad pin":                 {Address: "192.0.2.30:12201", Transport: TransportTLS, PinSHA256: "abc"},
		"upper-case pin":          {Address: "192.0.2.30:12201", Transport: TransportTLS, PinSHA256: strings.ToUpper(testPin)},
		"server name is an IP":    {Address: "192.0.2.30:12201", Transport: TransportTLS, ServerName: "192.0.2.30", PinSHA256: testPin},
		"server name junk":        {Address: "192.0.2.30:12201", Transport: TransportTLS, ServerName: "a b", PinSHA256: testPin},
	}
	for name, g := range bad {
		if p := ValidateGELF(g); len(p) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestGELFAddrAllowed(t *testing.T) {
	nets := DefaultGELFNetworks()
	for _, a := range []string{"10.1.2.3", "172.16.0.9", "192.168.1.1", "fd00::5"} {
		if err := GELFAddrAllowed(netip.MustParseAddr(a), nets); err != nil {
			t.Errorf("%s refused: %v", a, err)
		}
	}
	wide := append(DefaultGELFNetworks(), netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1"),
		netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1"))
	for _, a := range []string{"127.0.0.1", "::1", "0.0.0.0", "::", "169.254.169.254", "fe80::1", "224.0.0.1",
		"ff02::1", "255.255.255.255", "::ffff:10.0.0.1"} {
		if err := GELFAddrAllowed(netip.MustParseAddr(a), wide); err == nil {
			t.Errorf("%s allowed even with every network listed", a)
		}
	}
	if err := GELFAddrAllowed(netip.MustParseAddr("8.8.8.8"), nets); err == nil {
		t.Error("public address allowed by the default private ranges")
	}
}

func TestGELFFileKeysAndDefaults(t *testing.T) {
	cfg := mustParse(t, withGELF(`gelf: { address: "192.0.2.30:12201", transport: tls, pin_sha256: "`+strings.ToUpper(testPin)+`", allowed_networks: [192.0.2.0/25, 192.0.2.200] }`))
	g := cfg.GELF()
	if !g.Enabled || g.Transport != TransportTLS || g.PinSHA256 != testPin || g.ServerName != "" {
		t.Fatalf("gelf %+v", g)
	}
	for _, k := range []string{KeyGELFEnabled, KeyGELFAddress, KeyGELFTransport, KeyGELFPin} {
		if !cfg.FileSets(k) {
			t.Errorf("%s not file-managed", k)
		}
	}
	if cfg.FileSets(KeyGELFServerName) {
		t.Error("server_name reported as set")
	}
	nets := cfg.GELFNetworks()
	if len(nets) != 2 || nets[1] != netip.MustParsePrefix("192.0.2.200/32") {
		t.Fatalf("networks %v", nets)
	}

	// An empty address is "not set": the browser manages every GELF key.
	empty := mustParse(t, withGELF(`gelf: { address: "", transport: tls, pin_sha256: "`+testPin+`" }`)) // other keys do not lock
	for _, k := range IntegrationKeys() {
		if empty.FileSets(k) {
			t.Errorf("%s file-managed with an empty address", k)
		}
	}
	if g := empty.GELF(); g.Enabled || g.Transport != TransportTCP {
		t.Fatalf("empty gelf %+v", g)
	}
	if !slices.Equal(empty.GELFNetworks(), DefaultGELFNetworks()) {
		t.Fatalf("default networks %v", empty.GELFNetworks())
	}
}

func TestGELFConfigRefusals(t *testing.T) {
	cases := map[string]string{
		"loopback":        `gelf: { address: "127.0.0.1:12201" }`,
		"outside":         `gelf: { address: "192.0.2.30:12201" }`,
		"tls without pin": `gelf: { address: "192.0.2.30:12201", allowed_networks: [192.0.2.0/24], transport: tls }`,
		"bad network":     `gelf: { address: "192.0.2.30:12201", allowed_networks: [nope] }`,
		"zoned network":   `gelf: { address: "192.0.2.30:12201", allowed_networks: ["fe80::/10%eth0"] }`,
		"every address":   `gelf: { address: "192.0.2.30:12201", allowed_networks: [0.0.0.0/0] }`,
		"unknown key":     `gelf: { address: "192.0.2.30:12201", allowed_networks: [192.0.2.0/24], queue: 5 }`,
	}
	for name, repl := range cases {
		if _, err := Parse([]byte(withGELF(repl))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A listed documentation range makes a TEST-NET address valid; a host name is only
	// checked when it is dialled.
	for _, repl := range []string{`gelf: { address: "192.0.2.30:12201", allowed_networks: [192.0.2.0/24] }`,
		`gelf: { address: "logs.example.test:12201" }`} {
		if _, err := Parse([]byte(withGELF(repl))); err != nil {
			t.Errorf("%s: %v", repl, err)
		}
	}
}

func TestIntegrationKeysAndPaths(t *testing.T) {
	if len(IntegrationKeys()) != 5 || IntegrationKeys()[0] != KeyGELFEnabled {
		t.Fatalf("keys %v", IntegrationKeys())
	}
	want := map[string]string{KeyGELFEnabled: "audit.gelf.address", KeyGELFAddress: "audit.gelf.address",
		KeyGELFTransport: "audit.gelf.transport", KeyGELFServerName: "audit.gelf.server_name",
		KeyGELFPin: "audit.gelf.pin_sha256", KeyTheme: KeyTheme}
	for k, p := range want {
		if got := FilePath(k); got != p {
			t.Errorf("FilePath(%s) = %s, want %s", k, got, p)
		}
	}
}

func TestGELFHostNamesAndHints(t *testing.T) {
	for _, addr := range []string{"graylog_input:12201", "logs.example.test:12201"} {
		if p := ValidateGELF(GELF{Enabled: true, Address: addr, Transport: TransportTCP}); len(p) > 0 {
			t.Errorf("%s: %v", addr, p)
		}
	}
	if p := ValidateGELF(GELF{Address: "192.0.2.30:1", Transport: TransportTLS, ServerName: "log_server", PinSHA256: testPin}); len(p) == 0 {
		t.Error("an underscore accepted in the TLS server name")
	}
	err := GELFAddrAllowed(netip.MustParseAddr("203.0.113.9"), DefaultGELFNetworks())
	if err == nil || !strings.Contains(err.Error(), "add its range there, for example 203.0.113.9/32") {
		t.Fatalf("hint: %v", err)
	}
	if _, err := Parse([]byte(withGELF(`gelf: { address: "", transport: udp }`))); err == nil {
		t.Error("a bad transport loaded because the address was empty")
	}
}
