package config

import (
	"net/netip"
	"strings"
	"testing"
)

func TestBMCPortDefaultsAndBounds(t *testing.T) {
	cfg := mustParse(t, validYAML())
	if s, _ := cfg.Server("r730xd"); s.BMC.Port != DefaultBMCPort {
		t.Fatalf("default port = %d", s.BMC.Port)
	}
	if got := cfg.Servers[0].BMC.Endpoint(); got != "https://192.0.2.70:443" {
		t.Fatalf("endpoint = %q", got)
	}
	ok := strings.Replace(validYAML(), "address: 192.0.2.70, kind: idrac8 }", "address: 192.0.2.70, kind: idrac8, port: 8443 }", 1)
	if s, _ := mustParse(t, ok).Server("r730xd"); s.BMC.Port != 8443 || s.BMC.Endpoint() != "https://192.0.2.70:8443" {
		t.Fatalf("port 8443: %+v", s.BMC)
	}
	for _, bad := range []string{"80", "1023", "65536", "623"} {
		src := strings.Replace(validYAML(), "address: 192.0.2.70, kind: idrac8 }", "address: 192.0.2.70, kind: idrac8, port: "+bad+" }", 1)
		if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "bmc.port") {
			t.Errorf("port %s: err = %v", bad, err)
		}
	}
	v6 := strings.Replace(validYAML(), "address: 192.0.2.70, kind: idrac8 }", "address: \"fd00::50\", kind: idrac8 }", 1)
	if s, _ := mustParse(t, v6).Server("r730xd"); s.BMC.Endpoint() != "https://[fd00::50]:443" {
		t.Fatalf("v6 endpoint = %q", s.BMC.Endpoint())
	}
}

func TestIPMIPortDefault(t *testing.T) {
	s := Server{ID: "x", BMC: BMCConfig{Kind: KindIPMI}}
	if got := bmcDefaults(s.BMC).Port; got != DefaultIPMIPort {
		t.Fatalf("ipmi default port = %d", got)
	}
}

func TestBMCNetworksDefaultAndValidation(t *testing.T) {
	cfg := mustParse(t, validYAML())
	got := cfg.BMCNetworks()
	if len(got) != 4 || got[0] != netip.MustParsePrefix("10.0.0.0/8") || got[3] != netip.MustParsePrefix("fc00::/7") {
		t.Fatalf("default bmc_networks = %v", got)
	}
	custom := "settings: { bmc_networks: [192.0.2.0/24] }\n" + validYAML()
	if got := mustParse(t, custom).BMCNetworks(); len(got) != 1 || got[0].String() != "192.0.2.0/24" {
		t.Fatalf("custom = %v", got)
	}
	for _, bad := range []string{"192.0.2.1/24", "example.com/24", "192.0.2.0", "0.0.0.0/0", "::/0"} {
		_, err := Parse([]byte("settings: { bmc_networks: [\"" + bad + "\"] }\n" + validYAML()))
		if err == nil || !strings.Contains(err.Error(), "settings.bmc_networks") {
			t.Errorf("%s: err = %v", bad, err)
		}
	}
}

func TestNoServersIsValid(t *testing.T) {
	src := validYAML()
	src = src[:strings.Index(src, "servers:")] + "servers: []\n"
	if cfg := mustParse(t, src); len(cfg.Servers) != 0 {
		t.Fatalf("servers = %v", cfg.Servers)
	}
	noKey := validYAML()[:strings.Index(validYAML(), "servers:")]
	if _, err := Parse([]byte(noKey)); err != nil {
		t.Fatalf("no servers key: %v", err)
	}
}

func TestValidateServerExported(t *testing.T) {
	cfg := mustParse(t, validYAML())
	s, _ := cfg.Server("r240")
	if p := ValidateServer(s); len(p) != 0 {
		t.Fatalf("valid server: %v", p)
	}
	s.BMC.Address = "edge.example.test"
	s.Fan.SafeMinPct = 10
	p := ValidateServer(s)
	if len(p) != 2 || !strings.Contains(p[0], "bmc.address") || !strings.Contains(p[1], "fan.safe_min_pct") {
		t.Fatalf("problems = %v", p)
	}
	// A server that is not normalised yet (no defaults) gets them applied first.
	raw := Server{ID: "n1", Name: "New", BMC: BMCConfig{Address: "192.0.2.5", Kind: KindIDRAC9},
		TLSPinSHA256: testPin, Credentials: CredentialRef{ReadOnly: "readonly"}}
	if p := ValidateServer(Normalise(raw)); len(p) != 0 {
		t.Fatalf("normalised new server: %v", p)
	}
}
