package config

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func vncYAML(block string) string {
	return strings.Replace(validYAML(), "console: { serial: bmcssh, graphical: vnc }",
		"console:\n      serial: bmcssh\n      graphical: vnc\n"+block, 1)
}

func TestVNCDefaultsPerKind(t *testing.T) {
	cfg := mustParse(t, validYAML())
	s, _ := cfg.Server("r730xd")
	v := s.Console.VNC
	if v.Port != DefaultVNCPort || !v.TLSEnabled() {
		t.Errorf("vnc defaults = port %d tls %v", v.Port, v.TLSEnabled())
	}
	want := []VNCQuirk{QuirkIDRAC8SafeEncodings, QuirkIDRAC8LowColour, QuirkIDRAC8RSAKexTLS}
	if !slices.Equal(v.Quirks, want) {
		t.Errorf("idrac8 default quirks = %v, want %v", v.Quirks, want)
	}
	if v.PinSHA256 != "" || s.VNCPin() != testPin {
		t.Errorf("vnc pin defaults to the server pin: %q / %q", v.PinSHA256, s.VNCPin())
	}
	r240, _ := cfg.Server("r240")
	if len(r240.Console.VNC.Quirks) != 0 {
		t.Errorf("idrac9 quirks = %v, want none", r240.Console.VNC.Quirks)
	}
}

func TestVNCExplicitSettings(t *testing.T) {
	other := strings.Repeat("ab", 32)
	cfg := mustParse(t, vncYAML(`      vnc: { port: 5999, tls: false, quirks: [] }
`))
	s, _ := cfg.Server("r730xd")
	if s.Console.VNC.Port != 5999 || s.Console.VNC.TLSEnabled() || len(s.Console.VNC.Quirks) != 0 {
		t.Errorf("explicit vnc = %+v", s.Console.VNC)
	}
	cfg = mustParse(t, vncYAML(`      vnc: { tls: true, tls_pin_sha256: "`+strings.ToUpper(other)+`", quirks: [idrac8_low_colour] }
`))
	s, _ = cfg.Server("r730xd")
	if s.VNCPin() != other || len(s.Console.VNC.Quirks) != 1 || !s.Console.VNC.Has(QuirkIDRAC8LowColour) ||
		s.Console.VNC.Has(QuirkIDRAC8SafeEncodings) {
		t.Errorf("explicit vnc = %+v pin %q", s.Console.VNC, s.VNCPin())
	}
}

func TestVNCServerCopyIsDeep(t *testing.T) {
	cfg := mustParse(t, validYAML())
	s, _ := cfg.Server("r730xd")
	s.Console.VNC.Quirks[0] = "mutated"
	again, _ := cfg.Server("r730xd")
	if again.Console.VNC.Quirks[0] != QuirkIDRAC8SafeEncodings {
		t.Error("Server() leaked the quirks slice")
	}
}

func TestVNCRejects(t *testing.T) {
	tests := map[string]struct{ block, want string }{
		"port zero":       {"      vnc: { port: 70000 }\n", "console.vnc.port"},
		"unknown quirk":   {"      vnc: { quirks: [turbo] }\n", "console.vnc.quirks"},
		"duplicate quirk": {"      vnc: { quirks: [idrac8_low_colour, idrac8_low_colour] }\n", "duplicate"},
		"bad pin":         {"      vnc: { tls_pin_sha256: abc }\n", "console.vnc.tls_pin_sha256"},
		"unknown key":     {"      vnc: { password: x }\n", "password"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(vncYAML(tc.block)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want mention of %q", err, tc.want)
			}
		})
	}
}

func TestVNCTLSNeedsAPin(t *testing.T) {
	src := strings.Replace(validYAML(), "kind: idrac9 }\n    tls_pin_sha256: \""+testPin+"\"\n", "kind: ipmi }\n", 1)
	src = strings.Replace(src, "fan: { mode: redfishfloor, safe_min_pct: 41, max_lease: 2h }\n    console: { serial: bmcssh, graphical: kvm-launch }",
		"fan: { mode: none }\n    credentials: { readonly: x, operator: y, vnc: z }\n    console: { serial: none, graphical: vnc }", 1)
	src = strings.Replace(src, "    credentials: { readonly: r240-ro, operator: r240-op }\n", "", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "console.vnc.tls_pin_sha256") {
		t.Errorf("tls vnc without any pin: err = %v", err)
	}
	plain := strings.Replace(src, "serial: none, graphical: vnc }", "serial: none, graphical: vnc, vnc: { tls: false } }", 1)
	mustParse(t, plain)
}

func TestConsoleSettings(t *testing.T) {
	cfg := mustParse(t, validYAML())
	c := cfg.Console
	if c.IdleTimeout != DefaultConsoleIdle || c.MaxSession != DefaultConsoleMax || c.CloseOnStepUpExpiry {
		t.Errorf("console defaults = %+v", c)
	}
	src := strings.Replace(validYAML(), "servers:\n", "console: { idle_timeout: 5m, max_session: 1h, close_on_stepup_expiry: true }\nservers:\n", 1)
	c = mustParse(t, src).Console
	if c.IdleTimeout != 5*time.Minute || c.MaxSession != time.Hour || !c.CloseOnStepUpExpiry {
		t.Errorf("console settings = %+v", c)
	}
	for name, block := range map[string]string{
		"idle too short":  "console: { idle_timeout: 10s }\n",
		"max below idle":  "console: { idle_timeout: 30m, max_session: 10m }\n",
		"max above limit": "console: { max_session: 13h }\n",
	} {
		t.Run(name, func(t *testing.T) {
			bad := strings.Replace(validYAML(), "servers:\n", block+"servers:\n", 1)
			if _, err := Parse([]byte(bad)); err == nil || !strings.Contains(err.Error(), "console.") {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestRSAKexQuirkAccepted(t *testing.T) {
	cfg := mustParse(t, vncYAML("      vnc: { quirks: [idrac8_rsa_kex_tls] }\n"))
	s, _ := cfg.Server("r730xd")
	if !s.Console.VNC.Has(QuirkIDRAC8RSAKexTLS) || s.Console.VNC.Has(QuirkIDRAC8LowColour) {
		t.Errorf("quirks = %v", s.Console.VNC.Quirks)
	}
}

// VNC needs only the vnc credential; operator is for the native launch, fans and serial.
func TestVNCWithoutOperator(t *testing.T) {
	src := strings.Replace(validYAML(), "credentials: { readonly: r730xd-ro, operator: r730xd-op, vnc: r730xd-vnc }\n    fan: { mode: host-lease, safe_min_pct: 30, max_lease: 2h }\n    console: { serial: bmcssh, graphical: vnc }",
		"credentials: { readonly: r730xd-ro, vnc: r730xd-vnc }\n    fan: { mode: none }\n    console: { serial: none, graphical: vnc }", 1)
	cfg := mustParse(t, src)
	s, _ := cfg.Server("r730xd")
	if s.Credentials.Operator != "" || s.Console.Graphical != GraphicalVNC {
		t.Errorf("server = %+v", s)
	}
	noVNC := strings.Replace(src, "credentials: { readonly: r730xd-ro, vnc: r730xd-vnc }", "credentials: { readonly: r730xd-ro }", 1)
	if _, err := Parse([]byte(noVNC)); err == nil || !strings.Contains(err.Error(), "credentials.vnc") ||
		strings.Contains(err.Error(), "credentials.operator") {
		t.Errorf("vnc without its credential: err = %v", err)
	}
}

func TestKVMLaunchStillNeedsOperator(t *testing.T) {
	src := strings.Replace(validYAML(), "credentials: { readonly: r240-ro, operator: r240-op }\n    fan: { mode: redfishfloor, safe_min_pct: 41, max_lease: 2h }",
		"credentials: { readonly: r240-ro }\n    fan: { mode: none }", 1)
	src = strings.Replace(src, "console: { serial: bmcssh, graphical: kvm-launch }", "console: { serial: none, graphical: kvm-launch }", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "credentials.operator") {
		t.Errorf("kvm-launch without operator: err = %v", err)
	}
}
