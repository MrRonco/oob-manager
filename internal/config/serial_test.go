package config

import (
	"slices"
	"strings"
	"testing"
)

func serialYAML(block string) string {
	return strings.Replace(validYAML(), "console: { serial: bmcssh, graphical: vnc }",
		"console:\n      serial: bmcssh\n      graphical: vnc\n"+block, 1)
}

func TestSSHDefaultsPerKind(t *testing.T) {
	cfg := mustParse(t, validYAML())
	r730, _ := cfg.Server("r730xd")
	if r730.Console.SSH.Port != DefaultSSHPort || !slices.Equal(r730.Console.SSH.Quirks, []SSHQuirk{QuirkIDRAC8LegacySSH}) {
		t.Errorf("idrac8 ssh defaults = %+v", r730.Console.SSH)
	}
	if !r730.Console.SSH.Has(QuirkIDRAC8LegacySSH) {
		t.Error("Has(idrac8_legacy_ssh) = false")
	}
	r240, _ := cfg.Server("r240")
	if r240.Console.SSH.Port != DefaultSSHPort || len(r240.Console.SSH.Quirks) != 0 {
		t.Errorf("idrac9 ssh defaults = %+v", r240.Console.SSH)
	}
}

func TestSSHExplicitSettings(t *testing.T) {
	cfg := mustParse(t, serialYAML("      ssh: { port: 2222, quirks: [] }\n"))
	s, _ := cfg.Server("r730xd")
	if s.Console.SSH.Port != 2222 || len(s.Console.SSH.Quirks) != 0 {
		t.Errorf("explicit ssh = %+v", s.Console.SSH)
	}
}

func TestSSHServerCopyIsDeep(t *testing.T) {
	cfg := mustParse(t, validYAML())
	s, _ := cfg.Server("r730xd")
	s.Console.SSH.Quirks[0] = "mutated"
	again, _ := cfg.Server("r730xd")
	if again.Console.SSH.Quirks[0] != QuirkIDRAC8LegacySSH {
		t.Error("Server() leaked the ssh quirks slice")
	}
}

func TestSSHRejects(t *testing.T) {
	tests := map[string]struct{ block, want string }{
		"port":            {"      ssh: { port: 0x10000 }\n", "console.ssh.port"},
		"unknown quirk":   {"      ssh: { quirks: [telnet] }\n", "console.ssh.quirks"},
		"duplicate quirk": {"      ssh: { quirks: [idrac8_legacy_ssh, idrac8_legacy_ssh] }\n", "duplicate"},
		"unknown key":     {"      ssh: { command: shell }\n", "command"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(serialYAML(tc.block)))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want mention of %q", err, tc.want)
			}
		})
	}
}

// A missing host key is a setup step (the card says "Needs setup"), not a startup error:
// getting it needs a trusted first read of the BMC's key.
func TestBMCSSHWithoutHostKeyIsAccepted(t *testing.T) {
	src := strings.Replace(validYAML(), "    ssh_host_key: \""+testHostKey()+"\"\n", "", 1)
	cfg := mustParse(t, src)
	s, _ := cfg.Server("r730xd")
	if s.SSHHostKey != "" || s.Console.Serial != SerialBMCSSH {
		t.Errorf("server = %+v", s)
	}
}

func TestSSHHostKeyParses(t *testing.T) {
	cfg := mustParse(t, validYAML())
	s, _ := cfg.Server("r730xd")
	if s.SSHHostKey != testHostKey() {
		t.Errorf("host key = %q", s.SSHHostKey)
	}
}
