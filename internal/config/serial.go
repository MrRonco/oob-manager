package config

import "slices"

// DefaultSSHPort is the iDRAC SSH service port (bmcssh serial console).
const DefaultSSHPort = 22

// SSHQuirk is a closed enum of per-BMC SSH workarounds for the bmcssh serial console.
type SSHQuirk string

// QuirkIDRAC8LegacySSH adds the minimum legacy algorithms iDRAC8 2.8x needs: host key
// algorithm ssh-rsa (SHA-1 signatures, only when the pinned key is RSA) and key exchange
// diffie-hellman-group14-sha1. It is the default for kind idrac8; the app warns at
// startup for every server that uses it.
const QuirkIDRAC8LegacySSH SSHQuirk = "idrac8_legacy_ssh"

func allSSHQuirks() []SSHQuirk { return []SSHQuirk{QuirkIDRAC8LegacySSH} }

// SSHConfig is how the app reaches a BMC's SSH service for the serial console.
type SSHConfig struct {
	Port int `yaml:"port"`
	// Quirks: absent = the kind default; [] = none.
	Quirks []SSHQuirk `yaml:"quirks"`
}

// Has reports whether quirk q is set.
func (c SSHConfig) Has(q SSHQuirk) bool { return slices.Contains(c.Quirks, q) }

func (c SSHConfig) clone() SSHConfig {
	out := c
	if c.Quirks != nil {
		out.Quirks = slices.Clone(c.Quirks)
	}
	return out
}

func sshDefaults(kind BMCKind, c SSHConfig) SSHConfig {
	out := c.clone()
	if out.Port == 0 {
		out.Port = DefaultSSHPort
	}
	if out.Quirks == nil {
		out.Quirks = []SSHQuirk{}
		if kind == KindIDRAC8 {
			out.Quirks = allSSHQuirks()
		}
	}
	return out
}

func validateSSH(p problems, prefix string, s Server) problems {
	c := s.Console.SSH
	if c.Port < 1 || c.Port > 65535 {
		p = p.add("%s: console.ssh.port %d must be in [1, 65535]", prefix, c.Port)
	}
	seen := map[SSHQuirk]bool{}
	for _, q := range c.Quirks {
		switch {
		case !slices.Contains(allSSHQuirks(), q):
			p = p.add("%s: console.ssh.quirks: %q must be one of %v", prefix, q, allSSHQuirks())
		case seen[q]:
			p = p.add("%s: console.ssh.quirks: duplicate %q", prefix, q)
		}
		seen[q] = true
	}
	return p
}
