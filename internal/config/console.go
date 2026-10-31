package config

import (
	"slices"
	"strings"
	"time"
)

// Graphical console defaults and bounds (docs/tech_doc.md §18).
const (
	// DefaultVNCPort is the iDRAC VNC server's default port (VNCServer.1.Port).
	DefaultVNCPort     = 5901
	DefaultConsoleIdle = 15 * time.Minute
	DefaultConsoleMax  = 4 * time.Hour
	MinConsoleIdle     = time.Minute
	MaxConsoleIdle     = 2 * time.Hour
	MaxConsoleSession  = 12 * time.Hour
)

// VNCQuirk is a closed enum of per-BMC RFB workarounds applied by the console relay.
type VNCQuirk string

// Supported quirks. The first two iDRAC8 quirks together are the "black screen"
// workaround (docs/research/console.md §1.2); all three are the default for kind idrac8.
const (
	// QuirkIDRAC8SafeEncodings narrows the browser's SetEncodings to Raw, CopyRect and
	// DesktopSize.
	QuirkIDRAC8SafeEncodings VNCQuirk = "idrac8_safe_encodings"
	// QuirkIDRAC8LowColour makes noVNC request an 8-bit pixel format.
	QuirkIDRAC8LowColour VNCQuirk = "idrac8_low_colour"
	// QuirkIDRAC8RSAKexTLS adds the RSA key-exchange AES-GCM suites (no forward
	// secrecy) to the VNC TLS dial: iDRAC8 2.8x offers no ECDHE suite on its VNC port.
	// It never applies to the web/Redfish transport.
	QuirkIDRAC8RSAKexTLS VNCQuirk = "idrac8_rsa_kex_tls"
)

// allQuirks lists every supported quirk.
func allQuirks() []VNCQuirk {
	return []VNCQuirk{QuirkIDRAC8SafeEncodings, QuirkIDRAC8LowColour, QuirkIDRAC8RSAKexTLS}
}

func knownQuirk(q VNCQuirk) bool { return slices.Contains(allQuirks(), q) }

// defaultQuirks is the quirk set a kind gets when console.vnc.quirks is absent.
func defaultQuirks(k BMCKind) []VNCQuirk {
	if k == KindIDRAC8 {
		return allQuirks()
	}
	return []VNCQuirk{}
}

// VNCConfig is how the app reaches a BMC's VNC (RFB) server.
type VNCConfig struct {
	Port int `yaml:"port"`
	// TLS wraps the RFB stream in TLS (iDRAC "VNC SSL encryption"); default true.
	TLS *bool `yaml:"tls"`
	// PinSHA256 is the SPKI pin of the VNC port's certificate when it differs from the
	// web certificate; empty means the server's tls_pin_sha256.
	PinSHA256 string `yaml:"tls_pin_sha256"`
	// Quirks: absent = the kind default; [] = none.
	Quirks []VNCQuirk `yaml:"quirks"`
}

// TLSEnabled reports whether the relay dials the VNC port with TLS.
func (v VNCConfig) TLSEnabled() bool { return v.TLS == nil || *v.TLS }

// Has reports whether quirk q is set.
func (v VNCConfig) Has(q VNCQuirk) bool { return slices.Contains(v.Quirks, q) }

func (v VNCConfig) clone() VNCConfig {
	out := v
	if v.TLS != nil {
		on := *v.TLS
		out.TLS = &on
	}
	if v.Quirks != nil {
		out.Quirks = slices.Clone(v.Quirks)
	}
	return out
}

// VNCPin is the SPKI pin the relay checks on the VNC port: console.vnc.tls_pin_sha256,
// else the server's web pin.
func (s Server) VNCPin() string {
	if s.Console.VNC.PinSHA256 != "" {
		return s.Console.VNC.PinSHA256
	}
	return s.TLSPinSHA256
}

// ConsoleSettings are the app-wide console session limits.
type ConsoleSettings struct {
	IdleTimeout time.Duration `yaml:"idle_timeout"`
	MaxSession  time.Duration `yaml:"max_session"`
	// CloseOnStepUpExpiry ends a graphical console when the step-up window that opened
	// it lapses. Off by default: the console is bound to the session instead.
	CloseOnStepUpExpiry bool `yaml:"close_on_stepup_expiry"`
}

func consoleDefaults(c ConsoleSettings) ConsoleSettings {
	if c.IdleTimeout == 0 {
		c.IdleTimeout = DefaultConsoleIdle
	}
	if c.MaxSession == 0 {
		c.MaxSession = max(DefaultConsoleMax, c.IdleTimeout)
	}
	return c
}

func vncDefaults(kind BMCKind, v VNCConfig) VNCConfig {
	out := v.clone()
	if out.Port == 0 {
		out.Port = DefaultVNCPort
	}
	if out.Quirks == nil {
		out.Quirks = defaultQuirks(kind)
	}
	out.PinSHA256 = strings.ToLower(out.PinSHA256)
	return out
}

func validateConsoleSettings(p problems, c ConsoleSettings) problems {
	if c.IdleTimeout < MinConsoleIdle || c.IdleTimeout > MaxConsoleIdle {
		p = p.add("console.idle_timeout %v must be in [%v, %v]", c.IdleTimeout, MinConsoleIdle, MaxConsoleIdle)
	}
	if c.MaxSession < c.IdleTimeout || c.MaxSession > MaxConsoleSession {
		p = p.add("console.max_session %v must be in [console.idle_timeout, %v]", c.MaxSession, MaxConsoleSession)
	}
	return p
}

func validateVNC(p problems, prefix string, s Server) problems {
	v := s.Console.VNC
	if v.Port < 1 || v.Port > 65535 {
		p = p.add("%s: console.vnc.port %d must be in [1, 65535]", prefix, v.Port)
	}
	seen := map[VNCQuirk]bool{}
	for _, q := range v.Quirks {
		switch {
		case !knownQuirk(q):
			p = p.add("%s: console.vnc.quirks: %q must be one of %v", prefix, q, allQuirks())
		case seen[q]:
			p = p.add("%s: console.vnc.quirks: duplicate %q", prefix, q)
		}
		seen[q] = true
	}
	switch {
	case v.PinSHA256 != "" && !pinPattern.MatchString(v.PinSHA256):
		p = p.add("%s: console.vnc.tls_pin_sha256 must be 64 hex characters", prefix)
	case s.Console.Graphical == GraphicalVNC && v.TLSEnabled() && s.VNCPin() == "":
		p = p.add("%s: console.vnc.tls_pin_sha256 (or tls_pin_sha256) is required when console.vnc.tls is on", prefix)
	}
	return p
}
