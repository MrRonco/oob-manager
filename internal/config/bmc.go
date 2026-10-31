package config

import (
	"net"
	"net/netip"
	"strconv"
	"time"
)

// BMC ports.
const (
	DefaultBMCPort  = 443
	DefaultIPMIPort = 623
	// MinCustomPort is the lowest non-default Redfish port accepted (no well-known
	// service ports below it).
	MinCustomPort = 1024
)

// DefaultBMCNetworks is settings.bmc_networks when absent: the private ranges.
func DefaultBMCNetworks() []string {
	return []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}
}

// Endpoint is the Redfish base URL of the BMC: https://<literal IP>:<port> (a zero
// port, in a hand-built value, is the default 443).
func (b BMCConfig) Endpoint() string {
	port := b.Port
	if port == 0 {
		port = DefaultBMCPort
	}
	return "https://" + net.JoinHostPort(b.Address, strconv.Itoa(port))
}

// BMCNetworks returns settings.bmc_networks parsed (validated at load; fresh slice).
func (c Config) BMCNetworks() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(c.Settings.BMCNetworks))
	for _, s := range c.Settings.BMCNetworks {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}

// BMCAuth selects the Redfish authentication scheme.
type BMCAuth string

// Supported Redfish auth schemes.
const (
	BMCAuthSession BMCAuth = "session" // one X-Auth-Token session per server (default)
	BMCAuthBasic   BMCAuth = "basic"   // HTTP Basic on every request (no SessionService)
)

// BMCTimeouts bound BMC work: Request is one HTTP request, Cycle is one poll tier.
type BMCTimeouts struct {
	Request time.Duration `yaml:"request"`
	Cycle   time.Duration `yaml:"cycle"`
}

// Bounds for bmc.timeouts.
const (
	MinRequestTimeout = 5 * time.Second
	MaxRequestTimeout = 2 * time.Minute
	MaxCycleTimeout   = 10 * time.Minute
)

// DefaultTimeouts are the per-kind defaults. iDRAC8 (13G) is slow: measured on fw 2.86,
// every Basic-auth GET took 5.5–9.5 s, a session login ~6.6 s and session GETs 1–3.4 s.
func DefaultTimeouts(k BMCKind) BMCTimeouts {
	if k == KindIDRAC8 {
		return BMCTimeouts{Request: 30 * time.Second, Cycle: 150 * time.Second}
	}
	return BMCTimeouts{Request: 15 * time.Second, Cycle: 60 * time.Second}
}

// PollInterval is the effective poll interval of s: poll.interval, raised to the
// server's cycle timeout so a cycle always fits in an interval.
func (c Config) PollInterval(s Server) time.Duration {
	return max(c.Poll.Interval, s.BMC.Timeouts.Cycle)
}

// bmcDefaults fills auth and any zero timeout from the kind defaults.
func bmcDefaults(b BMCConfig) BMCConfig {
	if b.Auth == "" {
		b.Auth = BMCAuthSession
	}
	if b.Port == 0 {
		b.Port = DefaultBMCPort
		if b.Kind == KindIPMI {
			b.Port = DefaultIPMIPort
		}
	}
	def := DefaultTimeouts(b.Kind)
	if b.Timeouts.Request == 0 {
		b.Timeouts.Request = def.Request
	}
	if b.Timeouts.Cycle == 0 {
		b.Timeouts.Cycle = def.Cycle
	}
	return b
}

// validPort: 443 (or 623 for ipmi), or any port from MinCustomPort up.
func validPort(b BMCConfig) bool {
	def := b.Port == DefaultBMCPort
	if b.Kind == KindIPMI {
		def = b.Port == DefaultIPMIPort
	}
	return def || (b.Port >= MinCustomPort && b.Port <= 65535)
}

func validateBMCTuning(p problems, prefix string, b BMCConfig) problems {
	if !validPort(b) {
		p = p.add("%s: bmc.port %d must be %d (ipmi: %d) or in [%d, 65535]", prefix, b.Port, DefaultBMCPort,
			DefaultIPMIPort, MinCustomPort)
	}
	if b.Auth != BMCAuthSession && b.Auth != BMCAuthBasic {
		p = p.add("%s: bmc.auth %q must be session or basic", prefix, b.Auth)
	}
	t := b.Timeouts
	if t.Request < MinRequestTimeout || t.Request > MaxRequestTimeout {
		p = p.add("%s: bmc.timeouts.request %v must be in [%v, %v]", prefix, t.Request, MinRequestTimeout, MaxRequestTimeout)
	}
	if t.Cycle < t.Request || t.Cycle > MaxCycleTimeout {
		p = p.add("%s: bmc.timeouts.cycle %v must be in [bmc.timeouts.request (%v), %v]", prefix, t.Cycle, t.Request, MaxCycleTimeout)
	}
	return p
}
