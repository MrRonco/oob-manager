package config

import (
	"regexp"
	"time"
)

// BMC security check bounds (tech_doc §31).
const (
	// DefaultSecurityEvery is the slow tier the checks run on.
	DefaultSecurityEvery = 6 * time.Hour
	// MinSecurityEvery and MaxSecurityEvery bound security.every: a run is a few dozen
	// BMC reads and handshakes, and "Re-run checks" covers the urgent case.
	MinSecurityEvery = time.Hour
	MaxSecurityEvery = 7 * 24 * time.Hour
)

// firmwarePattern is a dotted numeric firmware version, the only shape the firmware
// check compares ("2.86.86.86", "7.10"): text is never ordered by guesswork.
var firmwarePattern = regexp.MustCompile(`^[0-9]{1,9}(\.[0-9]{1,9}){0,5}$`)

// SecurityConfig is the `security:` section: the read-only BMC security checks. It is
// file-only: which firmware is acceptable is not a browser setting.
type SecurityConfig struct {
	// Enabled runs the checks for every Redfish server (default true). Off, no server
	// has a Security tab and nothing beyond the normal polling reaches a BMC.
	Enabled *bool `yaml:"enabled"`
	// Every is how often each server's checks run (default 6h, in [1h, 168h]).
	Every time.Duration `yaml:"every"`
	// MinFirmware is the oldest BMC firmware accepted per kind ("minimum known good").
	MinFirmware MinFirmware `yaml:"min_firmware"`
}

// MinFirmware holds one version per BMC kind; empty means none is configured (the
// firmware check then reports the version only). Nothing is looked up online.
type MinFirmware struct {
	IDRAC8  string `yaml:"idrac8"`
	IDRAC9  string `yaml:"idrac9"`
	Redfish string `yaml:"redfish"`
}

// On reports the effective enabled flag.
func (s SecurityConfig) On() bool { return s.Enabled == nil || *s.Enabled }

// For is the minimum known good version of kind k ("" = none).
func (m MinFirmware) For(k BMCKind) string {
	switch k {
	case KindIDRAC8:
		return m.IDRAC8
	case KindIDRAC9:
		return m.IDRAC9
	case KindRedfish:
		return m.Redfish
	default:
		return ""
	}
}

func securityDefaults(s SecurityConfig) SecurityConfig {
	if s.Enabled != nil {
		on := *s.Enabled
		s.Enabled = &on
	}
	if s.Every == 0 {
		s.Every = DefaultSecurityEvery
	}
	return s
}

func validateSecurity(p problems, s SecurityConfig) problems {
	if s.Every < MinSecurityEvery || s.Every > MaxSecurityEvery {
		p = p.add("security.every %v must be in [%v, %v]", s.Every, MinSecurityEvery, MaxSecurityEvery)
	}
	for _, f := range []struct{ key, v string }{{"idrac8", s.MinFirmware.IDRAC8}, {"idrac9", s.MinFirmware.IDRAC9},
		{"redfish", s.MinFirmware.Redfish}} {
		if f.v != "" && !firmwarePattern.MatchString(f.v) {
			p = p.add("security.min_firmware.%s %q must be a dotted numeric version such as 2.86.86.86", f.key, f.v)
		}
	}
	return p
}
