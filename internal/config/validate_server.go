package config

import (
	"encoding/base64"
	"encoding/binary"
	"net"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Compiled once, never mutated.
var (
	idPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	refPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	pinPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	namePattern = regexp.MustCompile(`^[\pL\pN][\pL\pN ._()-]{0,63}$`)
)

// Fan floors. GlobalFanFloor applies to every mode that writes fans.
const (
	GlobalFanFloor = 20
	// HostLeaseFloor matches SAFE_MIN_PCT in the R730XD host script (decision 5).
	HostLeaseFloor = 30
	// DellMinFanSpeedLow is the lowest ThermalSettings.1.MinimumFanSpeed the iDRAC9 accepts
	// (MFSMinimumLimit = 35 on fw 7.00); the live limits are still read and clamped to.
	DellMinFanSpeedLow = 35
	IPMIOEMFloor       = 30
	MaxHostLease       = 2 * time.Hour
	MaxIPMIOEMLease    = 60 * time.Minute
)

type fanRule struct {
	kinds    []BMCKind
	minFloor int
	maxLease time.Duration
}

func fanRuleFor(m FanMode) (fanRule, bool) {
	switch m {
	case FanHostLease:
		return fanRule{[]BMCKind{KindIDRAC8}, HostLeaseFloor, MaxHostLease}, true
	case FanRedfishFloor:
		return fanRule{[]BMCKind{KindIDRAC9}, DellMinFanSpeedLow, MaxHostLease}, true
	case FanIPMIOEM:
		return fanRule{[]BMCKind{KindIDRAC8, KindIDRAC9}, IPMIOEMFloor, MaxIPMIOEMLease}, true
	default:
		return fanRule{}, false
	}
}

// ValidateServer checks one normalised server (Normalise, or a server of a loaded
// Config) with exactly the rules config.yaml servers get. It returns one message per
// problem, prefixed with the server's ID; the same function validates servers saved
// from the browser (settings_design.md §2: one validator for both sources).
func ValidateServer(s Server) []string {
	return validateServer(nil, "server "+s.ID, s)
}

func validateServer(p problems, prefix string, s Server) problems {
	if !idPattern.MatchString(s.ID) {
		p = p.add("%s: id must match %s", prefix, idPattern)
	}
	if !namePattern.MatchString(s.Name) {
		p = p.add("%s: name %q is empty or has unsupported characters", prefix, s.Name)
	}
	for _, tag := range s.Tags {
		if !idPattern.MatchString(tag) {
			p = p.add("%s: tags: %q must match %s", prefix, tag, idPattern)
		}
	}
	p = validateBMC(p, prefix, s)
	p = validateFan(p, prefix, s)
	p = validateConsole(p, prefix, s)
	p = validateVNC(p, prefix, s)
	p = validatePower(p, prefix, s.Power)
	p = validateSSH(p, prefix, s)
	return validateCredentials(p, prefix, s)
}

func validateBMC(p problems, prefix string, s Server) problems {
	if ip := net.ParseIP(s.BMC.Address); ip == nil {
		p = p.add("%s: bmc.address %q must be a literal IP address", prefix, s.BMC.Address)
	}
	switch s.BMC.Kind {
	case KindIDRAC8, KindIDRAC9, KindRedfish:
		if !pinPattern.MatchString(s.TLSPinSHA256) {
			p = p.add("%s: tls_pin_sha256 must be 64 hex characters (SHA-256 of the BMC SPKI)", prefix)
		}
	case KindIPMI:
		if s.TLSPinSHA256 != "" && !pinPattern.MatchString(s.TLSPinSHA256) {
			p = p.add("%s: tls_pin_sha256 must be 64 hex characters", prefix)
		}
	default:
		p = p.add("%s: bmc.kind %q must be one of idrac8, idrac9, redfish, ipmi", prefix, s.BMC.Kind)
	}
	if s.SSHHostKey != "" && !validHostKey(s.SSHHostKey) {
		p = p.add("%s: ssh_host_key is not a valid authorized-key line", prefix)
	}
	return validateBMCTuning(p, prefix, s.BMC)
}

func validateFan(p problems, prefix string, s Server) problems {
	f := s.Fan
	if f.Mode == FanNone {
		return p
	}
	rule, ok := fanRuleFor(f.Mode)
	if !ok {
		return p.add("%s: fan.mode %q must be one of host-lease, redfish-floor, ipmi-oem, none", prefix, f.Mode)
	}
	if !slices.Contains(rule.kinds, s.BMC.Kind) {
		p = p.add("%s: fan.mode %s is not allowed for bmc.kind %s", prefix, f.Mode, s.BMC.Kind)
	}
	switch {
	case f.SafeMinPct < GlobalFanFloor || f.SafeMinPct > 100:
		p = p.add("%s: fan.safe_min_pct %d must be in [%d, 100]", prefix, f.SafeMinPct, GlobalFanFloor)
	case f.SafeMinPct < rule.minFloor:
		p = p.add("%s: fan.safe_min_pct %d is below %d required for mode %s", prefix, f.SafeMinPct, rule.minFloor, f.Mode)
	}
	switch {
	case f.MaxLease <= 0:
		p = p.add("%s: fan.max_lease is required", prefix)
	case f.MaxLease > rule.maxLease:
		p = p.add("%s: fan.max_lease %v exceeds %v for mode %s", prefix, f.MaxLease, rule.maxLease, f.Mode)
	}
	return p
}

func validateConsole(p problems, prefix string, s Server) problems {
	isDell := s.BMC.Kind == KindIDRAC8 || s.BMC.Kind == KindIDRAC9
	switch s.Console.Serial {
	case SerialBMCSSH:
		if !isDell {
			p = p.add("%s: console.serial bmcssh needs an iDRAC (got %s)", prefix, s.BMC.Kind)
		}
	case SerialSOL, SerialNone:
	default:
		p = p.add("%s: console.serial %q must be one of bmcssh, sol, none", prefix, s.Console.Serial)
	}
	switch s.Console.Graphical {
	case GraphicalVNC:
		if s.Credentials.VNC == "" {
			p = p.add("%s: credentials.vnc is required for console.graphical vnc", prefix)
		}
	case GraphicalKVMLaunch:
		if s.BMC.Kind != KindIDRAC9 {
			p = p.add("%s: console.graphical kvm-launch needs idrac9 (got %s)", prefix, s.BMC.Kind)
		}
	case GraphicalLink, GraphicalNone:
	default:
		p = p.add("%s: console.graphical %q must be one of vnc, kvm-launch, link, none", prefix, s.Console.Graphical)
	}
	return p
}

func validateCredentials(p problems, prefix string, s Server) problems {
	c := s.Credentials
	if !refPattern.MatchString(c.ReadOnly) {
		p = p.add("%s: credentials.readonly %q must match %s", prefix, c.ReadOnly, refPattern)
	}
	refs := map[string]string{"operator": c.Operator, "vnc": c.VNC}
	for _, key := range sortedKeys(refs) {
		ref := refs[key]
		if ref != "" && !refPattern.MatchString(ref) {
			p = p.add("%s: credentials.%s %q must match %s", prefix, key, ref, refPattern)
		}
	}
	if c.Operator != "" {
		return p
	}
	for _, feature := range operatorFeatures(s) {
		p = p.add("%s: credentials.operator is required for %s", prefix, feature)
	}
	return p
}

// operatorFeatures names the configured features that log in with the operator account:
// the BMC fan floor (redfish-floor, ipmi-oem), the serial console and the native KVM
// launch. host-lease fans only write a file, the VNC console needs only credentials.vnc,
// and power control is optional: without an operator login it stays off with that reason.
func operatorFeatures(s Server) []string {
	var out []string
	if s.Fan.Mode == FanRedfishFloor || s.Fan.Mode == FanIPMIOEM {
		out = append(out, "fan.mode "+string(s.Fan.Mode))
	}
	if s.Console.Serial != SerialNone {
		out = append(out, "console.serial "+string(s.Console.Serial))
	}
	if s.Console.Graphical == GraphicalKVMLaunch {
		out = append(out, "console.graphical "+string(s.Console.Graphical))
	}
	return out
}

// validHostKey checks "<algo> <base64> [comment]" and that the blob names the same algo.
func validHostKey(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 2 || len(fields) > 3 {
		return false
	}
	switch fields[0] {
	case "ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa":
	default:
		return false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(blob) < 4 {
		return false
	}
	n := binary.BigEndian.Uint32(blob[:4])
	if int64(n) > int64(len(blob)-4) {
		return false
	}
	return string(blob[4:4+n]) == fields[0]
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
