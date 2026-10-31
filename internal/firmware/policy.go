package firmware

import (
	"maps"
	"slices"
	"strings"
	"time"

	"oob-manager/internal/bmc"
)

// Year is 365 days, the unit of firmware.stale_after ("3y").
const Year = 365 * 24 * time.Hour

// SourceRules names where a non-BMC minimum comes from (config.yaml firmware.minimum).
const SourceRules = "firmware.minimum"

// Rule is one "minimum known good" entry of firmware.minimum. Every match key that is
// set must match; a rule without any key matches nothing (config validation refuses
// it). FQDD may end in "*" (prefix match). Rules never apply to the BMC's own firmware:
// that minimum is security.min_firmware (one source of truth, shared with the security
// check fw.bmc).
type Rule struct {
	BMCKind     string // config BMC kind: idrac8, idrac9, redfish
	Kind        string // component kind (bmc.FirmwareKind, never "bmc")
	Model       string // system model, exact
	ComponentID string
	FQDD        string
	Version     string
	Note        string
}

// ServerInfo is what rules match on besides the component.
type ServerInfo struct {
	ID, Name string
	BMCKind  string // config kind
	Model    string // system model from the inventory ("" when not read yet)
	SystemID string // vendor system ID for the update check ("" unknown)
}

func (r Rule) matches(s ServerInfo, c Component) bool {
	if r.BMCKind == "" && r.Kind == "" && r.Model == "" && r.ComponentID == "" && r.FQDD == "" {
		return false
	}
	return (r.BMCKind == "" || r.BMCKind == s.BMCKind) &&
		(r.Kind == "" || r.Kind == string(c.Kind)) &&
		(r.Model == "" || r.Model == s.Model) &&
		(r.ComponentID == "" || r.ComponentID == c.ComponentID) &&
		(r.FQDD == "" || fqddMatch(r.FQDD, c.FQDD))
}

func fqddMatch(pattern, fqdd string) bool {
	if prefix, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(fqdd, prefix)
	}
	return pattern == fqdd
}

// PolicyParams are the inputs of NewPolicy (all copied).
type PolicyParams struct {
	Rules []Rule
	// BMCMinimum is security.min_firmware: the minimum of the BMC's own firmware per
	// config kind ("" or absent: none).
	BMCMinimum map[string]string
	// StaleAfter > 0 turns a release older than this into the Stale release flag.
	StaleAfter time.Duration
	// Names are display names per component ID for components no document names.
	Names map[string]string
}

// Policy is the immutable evaluation input built from config.yaml.
type Policy struct {
	rules      []Rule
	bmcMinimum map[string]string
	staleAfter time.Duration
	names      map[string]string
}

// NewPolicy builds a policy, copying p.
func NewPolicy(p PolicyParams) Policy {
	return Policy{rules: slices.Clone(p.Rules), bmcMinimum: maps.Clone(p.BMCMinimum),
		staleAfter: max(p.StaleAfter, 0), names: maps.Clone(p.Names)}
}

// Rules returns a copy of the rules.
func (p Policy) Rules() []Rule { return slices.Clone(p.rules) }

// BMCMinimum is security.min_firmware for a config kind.
func (p Policy) BMCMinimum(kind string) string { return p.bmcMinimum[kind] }

// StaleAfter is the age flag threshold (0: off).
func (p Policy) StaleAfter() time.Duration { return p.staleAfter }

// Name is the configured display name of a component ID ("" when none).
func (p Policy) Name(componentID string) string { return p.names[componentID] }

// Verdict is the evaluation of one component: its flags, worst first (empty: no rule
// matched and nothing is wrong), and the minimum that decided it.
type Verdict struct {
	Flags         []Flag
	Minimum       string
	MinimumSource string // SourceRules or "security.min_firmware.<kind>"
	Note          string
}

// Primary is the worst flag; FlagOK when a minimum applied and passed; FlagNone when
// nothing applied.
func (v Verdict) Primary() Flag {
	if len(v.Flags) > 0 {
		return v.Flags[0]
	}
	if v.Minimum != "" {
		return FlagOK
	}
	return FlagNone
}

// Evaluate judges c of server s at now. Age is information: it only flags when
// StaleAfter is set.
func (p Policy) Evaluate(s ServerInfo, c Component, now time.Time) Verdict {
	var v Verdict
	if minimum, source, note, ok := p.minimum(s, c); ok {
		v.Minimum, v.MinimumSource, v.Note = minimum, source, note
		switch cmp, known := CompareVersions(c.Running, minimum); {
		case !known:
			v.Flags = append(v.Flags, FlagCannotCompare)
		case cmp < 0:
			v.Flags = append(v.Flags, FlagBelowMinimum)
		}
	}
	if c.NotApplied() {
		v.Flags = append(v.Flags, FlagNotApplied)
	}
	if p.staleAfter > 0 && !c.ReleaseDate.IsZero() && now.Sub(c.ReleaseDate) > p.staleAfter {
		v.Flags = append(v.Flags, FlagStale)
	}
	sortFlags(v.Flags)
	return v
}

func sortFlags(f []Flag) {
	slices.SortStableFunc(f, func(a, b Flag) int { return a.rank() - b.rank() })
}

// minimum picks the minimum that decides c: the BMC's own from security.min_firmware;
// otherwise, of the matching rules, the first that the running version is below, else
// the first it cannot be compared with, else the highest that passes.
func (p Policy) minimum(s ServerInfo, c Component) (version, source, note string, ok bool) {
	if c.Kind == bmc.FirmwareBMC {
		m := p.bmcMinimum[s.BMCKind]
		return m, "security.min_firmware." + s.BMCKind, "", m != ""
	}
	var best *Rule
	bestRank := FlagNone.rank() + 1
	for i := range p.rules {
		r := &p.rules[i]
		if !r.matches(s, c) {
			continue
		}
		rank := FlagOK.rank()
		switch cmp, known := CompareVersions(c.Running, r.Version); {
		case !known:
			rank = FlagCannotCompare.rank()
		case cmp < 0:
			rank = FlagBelowMinimum.rank()
		}
		if best == nil || rank < bestRank || (rank == bestRank && rank == FlagOK.rank() && higher(r.Version, best.Version)) {
			best, bestRank = r, rank
		}
	}
	if best == nil {
		return "", "", "", false
	}
	return best.Version, SourceRules, best.Note, true
}

func higher(a, b string) bool {
	c, ok := CompareVersions(a, b)
	return ok && c > 0
}
