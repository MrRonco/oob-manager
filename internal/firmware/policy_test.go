package firmware

import (
	"slices"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

var now = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func idrac8() ServerInfo {
	return ServerInfo{ID: "r730xd", Name: "R730XD", BMCKind: "idrac8", Model: "PowerEdge R730xd"}
}

func comp(kind bmc.FirmwareKind, id, fqdd, running string) Component {
	return Component{Key: Key{id, fqdd}, Kind: kind, Name: id, Running: running}
}

func TestRuleMatches(t *testing.T) {
	bios := comp(bmc.FirmwareBIOS, "159", "BIOS.Setup.1-1", "2.19.0")
	cases := []struct {
		r    Rule
		want bool
	}{
		{Rule{BMCKind: "idrac8", Version: "1"}, true},
		{Rule{BMCKind: "idrac9", Version: "1"}, false},
		{Rule{Kind: "bios", Version: "1"}, true},
		{Rule{Kind: "nic", Version: "1"}, false},
		{Rule{Model: "PowerEdge R730xd", Version: "1"}, true},
		{Rule{Model: "PowerEdge R440", Version: "1"}, false},
		{Rule{ComponentID: "159", Version: "1"}, true},
		{Rule{ComponentID: "160", Version: "1"}, false},
		{Rule{FQDD: "BIOS.Setup.1-1", Version: "1"}, true},
		{Rule{FQDD: "BIOS.*", Version: "1"}, true},
		{Rule{FQDD: "NIC.*", Version: "1"}, false},
		{Rule{FQDD: "BIOS.Setup", Version: "1"}, false}, // no glob: exact
		{Rule{BMCKind: "idrac8", Kind: "bios", ComponentID: "159", FQDD: "BIOS.*", Version: "1"}, true},
		{Rule{BMCKind: "idrac8", Kind: "nic", Version: "1"}, false}, // every key must match
		{Rule{Version: "1"}, false},                                 // no key matches nothing
	}
	for _, c := range cases {
		if got := c.r.matches(idrac8(), bios); got != c.want {
			t.Errorf("%+v matches = %v, want %v", c.r, got, c.want)
		}
	}
}

func TestEvaluateMinimums(t *testing.T) {
	p := NewPolicy(PolicyParams{
		Rules: []Rule{
			{BMCKind: "idrac8", Kind: "bios", Version: "2.20.0", Note: "BIOS fix"},
			{ComponentID: "106802", Version: "RS04"},
			{ComponentID: "101095", Version: "00.24.8"},
			{ComponentID: "25227", Version: "9.99"}, // never applies: the BMC's minimum is security.min_firmware
		},
		BMCMinimum: map[string]string{"idrac8": "2.86.86.86", "idrac9": "7.10.30.00"},
	})
	srv := idrac8()
	cases := []struct {
		c       Component
		primary Flag
		min     string
		source  string
	}{
		{comp(bmc.FirmwareBIOS, "159", "", "2.19.0"), FlagBelowMinimum, "2.20.0", SourceRules},
		{comp(bmc.FirmwareBIOS, "159", "", "2.20.0"), FlagOK, "2.20.0", SourceRules},
		{comp(bmc.FirmwareOther, "106802", "", "RS03"), FlagBelowMinimum, "RS04", SourceRules},
		{comp(bmc.FirmwareOther, "101095", "", "00.24.7A"), FlagCannotCompare, "00.24.8", SourceRules},
		{comp(bmc.FirmwareBMC, "25227", "", "2.86.86.86"), FlagOK, "2.86.86.86", "security.min_firmware.idrac8"},
		{comp(bmc.FirmwareBMC, "25227", "", "2.85.85.85"), FlagBelowMinimum, "2.86.86.86", "security.min_firmware.idrac8"},
		{comp(bmc.FirmwareNIC, "1", "", "1.0"), FlagNone, "", ""},
		{comp(bmc.FirmwareBIOS, "159", "", ""), FlagCannotCompare, "2.20.0", SourceRules}, // nothing runs
	}
	for _, c := range cases {
		v := p.Evaluate(srv, c.c, now)
		if v.Primary() != c.primary || v.Minimum != c.min || v.MinimumSource != c.source {
			t.Errorf("%s %s: %+v (primary %s)", c.c.ComponentID, c.c.Running, v, v.Primary())
		}
	}
	if v := p.Evaluate(srv, comp(bmc.FirmwareBIOS, "159", "", "2.19.0"), now); v.Note != "BIOS fix" {
		t.Errorf("the rule's note is kept: %+v", v)
	}
	// A BMC kind without a configured minimum: no rule at all.
	if v := p.Evaluate(ServerInfo{BMCKind: "redfish"}, comp(bmc.FirmwareBMC, "x", "", "1.0"), now); v.Primary() != FlagNone {
		t.Errorf("redfish bmc %+v", v)
	}
}

func TestEvaluateStrictestRuleWins(t *testing.T) {
	p := NewPolicy(PolicyParams{Rules: []Rule{
		{Kind: "bios", Version: "2.10"},
		{Kind: "bios", Version: "2.30"},
		{Kind: "bios", Version: "X1"},
	}})
	v := p.Evaluate(idrac8(), comp(bmc.FirmwareBIOS, "159", "", "2.20"), now)
	if v.Primary() != FlagBelowMinimum || v.Minimum != "2.30" {
		t.Fatalf("below beats cannot compare and ok: %+v", v)
	}
	p = NewPolicy(PolicyParams{Rules: []Rule{{Kind: "bios", Version: "2.10"}, {Kind: "bios", Version: "X1"}}})
	if v := p.Evaluate(idrac8(), comp(bmc.FirmwareBIOS, "159", "", "2.20"), now); v.Primary() != FlagCannotCompare || v.Minimum != "X1" {
		t.Fatalf("cannot compare beats ok: %+v", v)
	}
}

func TestEvaluateNotAppliedAndStale(t *testing.T) {
	c := comp(bmc.FirmwareEnclosure, "101434", "", "2.23")
	c.Stored = "2.25"
	c.ReleaseDate = now.AddDate(-4, 0, 0)
	off := NewPolicy(PolicyParams{})
	if v := off.Evaluate(idrac8(), c, now); !slices.Equal(v.Flags, []Flag{FlagNotApplied}) {
		t.Errorf("age flag off by default: %+v", v)
	}
	on := NewPolicy(PolicyParams{StaleAfter: 3 * Year, Rules: []Rule{{ComponentID: "101434", Version: "3.0"}}})
	v := on.Evaluate(idrac8(), c, now)
	if !slices.Equal(v.Flags, []Flag{FlagBelowMinimum, FlagNotApplied, FlagStale}) || v.Primary() != FlagBelowMinimum {
		t.Errorf("flags %+v", v)
	}
	c.ReleaseDate = now.AddDate(-2, 0, 0)
	if v := on.Evaluate(idrac8(), c, now); slices.Contains(v.Flags, FlagStale) {
		t.Errorf("a two-year-old release is not stale at 3y: %+v", v)
	}
	c.ReleaseDate = time.Time{}
	if v := on.Evaluate(idrac8(), c, now); slices.Contains(v.Flags, FlagStale) {
		t.Errorf("no release date, no age flag: %+v", v)
	}
}

func TestFlagsAndPolicyCopies(t *testing.T) {
	for _, f := range []Flag{FlagBelowMinimum, FlagCannotCompare, FlagNotApplied, FlagStale, FlagOK, FlagNone} {
		if f.Label() == "" && f != FlagNone {
			t.Errorf("flag %q has no label", f)
		}
	}
	if !FlagBelowMinimum.Warn() || FlagNotApplied.Warn() || FlagCannotCompare.Warn() || FlagStale.Warn() || FlagOK.Warn() {
		t.Error("only below minimum is a warning")
	}
	if !FlagCannotCompare.Flagged() || FlagOK.Flagged() || FlagNone.Flagged() {
		t.Error("flagged = anything but ok and none")
	}
	if Flag("x").Label() != "x" || Flag("x").rank() <= FlagNone.rank() {
		t.Error("unknown flag")
	}
	rules := []Rule{{Kind: "bios", Version: "1"}}
	mins := map[string]string{"idrac8": "1"}
	names := map[string]string{"1": "One"}
	p := NewPolicy(PolicyParams{Rules: rules, BMCMinimum: mins, Names: names})
	rules[0].Version, mins["idrac8"], names["1"] = "9", "9", "Changed"
	if p.Rules()[0].Version != "1" || p.BMCMinimum("idrac8") != "1" || p.Name("1") != "One" {
		t.Fatal("the policy copies its inputs")
	}
	if p.StaleAfter() != 0 || p.Name("2") != "" {
		t.Fatal("defaults")
	}
}
