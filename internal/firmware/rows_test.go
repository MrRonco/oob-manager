package firmware

import (
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

func TestDisplayName(t *testing.T) {
	p := NewPolicy(PolicyParams{Names: map[string]string{"101068": "Backplane expander"}})
	cases := []struct {
		c    Component
		want string
	}{
		{Component{Key: Key{ComponentID: "101434"}, Name: "Backplane 0", Named: true}, "Backplane 0"},
		{Component{Key: Key{ComponentID: "101068"}, Name: "Component 101068"}, "Backplane expander"},
		{Component{Key: Key{ComponentID: "101068"}, Name: "BP13G+EXP 0:1", Named: true}, "BP13G+EXP 0:1"}, // a document wins
		{Component{Key: Key{ComponentID: "106802"}, Name: "Component 106802"}, "Unnamed component (ID 106802)"},
		{Component{Key: Key{ComponentID: "x"}, Name: ""}, "Unnamed component (ID x)"},
		{Component{Key: Key{ComponentID: "159"}, Name: "BIOS"}, "BIOS"},
	}
	for _, c := range cases {
		if got := p.DisplayName(c.c); got != c.want {
			t.Errorf("DisplayName(%+v) = %q, want %q", c.c, got, c.want)
		}
	}
}

func TestReleaseText(t *testing.T) {
	cases := []struct {
		at   time.Time
		want string
	}{
		{time.Time{}, ""},
		{time.Date(2025, 9, 27, 0, 0, 0, 0, time.UTC), "2025-09 (1 y 0 mo ago)"},
		{time.Date(2024, 7, 25, 0, 0, 0, 0, time.UTC), "2024-07 (2 y 2 mo ago)"},
		{time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC), "2026-08 (1 mo ago)"},
		{time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), "2026-10 (this month)"},
		{time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC), "2027-01"}, // a future date: no age
	}
	for _, c := range cases {
		if got := ReleaseText(c.at, now); got != c.want {
			t.Errorf("ReleaseText(%v) = %q, want %q", c.at, got, c.want)
		}
	}
}

func row(server string, k bmc.FirmwareKind, id, name string, flags ...Flag) Row {
	return Row{Server: ServerInfo{ID: server, Name: server}, Component: Component{Key: Key{ComponentID: id}, Kind: k,
		Running: "1.0"}, Verdict: Verdict{Flags: flags}, Display: name}
}

func TestSortRows(t *testing.T) {
	rows := []Row{
		row("b", bmc.FirmwareNIC, "3", "NIC"),
		row("a", bmc.FirmwareNIC, "3", "NIC"),
		row("a", bmc.FirmwareBIOS, "1", "BIOS"),
		row("a", bmc.FirmwareOther, "9", "Z", FlagCannotCompare),
		row("a", bmc.FirmwareEnclosure, "2", "Backplane", FlagNotApplied),
		row("b", bmc.FirmwareBIOS, "1", "BIOS", FlagBelowMinimum),
	}
	SortRows(rows)
	want := []string{"b/1", "a/2", "a/9", "a/1", "a/3", "b/3"}
	for i, r := range rows {
		if got := r.Server.ID + "/" + r.ComponentID; got != want[i] {
			t.Fatalf("position %d = %s, want %v", i, got, want)
		}
	}
}

func TestFilter(t *testing.T) {
	r := row("r730xd", bmc.FirmwareBIOS, "159", "BIOS", FlagBelowMinimum)
	r.Server.Name, r.FQDD, r.Previous = "R730XD", "BIOS.Setup.1-1", "2.18.1"
	ok := row("r240", bmc.FirmwareNIC, "105897", "Broadcom NIC")
	cases := []struct {
		f    Filter
		r    Row
		want bool
	}{
		{Filter{}, r, true},
		{Filter{ServerID: "r730xd"}, r, true},
		{Filter{ServerID: "r240"}, r, false},
		{Filter{Kind: bmc.FirmwareBIOS}, r, true},
		{Filter{Kind: bmc.FirmwareNIC}, r, false},
		{Filter{Flagged: true}, r, true},
		{Filter{Flagged: true}, ok, false},
		{Filter{Text: "bios.setup"}, r, true},
		{Filter{Text: "2.18"}, r, true},
		{Filter{Text: "r730"}, r, true},
		{Filter{Text: "broadcom"}, r, false},
		{Filter{Text: "  BROADCOM "}, ok, true},
	}
	for _, c := range cases {
		if got := c.f.Match(c.r); got != c.want {
			t.Errorf("%+v.Match(%s) = %v", c.f, c.r.Display, got)
		}
	}
	if (Filter{}).Active() || !(Filter{Flagged: true}).Active() {
		t.Error("Active")
	}
}

func TestBuildRows(t *testing.T) {
	p := NewPolicy(PolicyParams{Rules: []Rule{{Kind: "bios", Version: "2.20.0"}}})
	recs := []Record{
		{Component: Component{Key: Key{ComponentID: "159"}, Kind: bmc.FirmwareBIOS, Name: "BIOS", Running: "2.19.0"},
			FirstSeen: now.Add(-time.Hour), LastSeen: now},
		{Component: Component{Key: Key{ComponentID: "1"}, Kind: bmc.FirmwareOther, Name: "Component 1", Running: "1"}},
	}
	rows := BuildRows(p, idrac8(), recs, now, nil)
	if len(rows) != 2 || rows[0].Primary() != FlagBelowMinimum || rows[0].Server.ID != "r730xd" ||
		rows[1].Display != "Unnamed component (ID 1)" || !rows[0].LastSeen.Equal(now) {
		t.Fatalf("rows %+v", rows)
	}
}
