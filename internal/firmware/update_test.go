package firmware

import (
	"testing"
	"time"

	"oob-manager/internal/firmware/catalog"
)

type fakeIndex map[string]Update

func (f fakeIndex) Update(_ ServerInfo, c Component) Update   { return f[c.ComponentID] }
func (f fakeIndex) Coverage(ServerInfo, []Component) Coverage { return Coverage{} }

func TestUpdateFlagsJoinTheVerdict(t *testing.T) {
	p := NewPolicy(PolicyParams{Rules: []Rule{{ComponentID: "159", Version: "2.30.0"}}})
	s := ServerInfo{ID: "a", BMCKind: "idrac9"}
	recs := []Record{
		{Component: Component{Key: Key{ComponentID: "159"}, Kind: "bios", Running: "2.20.0"}},
		{Component: Component{Key: Key{ComponentID: "25227"}, Kind: "bmc", Running: "7.00"}},
		{Component: Component{Key: Key{ComponentID: "1"}, Kind: "nic", Running: "1.0"}},
		{Component: Component{Key: Key{ComponentID: "2"}, Kind: "nic", Running: "1.0"}},
	}
	idx := fakeIndex{
		"159":   {State: UpdateAvailable, Latest: catalog.Release{Version: "2.25.2"}},
		"25227": {State: UpdateUrgent, Latest: catalog.Release{Version: "7.01", Criticality: catalog.CriticalityUrgent}},
		"1":     {State: UpdateSkipped},
		"2":     {State: UpdateCurrent},
	}
	rows := BuildRows(p, s, recs, time.Unix(0, 0), idx)
	if got := rows[0].Flags; len(got) != 2 || got[0] != FlagBelowMinimum || got[1] != FlagUpdateAvailable {
		t.Fatalf("BIOS flags %v", got)
	}
	if rows[1].Primary() != FlagUpdateUrgent || !rows[1].Primary().Warn() || !rows[1].Update.Newer() {
		t.Fatalf("iDRAC %v", rows[1].Flags)
	}
	if rows[2].Primary() != FlagNone || rows[2].Update.Newer() || rows[3].Primary() != FlagNone {
		t.Fatalf("skipped/current rows flagged: %v %v", rows[2].Flags, rows[3].Flags)
	}
	if FlagUpdateAvailable.Warn() || !FlagUpdateAvailable.Flagged() || FlagUpdateAvailable.Label() != "Update available" ||
		FlagUpdateUrgent.Label() != "Urgent update" {
		t.Error("flag properties")
	}
	if FlagUpdateUrgent.rank() >= FlagNotApplied.rank() || FlagNotApplied.rank() >= FlagUpdateAvailable.rank() ||
		FlagBelowMinimum.rank() >= FlagUpdateUrgent.rank() {
		t.Error("rank order: below minimum, urgent, not applied, available")
	}
	if rows := BuildRows(p, s, recs, time.Unix(0, 0), nil); rows[1].Update.State != UpdateNone || len(rows[1].Flags) != 0 {
		t.Fatal("no index still judged updates")
	}
	f := Filter{Updates: true}
	upd := BuildRows(p, s, recs, time.Unix(0, 0), idx)
	if !f.Match(upd[0]) || !f.Match(upd[1]) || f.Match(upd[2]) || f.Match(upd[3]) || !f.Active() {
		t.Error("updates filter keeps newer releases only")
	}
}
