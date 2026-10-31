package fwinventory

import (
	"cmp"
	"context"
	"slices"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/textclean"
	"oob-manager/internal/firmware"
	"oob-manager/internal/notify"
	"oob-manager/internal/store"
)

// Bounds of stored strings (migration 0014).
const (
	maxIDLen      = 128
	maxNameLen    = 128
	maxVersionLen = 64
)

// Bounds of one server's view (security review S-M1, S-M3).
const (
	// MaxRowsPerServer caps the rows kept for a server: incomplete scans keep the
	// components they did not list, newest first, up to this many rows in all.
	MaxRowsPerServer = 2 * bmc.MaxFirmwareMembers
	// UnlistedExpiry drops a component no scan has listed for this long, even when the
	// scans are incomplete.
	UnlistedExpiry = 30 * 24 * time.Hour
	// MaxChangesPerScan caps the change rows and audit rows one scan writes; the rest is
	// counted in one summary audit row.
	MaxChangesPerScan = 16
)

// Record implements fleet.FirmwareSink: it merges the scan into one row per component,
// keeps what earlier member documents taught (names are sticky), detects the version
// changes and stores the server's rows, the changes (at most MaxChangesPerScan, plus a
// summary audit row) and one audit row per stored change (principal system) in one
// transaction, then sends one notification for the scan. The first scan of a server
// records no change. An incomplete scan (the member cap or the budget cut it, a document
// failed), or one that listed nothing while rows exist (a BMC glitch is not every
// component disappearing), records no removal: it keeps the components and states it did
// not list (platform firmware first, then the newest) up to MaxRowsPerServer rows, and
// drops only those no scan has listed for UnlistedExpiry. When there are more than
// MaxChangesPerScan changes, the platform firmware's running versions are recorded first.
func (s *Service) Record(ctx context.Context, id string, scan bmc.FirmwareScan, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.state.Load()
	old := cur.recs[id]
	merged := sanitize(firmware.Merge(scan.Items()))
	complete := scan.Complete() && (len(merged) > 0 || len(old) == 0)
	next := s.nextRecords(old, merged, complete, at)
	changes := prioritise(firmware.Diff(components(old), components(next), complete), old, next)
	row := store.FirmwareScanRow{ServerID: id, ScannedAt: at, Listed: scan.Listed(), Components: len(next),
		Complete: complete, DocsRead: scan.DocsRead(), DocsFailed: scan.DocsFailed(), Model: s.modelOf(id, cur),
		SystemID: s.systemIDOf(id, cur)}
	names := s.namesOf(old, next)
	if err := s.persist(ctx, row, next, changes, names); err != nil {
		return err
	}
	st := cur.clone()
	st.recs[id], st.scans[id] = next, row
	st.changes[id] += int64(len(changes))
	s.state.Store(st)
	s.warn.Store(nil)
	s.notifyChanges(id, changes, names, at)
	return nil
}

// modelOf is the system model rules match on: the fleet's inventory, else the one kept
// with the last scan (the inventory is not read yet after a restart).
func (s *Service) modelOf(id string, st *state) string {
	if srv, ok := s.cfg.Fleet.Server(id); ok && srv.HasInventory && srv.Inventory.Info().Model != "" {
		return textclean.Clean(srv.Inventory.Info().Model, maxNameLen)
	}
	return st.scans[id].Model
}

// systemIDOf is the vendor system ID the catalog matches on, from the same sources as
// modelOf.
func (s *Service) systemIDOf(id string, st *state) string {
	if srv, ok := s.cfg.Fleet.Server(id); ok && srv.HasInventory && srv.Inventory.Info().SystemID != "" {
		return srv.Inventory.Info().SystemID
	}
	return st.scans[id].SystemID
}

// nextRecords is the server's rows after the scan.
func (s *Service) nextRecords(old []firmware.Record, merged []firmware.Component, complete bool, at time.Time) []firmware.Record {
	byKey := map[firmware.Key]firmware.Record{}
	for _, r := range old {
		byKey[r.Key] = r
	}
	seen := map[firmware.Key]bool{}
	out := make([]firmware.Record, 0, len(merged))
	for _, m := range merged {
		seen[m.Key] = true
		r := firmware.Record{Component: m, FirstSeen: at, LastSeen: at}
		if o, ok := byKey[m.Key]; ok {
			r.Component, r.FirstSeen, r.DocReadAt = firmware.Sticky(o, m), o.FirstSeen, o.DocReadAt
			if !complete {
				r.Component = keepUnlisted(o.Component, r.Component)
			}
		}
		if m.Named {
			r.DocReadAt = at
		}
		if r.LastSeen.Before(r.FirstSeen) { // the clock stepped back (review S-L5)
			r.LastSeen = r.FirstSeen
		}
		out = append(out, r)
	}
	if complete {
		return out
	}
	return append(out, keptUnlisted(old, seen, at, MaxRowsPerServer-len(out))...)
}

// keptUnlisted are the stored components an incomplete scan did not list: those listed
// within UnlistedExpiry, the most recently seen first, at most room of them.
func keptUnlisted(old []firmware.Record, seen map[firmware.Key]bool, at time.Time, room int) []firmware.Record {
	var kept []firmware.Record
	for _, o := range old {
		if !seen[o.Key] && at.Sub(o.LastSeen) <= UnlistedExpiry {
			kept = append(kept, o)
		}
	}
	// Platform firmware first (review N1), so a flood of junk IDs cannot evict the BMC,
	// BIOS or CPLD row and lose its "before" version; then the most recently seen.
	slices.SortStableFunc(kept, func(a, b firmware.Record) int {
		return cmp.Or(platformRank(a.Kind)-platformRank(b.Kind), b.LastSeen.Compare(a.LastSeen))
	})
	return kept[:min(len(kept), max(room, 0))]
}

// platformRank puts the platform's own firmware (BMC, BIOS, CPLD) before the rest.
func platformRank(k bmc.FirmwareKind) int {
	switch k {
	case bmc.FirmwareBMC, bmc.FirmwareBIOS, bmc.FirmwareCPLD:
		return 0
	default:
		return 1
	}
}

// prioritise orders the changes for the per-scan cap (review N2): platform firmware
// (BMC, BIOS, CPLD) first, running versions before staged and previous ones, otherwise
// in Diff's order.
func prioritise(changes []firmware.Change, recs ...[]firmware.Record) []firmware.Change {
	kinds := map[firmware.Key]bmc.FirmwareKind{}
	for _, rs := range recs {
		for _, r := range rs {
			kinds[r.Key] = r.Kind
		}
	}
	out := slices.Clone(changes)
	slices.SortStableFunc(out, func(a, b firmware.Change) int {
		return cmp.Or(platformRank(kinds[a.Key])-platformRank(kinds[b.Key]),
			boolRank(a.Field != firmware.FieldRunning)-boolRank(b.Field != firmware.FieldRunning))
	})
	return out
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// namesOf maps every key of old and next to its display name (a removed component's name
// comes from its old row).
func (s *Service) namesOf(old, next []firmware.Record) map[firmware.Key]string {
	names := map[firmware.Key]string{}
	for _, r := range append(slices.Clone(old), next...) {
		names[r.Key] = textclean.Clean(s.cfg.Policy.DisplayName(r.Component), maxNameLen)
	}
	return names
}

func (s *Service) persist(ctx context.Context, row store.FirmwareScanRow, recs []firmware.Record, changes []firmware.Change,
	names map[firmware.Key]string) error {
	comps := make([]store.FirmwareComponentRow, 0, len(recs))
	for _, r := range recs {
		comps = append(comps, rowOf(row.ServerID, r))
	}
	kept := changes[:min(len(changes), MaxChangesPerScan)]
	chRows := make([]store.FirmwareChangeRow, 0, len(kept))
	for _, c := range kept {
		chRows = append(chRows, store.FirmwareChangeRow{ServerID: row.ServerID, ComponentID: c.ComponentID, FQDD: c.FQDD,
			Name: names[c.Key], Field: c.Field, Before: c.Before, After: c.After, SeenAt: row.ScannedAt})
	}
	return s.cfg.DB.WithTx(ctx, func(tx *store.Tx) error {
		if err := tx.Firmware().ReplaceServer(ctx, row, comps, chRows); err != nil {
			return err
		}
		for _, c := range chRows {
			if _, err := s.cfg.Audit.RecordTx(ctx, tx, changedEntry(c)); err != nil {
				return err
			}
		}
		if len(changes) > len(kept) {
			if _, err := s.cfg.Audit.RecordTx(ctx, tx, summaryEntry(row.ServerID, changes, len(kept))); err != nil {
				return err
			}
		}
		return nil
	})
}

// summaryEntry is the audit row of a scan with more changes than it records one by one.
func summaryEntry(server string, changes []firmware.Change, recorded int) audit.Entry {
	return audit.Entry{Principal: "system", AuthMethod: "system", ServerID: server, Action: ActionChanged,
		Params: map[string]any{"summary": true, "changes": len(changes), "components": len(componentsOf(changes, true)),
			"recorded": recorded}, Result: audit.ResultOK}
}

// componentsOf lists the keys with a change, in order; notable leaves out components
// whose only change is the rollback copy (it follows a running change).
func componentsOf(changes []firmware.Change, all bool) []firmware.Key {
	var out []firmware.Key
	seen := map[firmware.Key]bool{}
	for _, c := range changes {
		if seen[c.Key] || (!all && c.Field == firmware.FieldPrevious) {
			continue
		}
		seen[c.Key] = true
		out = append(out, c.Key)
	}
	return out
}

// notifyChanges sends one notification for the scan's changes (review S-M2).
func (s *Service) notifyChanges(id string, changes []firmware.Change, names map[firmware.Key]string, at time.Time) {
	keys := componentsOf(changes, false)
	if s.cfg.Emit == nil || len(keys) == 0 {
		return
	}
	name := id
	if srv, ok := s.cfg.Fleet.Server(id); ok && srv.Name != "" {
		name = srv.Name
	}
	c := notify.FirmwareChange{ServerID: id, ServerName: name, Components: len(keys)}
	for _, ch := range changes {
		if ch.Field != firmware.FieldPrevious {
			c.Lines = append(c.Lines, notify.FirmwareChangeLine{Component: names[ch.Key], Field: ch.Field, Before: ch.Before,
				After: ch.After})
		}
	}
	s.cfg.Emit(notify.FirmwareEvent(c, at))
}

func changedEntry(c store.FirmwareChangeRow) audit.Entry {
	p := map[string]any{"component": c.Name, "component_id": c.ComponentID, "field": c.Field,
		"before": c.Before, "after": c.After}
	if c.FQDD != "" {
		p["fqdd"] = c.FQDD
	}
	return audit.Entry{Principal: "system", AuthMethod: "system", ServerID: c.ServerID, Action: ActionChanged,
		Params: p, Result: audit.ResultOK}
}

// sanitize drops components the store cannot hold (an identifier too long) and cleans
// and caps every BMC string.
func sanitize(cs []firmware.Component) []firmware.Component {
	out := make([]firmware.Component, 0, len(cs))
	seen := map[firmware.Key]bool{}
	for _, c := range cs {
		if len(c.ComponentID) > maxIDLen || len(c.FQDD) > maxIDLen || c.ComponentID != textclean.Clean(c.ComponentID, maxIDLen) {
			continue
		}
		c.FQDD = textclean.Clean(c.FQDD, maxIDLen)
		c.Name = textclean.Clean(c.Name, maxNameLen)
		c.Running = textclean.Clean(c.Running, maxVersionLen)
		c.Previous = textclean.Clean(c.Previous, maxVersionLen)
		c.Staged = textclean.Clean(c.Staged, maxVersionLen)
		c.Stored = textclean.Clean(c.Stored, maxVersionLen)
		c.Identity = textclean.Clean(c.Identity, maxIDLen)
		if _, ok := bmc.ParseFirmwareKind(string(c.Kind)); !ok {
			c.Kind = bmc.FirmwareOther
		}
		if seen[c.Key] { // two keys equal once cleaned (review S-L1): the first wins
			continue
		}
		seen[c.Key] = true
		out = append(out, c)
	}
	return out
}

func components(rs []firmware.Record) []firmware.Component {
	out := make([]firmware.Component, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Component)
	}
	return out
}

func recordOf(r store.FirmwareComponentRow) firmware.Record {
	kind, ok := bmc.ParseFirmwareKind(r.Kind)
	if !ok {
		kind = bmc.FirmwareOther
	}
	return firmware.Record{Component: firmware.Component{Key: firmware.Key{ComponentID: r.ComponentID, FQDD: r.FQDD},
		Kind: kind, Name: r.Name, Named: r.Named, Running: r.Running, Previous: r.Previous, Staged: r.Staged,
		Stored: r.Stored, ReleaseDate: r.ReleaseDate, Updateable: r.Updateable, Identity: r.Identity},
		FirstSeen: r.FirstSeen, LastSeen: r.LastSeen, DocReadAt: r.DocReadAt}
}

func rowOf(server string, r firmware.Record) store.FirmwareComponentRow {
	return store.FirmwareComponentRow{ServerID: server, ComponentID: r.ComponentID, FQDD: r.FQDD, Kind: string(r.Kind),
		Name: r.Name, Named: r.Named, Running: r.Running, Previous: r.Previous, Staged: r.Staged, Stored: r.Stored,
		ReleaseDate: r.ReleaseDate, Updateable: r.Updateable, Identity: r.Identity, FirstSeen: r.FirstSeen,
		LastSeen: r.LastSeen, DocReadAt: r.DocReadAt}
}

// keepUnlisted fills the states an incomplete scan did not list (a Previous- member
// beyond the cap) from the stored row: a missing member there is not a removal. A Dell
// component whose Installed- member was not listed shows its Current- version as
// running; that is the image the BMC holds, not an upgrade, so the stored running
// version is kept and a different Current- version is the stored image (review C-M1;
// a component listed only as Current- shows a real change at the next complete scan).
// One whose Current- member was not listed keeps its stored image while it runs the same
// version. Members, not the versions, tell a missing member from two listed at one
// version.
func keepUnlisted(old, next firmware.Component) firmware.Component {
	listed := next.Members
	switch {
	case old.Running != "" && listed.Has(firmware.MemberCurrent) && !listed.Has(firmware.MemberInstalled):
		image := next.Running // running fell back to the Current- version
		next.Running, next.ReleaseDate, next.Stored = old.Running, old.ReleaseDate, ""
		if image != old.Running {
			next.Stored = image
		}
	case old.Stored != "" && listed.Has(firmware.MemberInstalled) && !listed.Has(firmware.MemberCurrent) &&
		next.Running == old.Running:
		next.Stored = old.Stored
	}
	for _, f := range []struct{ o, n *string }{{&old.Running, &next.Running}, {&old.Previous, &next.Previous},
		{&old.Staged, &next.Staged}} {
		if *f.n == "" {
			*f.n = *f.o
		}
	}
	return next
}
