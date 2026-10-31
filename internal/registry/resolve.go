package registry

import (
	"fmt"
	"sort"

	"oob-manager/internal/config"
	"oob-manager/internal/netpolicy"
	"oob-manager/internal/secrets/credstore"
	"oob-manager/internal/store"
)

// Resolve builds the registry: every file server (in file order), then every database
// row (by id). A row whose id the file also defines is shadowed. A row that fails the
// config.yaml validator or the address policy, or lacks a credential its features need,
// gets Problems and does not run; nothing a row contains can stop the app.
func Resolve(file config.Config, rows []store.ServerRow, creds []store.CredentialRow, policy netpolicy.Policy) Effective {
	eff := Effective{Locked: file.Locked(config.SectionServers)}
	inFile := map[string]bool{}
	for _, s := range file.Servers {
		inFile[s.ID] = true
		eff.entries = append(eff.entries, Entry{Server: s, Source: SourceFile, Enabled: true})
	}
	byServer := map[string][]store.CredentialRow{}
	for _, c := range creds {
		byServer[c.ServerID] = append(byServer[c.ServerID], c)
	}
	sorted := append([]store.ServerRow(nil), rows...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })
	for _, r := range sorted {
		e := entryOf(r, byServer[r.ID], policy)
		if inFile[r.ID] {
			e.Shadowed = true
			eff.Warnings = append(eff.Warnings, fmt.Sprintf("server %s: the browser-managed copy is shadowed by config.yaml and ignored", r.ID))
		} else if e.Enabled && len(e.Problems) > 0 {
			eff.Warnings = append(eff.Warnings, fmt.Sprintf("server %s: enabled but not running: %s", r.ID, e.Problems[0]))
		}
		eff.entries = append(eff.entries, e)
	}
	return eff
}

func entryOf(r store.ServerRow, creds []store.CredentialRow, policy netpolicy.Policy) Entry {
	stored := map[credstore.Slot]bool{}
	infos := make([]CredInfo, 0, len(creds))
	for _, c := range credstore.Slots() {
		for _, row := range creds {
			if row.Slot == string(c) {
				stored[c] = true
				infos = append(infos, CredInfo{Slot: c, Version: row.Version, CreatedAt: row.CreatedAt, CreatedBy: row.CreatedBy})
			}
		}
	}
	s := serverOf(r, stored)
	return Entry{Server: s, Source: SourceDB, Enabled: r.Enabled, Problems: problemsOf(s, policy),
		PollInterval: r.PollInterval, Creds: infos, Rev: r.Rev, CreatedAt: r.CreatedAt, CreatedBy: r.CreatedBy,
		UpdatedAt: r.UpdatedAt, UpdatedBy: r.UpdatedBy}
}

// problemsOf is everything that keeps a database server from running.
func problemsOf(s config.Server, policy netpolicy.Policy) []string {
	var out []string
	if _, err := netpolicy.CheckBMCAddr(s.BMC.Address, policy); err != nil {
		out = append(out, "bmc.address: "+reasonOf(err))
	}
	return append(out, config.ValidateServer(s)...)
}

func reasonOf(err error) string {
	if pe, ok := err.(*netpolicy.Error); ok { //nolint:errorlint // CheckBMCAddr returns *Error unwrapped
		return pe.Reason()
	}
	return err.Error()
}
