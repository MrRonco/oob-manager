package fwcatalog

import (
	"context"
	"strings"
	"time"

	"oob-manager/internal/firmware"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/store"
)

// legacyAge: a system whose newest catalog entry is older than this, with nothing
// matched, reads "only legacy entries" (likely end of support; plan 08 §8.3).
const legacyAge = 5 * 365 * 24 * time.Hour

// Matched-by values (firmware.Update.MatchedBy).
const (
	ByOverride  = "override"
	BySystemID  = "system_id"
	ByModelName = "model_name"
)

// vendorKinds are the BMC kinds the Dell catalog covers.
var vendorKinds = map[string]bool{"idrac8": true, "idrac9": true}

type compKey struct{ system, component string }

type skipKey struct{ server, component, fqdd string }

// Index judges components against one catalog import, built from the store (no
// network). It is immutable and safe for concurrent use.
type Index struct {
	releases  map[compKey][]store.CatalogReleaseRow
	systems   map[string]time.Time // system ID → newest release listed
	models    map[string]string    // normalised model → system ID ("" when ambiguous)
	overrides map[string]string    // server ID → system ID (firmware.catalog.systems)
	skips     map[skipKey]firmware.Skip
	now       time.Time
}

var _ firmware.UpdateIndex = (*Index)(nil)

// BuildIndex loads the active import of source. It returns nil (and no error) when no
// catalog was imported.
func BuildIndex(ctx context.Context, cat store.CatalogRepository, upd store.FirmwareUpdateRepository, source string,
	overrides map[string]string, now time.Time) (*Index, store.CatalogImportRow, error) {
	imp, ok, err := cat.Import(ctx, source, store.CatalogActive)
	if err != nil || !ok {
		return nil, store.CatalogImportRow{}, err
	}
	rels, err := cat.Releases(ctx, imp.ID)
	if err != nil {
		return nil, imp, err
	}
	models, err := cat.Models(ctx, imp.ID)
	if err != nil {
		return nil, imp, err
	}
	skips, err := upd.Skips(ctx)
	if err != nil {
		return nil, imp, err
	}
	x := &Index{releases: map[compKey][]store.CatalogReleaseRow{}, systems: map[string]time.Time{},
		models: map[string]string{}, overrides: map[string]string{}, skips: map[skipKey]firmware.Skip{}, now: now}
	for _, r := range rels {
		k := compKey{r.SystemID, r.ComponentID}
		x.releases[k] = append(x.releases[k], r)
		if r.ReleasedAt.After(x.systems[r.SystemID]) || x.systems[r.SystemID].IsZero() {
			x.systems[r.SystemID] = r.ReleasedAt
		}
	}
	for _, m := range models {
		n := catalog.NormalizeModel(m.Model)
		if prev, seen := x.models[n]; seen && prev != m.SystemID {
			x.models[n] = "" // ambiguous: no match
			continue
		}
		x.models[n] = m.SystemID
	}
	for id, sys := range overrides {
		x.overrides[id] = sys
	}
	for _, s := range skips {
		x.skips[skipKey{s.ServerID, s.ComponentID, s.FQDD}] = firmware.Skip{Version: s.Version, Comment: s.Comment,
			By: s.SkippedBy, At: s.SkippedAt}
	}
	return x, imp, nil
}

// system identifies a server's vendor system: the override, else the BMC's system ID,
// else a model name that names exactly one system in the catalog.
func (x *Index) system(s firmware.ServerInfo) (id, by string) {
	switch {
	case x.overrides[s.ID] != "":
		return x.overrides[s.ID], ByOverride
	case s.SystemID != "":
		return s.SystemID, BySystemID
	case s.Model != "" && x.models[catalog.NormalizeModel(s.Model)] != "":
		return x.models[catalog.NormalizeModel(s.Model)], ByModelName
	default:
		return "", ""
	}
}

// Update judges one component (plan 08 §8.2).
func (x *Index) Update(s firmware.ServerInfo, c firmware.Component) firmware.Update {
	if !vendorKinds[s.BMCKind] {
		return firmware.Update{}
	}
	sys, by := x.system(s)
	if sys == "" {
		return firmware.Update{}
	}
	cands := narrow(x.releases[compKey{sys, c.ComponentID}], catalog.KeyFromIdentity(c.Identity, c.ComponentID, sys))
	u := firmware.Update{Candidates: len(cands), MatchedBy: by}
	if len(cands) == 0 {
		u.State = firmware.UpdateNotInCatalog
		return u
	}
	latest, ok := newest(cands, c.Running)
	u.Latest = release(latest)
	if !ok {
		u.State = firmware.UpdateCannotCompare
		return u
	}
	u.StoredIsLatest = c.Stored != "" && c.Stored == latest.Version
	skip, skipped := x.skips[skipKey{s.ID, c.ComponentID, c.FQDD}]
	if skipped {
		u.Skip = &skip
	}
	switch cmp, _ := firmware.CompareVersions(c.Running, latest.Version); {
	case cmp >= 0:
		u.State = firmware.UpdateCurrent
	case skipped && skip.Version == latest.Version:
		u.State = firmware.UpdateSkipped
	case catalog.Criticality(latest.Criticality) == catalog.CriticalityUrgent:
		u.State = firmware.UpdateUrgent
	default:
		u.State = firmware.UpdateAvailable
	}
	return u
}

// narrow keeps the packages for the component's PCI identity when it has one and some
// packages carry one; when none matches, the packages without a PCI identity.
func narrow(cands []store.CatalogReleaseRow, k catalog.Key) []store.CatalogReleaseRow {
	if k.VendorID == "" {
		return cands
	}
	// The most specific matching packages win (more PCI IDs given and equal), so a
	// vendor-only package never beats one naming this exact device.
	best, bestScore := []store.CatalogReleaseRow(nil), 0
	var generic []store.CatalogReleaseRow
	for _, r := range cands {
		if r.VendorID == "" && r.DeviceID == "" && r.SubVendorID == "" && r.SubDeviceID == "" {
			generic = append(generic, r)
			continue
		}
		score, ok := pciScore(r, k)
		switch {
		case !ok || score < bestScore:
		case score > bestScore:
			best, bestScore = []store.CatalogReleaseRow{r}, score
		default:
			best = append(best, r)
		}
	}
	if len(best) > 0 {
		return best
	}
	return generic
}

// newest is the highest candidate version that orders against running; false (with the
// most recently released candidate, for display) when none does.
func newest(cands []store.CatalogReleaseRow, running string) (store.CatalogReleaseRow, bool) {
	var best store.CatalogReleaseRow
	found := false
	for _, r := range cands {
		if _, ok := firmware.CompareVersions(running, r.Version); !ok {
			continue
		}
		if c, ok := firmware.CompareVersions(r.Version, best.Version); !found || (ok && c > 0) {
			best, found = r, true
		}
	}
	if found {
		return best, true
	}
	latest := cands[0]
	for _, r := range cands[1:] {
		if r.ReleasedAt.After(latest.ReleasedAt) {
			latest = r
		}
	}
	return latest, false
}

// pciScore counts the PCI IDs both sides give and that are equal; false when any given
// pair differs (a side that does not give an ID matches anything).
func pciScore(r store.CatalogReleaseRow, k catalog.Key) (int, bool) {
	n := 0
	for _, p := range [][2]string{{r.VendorID, k.VendorID}, {r.DeviceID, k.DeviceID}, {r.SubVendorID, k.SubVendorID},
		{r.SubDeviceID, k.SubDeviceID}} {
		switch {
		case p[0] == "" || p[1] == "":
		case strings.EqualFold(p[0], p[1]):
			n++
		default:
			return 0, false
		}
	}
	return n, true
}

func release(r store.CatalogReleaseRow) catalog.Release {
	return catalog.Release{Version: r.Version, Date: r.ReleasedAt, Criticality: catalog.Criticality(r.Criticality),
		Name: r.Name, PackagePath: r.PackagePath, DetailsURL: r.DetailsURL, RebootRequired: r.RebootRequired}
}

// Coverage is a server's catalog line (plan 08 §8.3).
func (x *Index) Coverage(s firmware.ServerInfo, comps []firmware.Component) firmware.Coverage {
	if !vendorKinds[s.BMCKind] {
		return firmware.Coverage{State: firmware.CoverageNoBMCType}
	}
	sys, by := x.system(s)
	if sys == "" {
		return firmware.Coverage{State: firmware.CoverageUnknown}
	}
	cov := firmware.Coverage{SystemID: sys, MatchedBy: by, Newest: x.systems[sys], Components: len(comps)}
	if _, listed := x.systems[sys]; !listed {
		cov.State = firmware.CoverageNotListed
		return cov
	}
	for _, c := range comps {
		u := x.Update(s, c)
		if u.Candidates > 0 {
			cov.Matched++
		}
		if u.Newer() {
			cov.Updates++
			if u.State == firmware.UpdateUrgent {
				cov.Urgent++
			}
		}
	}
	cov.State = firmware.CoverageNormal
	if cov.Matched == 0 && !cov.Newest.IsZero() && x.now.Sub(cov.Newest) > legacyAge {
		cov.State = firmware.CoverageLegacy
	}
	return cov
}
