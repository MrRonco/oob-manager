package fwinventory

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/firmware"
	"oob-manager/internal/fleet"
	"oob-manager/internal/fwcatalog"
	"oob-manager/internal/store"
)

// RecentChanges is how many changes a server's view lists.
const RecentChanges = 20

// ScanStatus is a server's firmware tier as the poller reports it.
type ScanStatus struct {
	Enabled, Running, Requested bool
	Paused                      bool      // polling is paused: the BMC certificate does not match its pin
	AsOf, Next                  time.Time // AsOf: last good scan since start (zero: none yet)
	Error                       string    // class of the last failed scan
	Every                       time.Duration
}

// Busy reports a scan waiting or running ("Scanning…").
func (s ScanStatus) Busy() bool { return s.Requested || s.Running }

// ServerScan is one polled server in the view: identity, its stored last scan and the
// tier's status.
type ServerScan struct {
	Info     firmware.ServerInfo
	Scan     store.FirmwareScanRow
	Scanned  bool // a scan is stored (survives restarts)
	Status   ScanStatus
	Coverage firmware.Coverage // the vendor catalog's line (zero: no catalog in use)
}

// Truncated reports a collection longer than the scan's member cap: only the first
// bmc.MaxFirmwareMembers of Scan.Listed members were read.
func (s ServerScan) Truncated() bool { return s.Scanned && s.Scan.Listed > bmc.MaxFirmwareMembers }

// Table is the fleet view: rows after the filter, worst first, and the counts before it.
type Table struct {
	Rows      []firmware.Row
	Total     int // rows before the filter
	Flagged   int // rows with any flag (below minimum, updates, not applied, cannot compare, stale)
	Warn      int // below minimum or an Urgent vendor update (the sidebar count)
	Updates   int // rows with a newer vendor release, not skipped
	Urgent    int // of which rated Urgent
	Servers   []ServerScan
	Catalog   fwcatalog.Status
	Generated time.Time
}

// ServerView is one server's firmware section.
type ServerView struct {
	ServerScan
	Rows    []firmware.Row // by kind, then name
	Changes []store.FirmwareChangeRow
}

// Table builds the fleet view for f. Only servers the fleet polls are shown (a disabled
// server's rows are kept, not listed).
func (s *Service) Table(ctx context.Context, f firmware.Filter) Table {
	now := s.cfg.Now()
	st := s.state.Load()
	idx := s.index(ctx)
	t := Table{Catalog: s.CatalogStatus(ctx), Generated: now}
	for _, srv := range s.cfg.Fleet.Servers() {
		ss := s.serverScan(st, srv)
		ss.Coverage = coverage(idx, ss.Info, st.recs[srv.ID])
		t.Servers = append(t.Servers, ss)
		for _, r := range firmware.BuildRows(s.cfg.Policy, ss.Info, st.recs[srv.ID], now, idx) {
			t.Total++
			if p := r.Primary(); p.Flagged() {
				t.Flagged++
				if p.Warn() { // flags sort worst first: a warning is always the primary flag
					t.Warn++
				}
			}
			if r.Update.Newer() {
				t.Updates++
				if r.Update.State == firmware.UpdateUrgent {
					t.Urgent++
				}
			}
			if f.Match(r) {
				t.Rows = append(t.Rows, r)
			}
		}
	}
	firmware.SortRows(t.Rows)
	return t
}

// warnCacheFor is how long the sidebar count is reused (review S-L4): every page shows
// it, and a recorded scan or a registry sync clears it at once.
const warnCacheFor = 10 * time.Second

// UpdatesChanged drops the cached sidebar count: the vendor catalog in use or a skip
// changed (fwcatalog.Checker's OnChange).
func (s *Service) UpdatesChanged() { s.warn.Store(nil) }

// WarnCount is the sidebar count: rows below their minimum or with an Urgent update.
func (s *Service) WarnCount(ctx context.Context) int {
	now := s.cfg.Now()
	if c := s.warn.Load(); c != nil && now.Sub(c.at) < warnCacheFor && !now.Before(c.at) {
		return c.n
	}
	n := s.Table(ctx, firmware.Filter{}).Warn
	s.warn.Store(&warnCache{at: now, n: n})
	return n
}

// Server is one polled server's section with its newest changes.
func (s *Service) Server(ctx context.Context, id string) (ServerView, error) {
	srv, ok := s.cfg.Fleet.Server(id)
	if !ok {
		return ServerView{}, ErrNotFound
	}
	st := s.state.Load()
	idx := s.index(ctx)
	v := ServerView{ServerScan: s.serverScan(st, srv)}
	v.Coverage = coverage(idx, v.Info, st.recs[id])
	v.Rows = firmware.BuildRows(s.cfg.Policy, v.Info, st.recs[id], s.cfg.Now(), idx)
	slices.SortStableFunc(v.Rows, func(a, b firmware.Row) int {
		return cmp.Or(cmp.Compare(a.Kind.Rank(), b.Kind.Rank()), cmp.Compare(a.Display, b.Display),
			cmp.Compare(a.ComponentID, b.ComponentID), cmp.Compare(a.FQDD, b.FQDD))
	})
	changes, err := s.cfg.DB.Firmware().Changes(ctx, id, RecentChanges)
	if err != nil {
		return ServerView{}, err
	}
	v.Changes = changes
	return v, nil
}

func (s *Service) serverScan(st *state, srv fleet.ServerState) ServerScan {
	scan, scanned := st.scans[srv.ID]
	info := firmware.ServerInfo{ID: srv.ID, Name: srv.Name, BMCKind: s.cfg.Kind(srv.ID), Model: scan.Model,
		SystemID: scan.SystemID}
	if srv.HasInventory && srv.Inventory.Info().Model != "" {
		info.Model = srv.Inventory.Info().Model
	}
	if srv.HasInventory && srv.Inventory.Info().SystemID != "" {
		info.SystemID = srv.Inventory.Info().SystemID
	}
	return ServerScan{Info: info, Scan: scan, Scanned: scanned, Status: ScanStatus{Enabled: srv.FirmwareEnabled,
		Running: srv.FirmwareRunning, Requested: srv.FirmwareRequested, AsOf: srv.FirmwareAsOf, Next: srv.FirmwareNext,
		Error: string(srv.FirmwareError), Every: srv.FirmwareEvery, Paused: srv.Paused}}
}

// coverage is a server's catalog line; zero without an index.
func coverage(idx firmware.UpdateIndex, info firmware.ServerInfo, recs []firmware.Record) firmware.Coverage {
	if idx == nil {
		return firmware.Coverage{}
	}
	comps := make([]firmware.Component, 0, len(recs))
	for _, r := range recs {
		comps = append(comps, r.Component)
	}
	return idx.Coverage(info, comps)
}

// Counts are a server's metric values.
type Counts struct {
	Components int
	Flagged    map[firmware.Flag]int // below_minimum, update_*, not_applied, cannot_compare, stale_release
	Updates    map[string]int        // newer vendor releases by criticality ("urgent", "recommended", "optional")
	LastScan   time.Time
	Changes    int64 // since the process started
}

// Counts reports a server's metric values (false: not polled).
func (s *Service) Counts(ctx context.Context, id string) (Counts, bool) {
	srv, ok := s.cfg.Fleet.Server(id)
	if !ok {
		return Counts{}, false
	}
	st := s.state.Load()
	ss := s.serverScan(st, srv)
	c := Counts{Flagged: map[firmware.Flag]int{}, Updates: map[string]int{}, LastScan: ss.Scan.ScannedAt, Changes: st.changes[id]}
	for _, r := range firmware.BuildRows(s.cfg.Policy, ss.Info, st.recs[id], s.cfg.Now(), s.index(ctx)) {
		c.Components++
		for _, f := range r.Flags {
			c.Flagged[f]++
		}
		if r.Update.Newer() {
			c.Updates[r.Update.Latest.Criticality.String()]++
		}
	}
	return c, true
}

// RescanCooldown is the wait between two re-scans of one server (review S-M4), on top of
// the per-user rate limit of the UI.
const RescanCooldown = 30 * time.Second

// CooldownError refuses a re-scan of a server that was re-scanned moments ago.
type CooldownError struct{ Left time.Duration }

func (e *CooldownError) Error() string { return "fwinventory: re-scanned moments ago" }

// Rescan asks the poller to scan server id's firmware now (an operator action: a BMC
// read, no write). Fail-closed like the security re-run (review S-L2): a started row is
// written first (no row, no request), then ok or error with the refusal's class; a
// re-scan within RescanCooldown of the last one is refused (denied, cooldown).
func (s *Service) Rescan(ctx context.Context, a admin.Actor, id string) error {
	srv, ok := s.cfg.Fleet.Server(id)
	switch {
	case !ok:
		return ErrNotFound
	case !srv.FirmwareEnabled || s.cfg.Refresh == nil:
		return ErrUnavailable
	}
	e := audit.Entry{Principal: a.Username, AuthMethod: a.Method, Role: string(a.Role), SrcIP: a.IP, ServerID: id,
		Action: ActionRescan}
	if left, ok := s.reserve(id); !ok {
		e.Result, e.ErrorClass = audit.ResultDenied, "cooldown"
		return errors.Join(&CooldownError{Left: left}, s.record(ctx, e))
	}
	e.Result = audit.ResultStarted
	if err := s.record(ctx, e); err != nil {
		s.release(id)
		return err
	}
	err := s.cfg.Refresh(id, fleet.TierFirmware)
	e.Result = audit.ResultOK
	if err != nil {
		s.release(id)
		e.Result, e.ErrorClass = audit.ResultError, rescanClass(err)
	}
	return errors.Join(err, s.record(ctx, e))
}

func (s *Service) record(ctx context.Context, e audit.Entry) error {
	if _, err := s.cfg.Audit.Record(ctx, e); err != nil {
		s.cfg.Logger.Error("fwinventory: audit of a re-scan failed", "server", e.ServerID, "err", err)
		return err
	}
	return nil
}

func (s *Service) reserve(id string) (time.Duration, bool) {
	s.rescanMu.Lock()
	defer s.rescanMu.Unlock()
	now := s.cfg.Now()
	if at, ok := s.rescanAt[id]; ok && now.Before(at.Add(RescanCooldown)) && !now.Before(at) {
		return at.Add(RescanCooldown).Sub(now), false
	}
	s.rescanAt[id] = now
	return 0, true
}

func (s *Service) release(id string) {
	s.rescanMu.Lock()
	defer s.rescanMu.Unlock()
	delete(s.rescanAt, id)
}

func rescanClass(err error) string {
	switch {
	case errors.Is(err, fleet.ErrPaused):
		return "paused"
	case errors.Is(err, fleet.ErrNoTier):
		return "unavailable"
	default:
		return "refused"
	}
}
