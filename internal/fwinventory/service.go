// Package fwinventory is the read-only firmware view's service (docs/tech_doc.md §38).
// It records the fleet's firmware scans (fleet.FirmwareSink): it merges the member
// states, keeps the names learnt from member documents, detects version changes and
// writes them, with one audit row each, in the scan's transaction; and it serves the
// view (the fleet table, a server's section, the API, CSV and metrics) from an
// immutable in-memory copy loaded from the database at start, so a restarted app shows
// the last scan at once. It never writes to a BMC; Rescan only asks the poller to read.
package fwinventory

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/bmc"
	"oob-manager/internal/firmware"
	"oob-manager/internal/fleet"
	"oob-manager/internal/fwcatalog"
	"oob-manager/internal/notify"
	"oob-manager/internal/store"
)

// Audit actions written by the service.
const (
	ActionChanged = "server.firmware.changed"
	ActionRescan  = "server.firmware.rescan"
)

// ChangeRetention is how long version changes are kept.
const ChangeRetention = 2 * 365 * 24 * time.Hour

// Errors.
var (
	ErrNotFound    = errors.New("fwinventory: unknown server")
	ErrUnavailable = errors.New("fwinventory: this server has no firmware scan")
)

// Config wires the service. DB, Audit and Fleet are required.
type Config struct {
	DB    *store.DB
	Audit admin.Recorder
	Fleet fleet.Reader
	// Kind is a server's configured BMC kind (rules match on it; the BMC minimum is
	// security.min_firmware for it). Read live: the registry can change.
	Kind func(id string) string
	// Refresh asks the poller to run a tier now (fleet.Fleet.Refresh).
	Refresh func(id string, tier fleet.Tier) error
	Policy  firmware.Policy
	// Updates is the vendor update check (internal/fwcatalog); nil: none.
	Updates Updates
	// Emit sends the one notification of a scan with changes (notify.Service.Emit; nil:
	// none sent).
	Emit   func(notify.Event)
	Now    func() time.Time
	Logger *slog.Logger
}

// Service is safe for concurrent use. Writers (Record, SyncServers) are serialised;
// readers load the published state without locks.
type Service struct {
	cfg   Config
	mu    sync.Mutex
	state atomic.Pointer[state]
	// warn caches the sidebar count (WarnCount); a recorded scan or a sync clears it.
	warn atomic.Pointer[warnCache]
	// rescanMu guards rescanAt, the last re-scan per server (the cooldown).
	rescanMu sync.Mutex
	rescanAt map[string]time.Time
}

type warnCache struct {
	at time.Time
	n  int
}

// state is one immutable generation of the stored view.
type state struct {
	recs  map[string][]firmware.Record
	scans map[string]store.FirmwareScanRow
	// changes counts version changes per server since the process started (metrics).
	changes map[string]int64
}

func (st *state) clone() *state {
	return &state{recs: maps.Clone(st.recs), scans: maps.Clone(st.scans), changes: maps.Clone(st.changes)}
}

var _ fleet.FirmwareSink = (*Service)(nil)

// New loads the stored view.
func New(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Fleet == nil {
		return nil, errors.New("fwinventory: DB, Audit and Fleet are required")
	}
	if cfg.Kind == nil {
		cfg.Kind = func(string) string { return "" }
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Service{cfg: cfg, rescanAt: map[string]time.Time{}}
	st, err := s.load(ctx)
	if err != nil {
		return nil, err
	}
	s.state.Store(st)
	return s, nil
}

func (s *Service) load(ctx context.Context) (*state, error) {
	repo := s.cfg.DB.Firmware()
	rows, err := repo.Components(ctx)
	if err != nil {
		return nil, err
	}
	scans, err := repo.Scans(ctx)
	if err != nil {
		return nil, err
	}
	st := &state{recs: map[string][]firmware.Record{}, scans: map[string]store.FirmwareScanRow{}, changes: map[string]int64{}}
	for _, r := range rows {
		st.recs[r.ServerID] = append(st.recs[r.ServerID], recordOf(r))
	}
	for _, sc := range scans {
		st.scans[sc.ServerID] = sc
	}
	return st, nil
}

// Policy is the evaluation policy (config.yaml).
func (s *Service) Policy() firmware.Policy { return s.cfg.Policy }

// Updates is the vendor update check's read side.
type Updates interface {
	// Index is the catalog in use (nil: none imported).
	Index(ctx context.Context) firmware.UpdateIndex
	// Status is the catalog line; Checks the newest checks (at most limit).
	Status(ctx context.Context) fwcatalog.Status
	Checks(ctx context.Context, limit int) []store.CatalogCheckRow
}

// index is the update index, nil when the check is not wired or no catalog is in use.
func (s *Service) index(ctx context.Context) firmware.UpdateIndex {
	if s.cfg.Updates == nil {
		return nil
	}
	return s.cfg.Updates.Index(ctx)
}

// CatalogStatus is the update check's status line (zero without the check).
func (s *Service) CatalogStatus(ctx context.Context) fwcatalog.Status {
	if s.cfg.Updates == nil {
		return fwcatalog.Status{}
	}
	return s.cfg.Updates.Status(ctx)
}

// CatalogChecks lists the update check's newest checks (none without the check).
func (s *Service) CatalogChecks(ctx context.Context, limit int) []store.CatalogCheckRow {
	if s.cfg.Updates == nil {
		return nil
	}
	return s.cfg.Updates.Checks(ctx, limit)
}

// Need implements fleet.FirmwareSink: a member document is read for components that are
// new, unnamed, named longer than firmware.DocRefresh ago, or whose running version
// changed.
func (s *Service) Need(id string, now time.Time) func(bmc.FirmwareItem) bool {
	idx := map[firmware.Key]firmware.Record{}
	for _, r := range s.state.Load().recs[id] {
		idx[r.Key] = r
	}
	return func(it bmc.FirmwareItem) bool {
		k := keyOf(it)
		r, ok := idx[k]
		return firmware.NeedsDocument(r, ok, it, now)
	}
}

func keyOf(it bmc.FirmwareItem) firmware.Key {
	id := it.ComponentID
	if id == "" {
		id = it.ID
	}
	return firmware.Key{ComponentID: id, FQDD: it.FQDD}
}

// SyncServers forgets every server not in ids (the registry's servers, enabled or not):
// their rows are deleted, so a later server with the same ID starts clean.
func (s *Service) SyncServers(ctx context.Context, ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur := s.state.Load()
	var gone []string
	for id := range cur.recs {
		if !slices.Contains(ids, id) {
			gone = append(gone, id)
		}
	}
	for id := range cur.scans {
		if !slices.Contains(ids, id) && !slices.Contains(gone, id) {
			gone = append(gone, id)
		}
	}
	if len(gone) == 0 {
		return nil
	}
	next := cur.clone()
	var errs []error
	for _, id := range gone {
		if err := s.cfg.DB.Firmware().DeleteServer(ctx, id); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := s.cfg.DB.FirmwareUpdates().DeleteServer(ctx, id); err != nil { // skips and notified updates
			errs = append(errs, err)
			continue
		}
		delete(next.recs, id)
		delete(next.scans, id)
		delete(next.changes, id)
	}
	s.state.Store(next)
	s.warn.Store(nil)
	return errors.Join(errs...)
}

// Prune deletes version changes older than ChangeRetention (the janitor).
func (s *Service) Prune(ctx context.Context) (int64, error) {
	return s.cfg.DB.Firmware().PruneChanges(ctx, s.cfg.Now().Add(-ChangeRetention))
}
