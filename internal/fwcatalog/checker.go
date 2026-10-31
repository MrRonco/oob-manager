package fwcatalog

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/bmc/textclean"
	"oob-manager/internal/firmware"
	"oob-manager/internal/firmware/catalog"
	"oob-manager/internal/store"
)

// indexTTL bounds how stale the cached index can be when another process (the CLI)
// imported a catalog; changes made here invalidate it at once.
const indexTTL = 30 * time.Second

// Audit actions of the update decisions (plan 08 §12).
const (
	ActionSkipUpdate   = "server.firmware.skip_update"
	ActionUnskipUpdate = "server.firmware.unskip_update"
)

// MaxSkipComment caps a skip's comment.
const MaxSkipComment = 500

// ErrBadSkip refuses a skip whose comment or version is not acceptable.
var ErrBadSkip = errors.New("fwcatalog: a skip needs a version and a 1-500 character comment")

// CheckerConfig wires the checker. Repo, Updates and Audit are required.
type CheckerConfig struct {
	Importer Importer
	Repo     store.CatalogRepository
	Updates  store.FirmwareUpdateRepository
	Audit    admin.Recorder
	// Overrides is firmware.catalog.systems (server ID → system ID).
	Overrides map[string]string
	// DB commits a skip and its audit row together (nil: one after the other).
	DB *store.DB
	// OnChange is called after a change of what the view shows (an import, a skip, a
	// re-parse): the firmware view drops its cached sidebar count.
	OnChange func()
	// Host is the configured download host, named in the help text.
	Host string
	// Online is the scheduled check (zero: none; plan 08 §6); File the file-only keys.
	Online Online
	File   FileSettings
	Now    func() time.Time
	Logger *slog.Logger
}

// Checker serves the update check's read side (the index and the status line) and the
// skip decisions. U3 adds the online schedule.
type Checker struct {
	cfg        CheckerConfig
	mu         sync.Mutex // guards index rebuilds, lastWant and st
	cache      atomic.Pointer[cachedIndex]
	reparsing  atomic.Bool
	dirty      atomic.Bool
	gen        atomic.Uint64 // bumped by Invalidate: a build started before it is not cached
	lastWant   string        // the fleet's systems at the last re-parse ("" none yet)
	failedWant string
	failedAt   time.Time
	st         onlineState
	kick       chan struct{}
	onl        atomic.Pointer[Online] // SetOnline (nil: cfg.Online)
}

type cachedIndex struct {
	at  time.Time
	idx *Index
	imp store.CatalogImportRow
}

// NewChecker builds a checker.
func NewChecker(cfg CheckerConfig) (*Checker, error) {
	if cfg.Repo == nil || cfg.Updates == nil || cfg.Audit == nil {
		return nil, errors.New("fwcatalog: Repo, Updates and Audit are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Checker{cfg: cfg, st: onlineState{byClass: map[string]int64{}}, kick: make(chan struct{}, 1)}, nil
}

func (c *Checker) source() string {
	if c.cfg.Importer.Source != nil {
		return c.cfg.Importer.Source.Name()
	}
	return "dell"
}

// Invalidate drops the cached index (after an import, a skip or a fleet change).
func (c *Checker) Invalidate() {
	c.gen.Add(1)
	c.cache.Store(nil)
}

// Index is the index of the catalog in use; nil when none is imported (or it cannot be
// read, which is logged).
func (c *Checker) Index(ctx context.Context) firmware.UpdateIndex {
	if idx := c.index(ctx); idx != nil {
		return idx
	}
	return nil
}

func (c *Checker) index(ctx context.Context) *Index {
	now := c.cfg.Now()
	if ci := c.cache.Load(); ci != nil && now.Sub(ci.at) < indexTTL && !now.Before(ci.at) {
		return ci.idx
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ci := c.cache.Load(); ci != nil && now.Sub(ci.at) < indexTTL && !now.Before(ci.at) {
		return ci.idx
	}
	gen := c.gen.Load()
	idx, imp, err := BuildIndex(ctx, c.cfg.Repo, c.cfg.Updates, c.source(), c.cfg.Overrides, now)
	if err != nil {
		c.cfg.Logger.Warn("fwcatalog: the catalog index could not be read", "err", err)
		return nil
	}
	if c.gen.Load() == gen { // nothing changed during the build
		c.cache.Store(&cachedIndex{at: now, idx: idx, imp: imp})
	}
	return idx
}

// Status is the catalog line of the firmware page and the API's meta.catalog.
type Status struct {
	Source    string
	Host      string
	Enabled   bool                    // the online check is on
	Online    bool                    // an online source is configured
	Active    *store.CatalogImportRow // the catalog in use (nil: none)
	Held      *store.CatalogImportRow // a smaller catalog waiting for an admin (plan §15)
	LastCheck *store.CatalogCheckRow
}

// Signed reports a signed catalog in use.
func (s Status) Signed() bool { return s.Active != nil && s.Active.Signer != "" }

// Status reads the catalog line (zero Active when nothing is imported).
func (c *Checker) Status(ctx context.Context) Status {
	st := Status{Source: c.source(), Host: c.cfg.Host, Enabled: c.schedule().Enabled, Online: c.online().Fetcher != nil}
	if imp, ok, err := c.cfg.Repo.Import(ctx, st.Source, store.CatalogActive); err == nil && ok {
		st.Active = &imp
	}
	if imp, ok, err := c.cfg.Repo.Import(ctx, st.Source, store.CatalogHeld); err == nil && ok {
		st.Held = &imp
	}
	if checks, err := c.cfg.Repo.Checks(ctx, st.Source, 1); err == nil && len(checks) == 1 {
		st.LastCheck = &checks[0]
	}
	return st
}

// Checks lists the newest checks (at most limit, 1–500; an unreadable list is empty).
func (c *Checker) Checks(ctx context.Context, limit int) []store.CatalogCheckRow {
	rows, err := c.cfg.Repo.Checks(ctx, c.source(), limit)
	if err != nil {
		c.cfg.Logger.Warn("fwcatalog: the check list could not be read", "err", err)
		return nil
	}
	return rows
}

// SkipRequest is one "skip this version".
type SkipRequest struct {
	ServerID, ComponentID, FQDD, Version, Comment string
}

// ErrBadVersion refuses a skip of a version longer than the catalog allows.
var ErrBadVersion = errors.New("fwcatalog: the version cannot be skipped")

// cleanComment accepts one line of text, 1–500 bytes after cleaning (the security
// checks' rule for accepted risks).
func cleanComment(s string) (string, error) {
	if !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl) {
		return "", ErrBadSkip
	}
	s = textclean.Clean(s, 0)
	if s == "" || len(s) > MaxSkipComment {
		return "", ErrBadSkip
	}
	return s, nil
}

// Skip records an admin's decision to skip one component's latest version; a newer
// version reopens it. The write and its audit row commit together. The caller checks
// that the version is the row's latest (the form carries it) and that the actor stepped
// up.
func (c *Checker) Skip(ctx context.Context, a admin.Actor, r SkipRequest) error {
	if r.Version == "" || len(r.Version) > 64 {
		return ErrBadVersion
	}
	comment, err := cleanComment(r.Comment)
	if err != nil {
		return err
	}
	e := c.entry(a, r.ServerID, ActionSkipUpdate, map[string]any{"component_id": r.ComponentID, "fqdd": r.FQDD,
		"version": r.Version, "comment": comment})
	return c.inTx(ctx, e, func(u store.FirmwareUpdateRepository) error {
		return u.PutSkip(ctx, store.FirmwareUpdateSkipRow{ServerID: r.ServerID, ComponentID: r.ComponentID, FQDD: r.FQDD,
			Version: r.Version, Comment: comment, SkippedBy: a.Username, SkippedAt: c.cfg.Now()})
	})
}

// Unskip removes a component's skip.
func (c *Checker) Unskip(ctx context.Context, a admin.Actor, serverID, componentID, fqdd string) error {
	e := c.entry(a, serverID, ActionUnskipUpdate, map[string]any{"component_id": componentID, "fqdd": fqdd})
	return c.inTx(ctx, e, func(u store.FirmwareUpdateRepository) error {
		ok, err := u.DeleteSkip(ctx, serverID, componentID, fqdd)
		if err == nil && !ok {
			err = fmt.Errorf("fwcatalog: %w", store.ErrNotFound)
		}
		return err
	})
}

func (c *Checker) entry(a admin.Actor, serverID, action string, params map[string]any) audit.Entry {
	return audit.Entry{Principal: a.Username, AuthMethod: a.Method, Role: string(a.Role), SrcIP: a.IP,
		ServerID: serverID, Action: action, Params: params}
}

// inTx applies a change and its audit row in one transaction (CheckerConfig.DB), or,
// without a database handle (tests), one after the other. A failure is audited apart.
func (c *Checker) inTx(ctx context.Context, e audit.Entry, fn func(store.FirmwareUpdateRepository) error) error {
	var err error
	if c.cfg.DB != nil {
		err = c.cfg.DB.WithTx(ctx, func(tx *store.Tx) error {
			if ferr := fn(tx.FirmwareUpdates()); ferr != nil {
				return ferr
			}
			e.Result = audit.ResultOK
			_, aerr := c.cfg.Audit.RecordTx(ctx, tx, e)
			return aerr
		})
	} else if err = fn(c.cfg.Updates); err == nil {
		err = c.finish(ctx, e, nil)
	}
	if err == nil {
		c.changed()
		return nil
	}
	e.Result, e.ErrorClass = audit.ResultError, "store"
	if _, aerr := c.cfg.Audit.Record(ctx, e); aerr != nil {
		c.cfg.Logger.Error("fwcatalog: audit failed", "action", e.Action, "err", aerr)
	}
	return err
}

func (c *Checker) finish(ctx context.Context, e audit.Entry, err error) error {
	e.Result = audit.ResultOK
	if err != nil {
		e.Result, e.ErrorClass = audit.ResultError, "store"
	} else {
		c.changed()
	}
	if _, aerr := c.cfg.Audit.Record(ctx, e); aerr != nil {
		c.cfg.Logger.Error("fwcatalog: audit failed", "action", e.Action, "err", aerr)
		return errors.Join(err, aerr)
	}
	return err
}

// changed drops the cached index and tells the view (its sidebar count).
func (c *Checker) changed() {
	c.Invalidate()
	if c.cfg.OnChange != nil {
		c.cfg.OnChange()
	}
}

// FleetChanged re-parses the cached catalog when the fleet's systems changed since the
// last parse (a server was added, or a scan read a new system ID or model): no network.
// A call during a re-parse is not lost: the running one goes round again. A failed
// re-parse of the same fleet is retried after an hour at the earliest.
func (c *Checker) FleetChanged(ctx context.Context) {
	if c.cfg.Importer.Want == nil || c.cfg.Importer.Source == nil {
		return
	}
	c.dirty.Store(true)
	for c.dirty.Load() && c.reparsing.CompareAndSwap(false, true) {
		for c.dirty.CompareAndSwap(true, false) {
			c.reparse(ctx)
		}
		c.reparsing.Store(false) // a call that came in just now finds dirty set and runs again
	}
	c.notifyNew(ctx) // a scan may show an update not notified yet (a new server, a window ended)
}

const reparseRetry = time.Hour

func (c *Checker) reparse(ctx context.Context) {
	w, err := c.cfg.Importer.Want(ctx)
	if err != nil {
		c.cfg.Logger.Warn("fwcatalog: the fleet's systems could not be read", "err", err)
		return
	}
	key := wantKey(w)
	now := c.cfg.Now()
	c.mu.Lock()
	skip := key == c.lastWant || (key == c.failedWant && now.Sub(c.failedAt) < reparseRetry)
	c.mu.Unlock()
	if skip {
		return
	}
	err = c.cfg.Importer.Reparse(ctx)
	c.mu.Lock()
	if err != nil {
		c.failedWant, c.failedAt = key, now
	} else {
		c.lastWant = key
	}
	c.mu.Unlock()
	if err != nil {
		c.cfg.Logger.Warn("fwcatalog: re-parsing the cached catalog failed", "err", err)
		return
	}
	c.changed()
}

// wantKey is a stable text form of a Want.
func wantKey(w catalog.Want) string {
	ids := make([]string, 0, len(w.SystemIDs)+len(w.Models))
	for id := range w.SystemIDs {
		ids = append(ids, "s:"+id)
	}
	for m := range w.Models {
		ids = append(ids, "m:"+m)
	}
	slices.Sort(ids)
	return strings.Join(ids, "\n")
}
