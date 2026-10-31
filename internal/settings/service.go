package settings

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/store"
)

// Audit actions written by this package.
const (
	ActionGeneralUpdate = "admin.general.update"
	ActionGeneralReset  = "admin.general.reset"
	ActionPrefsUpdate   = "user.prefs.update"
)

// Errors. Messages are safe to show to the person making the change.
var (
	ErrLocked   = errors.New("this setting is managed by config.yaml or the section is locked")
	ErrConflict = errors.New("the settings were changed elsewhere; reload the page and try again")
	ErrInvalid  = errors.New("invalid value")
)

// Recorder writes audit rows; *audit.Logger implements it.
type Recorder interface {
	Record(ctx context.Context, e audit.Entry) (store.AuditRecord, error)
	RecordTx(ctx context.Context, tx *store.Tx, e audit.Entry) (store.AuditRecord, error)
}

// Config wires a Service. DB, Audit and File are required.
type Config struct {
	DB     *store.DB
	Audit  Recorder
	File   config.Config
	Now    func() time.Time
	Logger *slog.Logger
}

// Service loads, publishes and changes the runtime-managed settings.
type Service struct {
	cfg      Config
	provider *Provider
}

// New reads the saved settings, resolves them against the file and publishes the
// result. Rows that were not applied are logged.
func New(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil {
		return nil, errors.New("settings: DB and Audit are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Service{cfg: cfg}
	e, err := s.load(ctx, cfg.DB.Settings())
	if err != nil {
		return nil, err
	}
	for _, why := range e.Ignored {
		cfg.Logger.Warn("saved setting not applied", "reason", why)
	}
	s.provider = NewProvider(e)
	return s, nil
}

// Provider is the live view other packages read from.
func (s *Service) Provider() *Provider { return s.provider }

// Current is Provider().Current().
func (s *Service) Current() Effective { return s.provider.Current() }

func (s *Service) load(ctx context.Context, repo store.SettingsRepository) (Effective, error) {
	rows, err := repo.All(ctx)
	if err != nil {
		return Effective{}, err
	}
	rev, err := repo.Rev(ctx)
	if err != nil {
		return Effective{}, err
	}
	return Resolve(s.cfg.File, rows, rev), nil
}

// UpdateGeneral applies form values (key → raw form value) made by a. rev is the
// revision the form was rendered at. Only keys present in form are considered; a
// file-managed key or a locked section is refused (ErrLocked) unless its value is
// unchanged. Nothing is written when nothing changed. The change and its audit row
// commit together; the new settings are published after the commit.
func (s *Service) UpdateGeneral(ctx context.Context, a admin.Actor, rev int64, form map[string]string) ([]Change, error) {
	cur := s.Current()
	next, err := s.applyForm(cur, form)
	if err != nil {
		s.deny(ctx, a, err)
		return nil, err
	}
	if p := config.ValidateGeneral(next, s.cfg.File.Poll.MinInterval); len(p) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(p, "; "))
	}
	changes := Diff(config.GeneralKeys(), generalValues(cur.General), generalValues(next), generalPublic)
	if len(changes) == 0 {
		return nil, nil
	}
	var published Effective
	err = s.cfg.DB.WithTx(ctx, func(tx *store.Tx) error {
		newRev, werr := s.write(ctx, tx, a, rev, cur.General, next)
		if werr != nil {
			return werr
		}
		e := entry(a, ActionGeneralUpdate, params("general", changes, map[string]any{"rev": newRev}))
		if _, rerr := s.cfg.Audit.RecordTx(ctx, tx, e); rerr != nil {
			return rerr
		}
		var lerr error
		published, lerr = s.load(ctx, tx.Settings())
		return lerr
	})
	if errors.Is(err, store.ErrConflict) {
		s.deny(ctx, a, ErrConflict)
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	s.provider.publish(published)
	return changes, nil
}

// applyForm returns cur's General with the form values applied, refusing changes to
// keys the browser may not edit.
func (s *Service) applyForm(cur Effective, form map[string]string) (config.General, error) {
	next := cur.General
	for _, spec := range GeneralSpecs() {
		raw, ok := form[spec.Key]
		if !ok {
			continue
		}
		v, err := spec.parseForm(raw)
		if err != nil {
			return config.General{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if v == get(cur.General, spec.Key) {
			continue
		}
		if !cur.Editable(spec.Key) {
			return config.General{}, fmt.Errorf("%w: %s", ErrLocked, spec.Key)
		}
		next = set(next, spec.Key, v)
	}
	return next, nil
}

// write stores every changed key and bumps the revision (compare-and-set on rev).
func (s *Service) write(ctx context.Context, tx *store.Tx, a admin.Actor, rev int64, before, after config.General) (int64, error) {
	now := s.cfg.Now()
	for _, spec := range GeneralSpecs() {
		v := get(after, spec.Key)
		if v == get(before, spec.Key) {
			continue
		}
		row := store.SettingRow{Key: spec.Key, ValueJSON: spec.encode(v), UpdatedAt: now, UpdatedBy: a.Username}
		if err := tx.Settings().Put(ctx, row); err != nil {
			return 0, err
		}
	}
	return tx.Settings().BumpRev(ctx, rev)
}

// deny audits a refused change (locked key, stale revision). Invalid values are not
// audited: nothing about them is security relevant and the form shows the problem.
func (s *Service) deny(ctx context.Context, a admin.Actor, err error) {
	s.denyAction(ctx, a, ActionGeneralUpdate, err)
}

func (s *Service) denyAction(ctx context.Context, a admin.Actor, action string, err error) {
	s.denyTarget(ctx, a, action, "general", err)
}

// denyTarget audits a locked or conflicting change of target ("general", "gelf").
func (s *Service) denyTarget(ctx context.Context, a admin.Actor, action, target string, err error) {
	class := "locked"
	switch {
	case errors.Is(err, ErrConflict):
		class = "conflict"
	case !errors.Is(err, ErrLocked):
		return
	}
	e := entry(a, action, map[string]any{"target": target})
	e.Result, e.ErrorClass = audit.ResultDenied, class
	if _, rerr := s.cfg.Audit.Record(ctx, e); rerr != nil {
		s.cfg.Logger.Error("settings denial audit failed", "err", rerr)
	}
}

func entry(a admin.Actor, action string, p map[string]any) audit.Entry {
	return audit.Entry{Principal: a.Username, AuthMethod: a.Method, Role: string(a.Role), SrcIP: a.IP,
		Action: action, Params: p, Result: audit.ResultOK}
}

// Changes signals (coalesced) that the General settings changed.
func (s *Service) Changes() <-chan struct{} { return s.provider.Changes() }

// PendingRestart lists restart-only keys whose saved value is not running yet.
func (s *Service) PendingRestart() []string { return s.provider.PendingRestart() }

// ResetGeneral removes the saved value of key, so it falls back to the built-in default
// (a file-managed key is refused: the file always wins and cannot be reset here). rev is
// the revision the page was rendered at. A key with nothing saved is a no-op. The delete
// and its audit row (ActionGeneralReset, before → after) commit together.
func (s *Service) ResetGeneral(ctx context.Context, a admin.Actor, rev int64, key string) ([]Change, error) {
	cur := s.Current()
	spec, known := specFor(key)
	if !known {
		return nil, fmt.Errorf("%w: unknown setting", ErrInvalid)
	}
	if !cur.Editable(key) {
		s.denyAction(ctx, a, ActionGeneralReset, ErrLocked)
		return nil, fmt.Errorf("%w: %s", ErrLocked, key)
	}
	if f, _ := cur.Field(key); f.Source != SourceDB {
		return nil, nil
	}
	next := set(cur.General, key, get(s.cfg.File.General(), key))
	if p := config.ValidateGeneral(next, s.cfg.File.Poll.MinInterval); len(p) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(p, "; "))
	}
	changes := Diff([]string{spec.Key}, generalValues(cur.General), generalValues(next), generalPublic)
	var published Effective
	err := s.cfg.DB.WithTx(ctx, func(tx *store.Tx) error {
		if err := tx.Settings().Delete(ctx, key); err != nil {
			return err
		}
		newRev, err := tx.Settings().BumpRev(ctx, rev)
		if err != nil {
			return err
		}
		e := entry(a, ActionGeneralReset, params("general", changes, map[string]any{"rev": newRev}))
		if _, rerr := s.cfg.Audit.RecordTx(ctx, tx, e); rerr != nil {
			return rerr
		}
		published, err = s.load(ctx, tx.Settings())
		return err
	})
	if errors.Is(err, store.ErrConflict) {
		s.denyAction(ctx, a, ActionGeneralReset, ErrConflict)
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	s.provider.publish(published)
	return changes, nil
}
