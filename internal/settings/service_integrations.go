package settings

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"oob-manager/internal/admin"
	"oob-manager/internal/config"
	"oob-manager/internal/store"
)

// Audit actions of the Integrations section (tech_doc §34). The integrations service
// writes the rest (applied, fingerprint, test).
const (
	ActionIntegrationsUpdate = "admin.integrations.update"
	ActionIntegrationsReset  = "admin.integrations.reset"
	ActionIntegrationsPin    = "admin.integrations.gelf.pin"
)

// auditTargetGELF is the "target" of every GELF settings audit row.
const auditTargetGELF = "gelf"

// PinOrigin says how a new pin was obtained: Via "fetched" (TOFU, proof checked) or
// "manual" (typed or pasted; also the default), and which certificate was pinned
// ("leaf" or "issuer"; empty when typed).
type PinOrigin struct{ Via, Pinned string }

// UpdateIntegrations applies form values (key → raw form value) to the GELF target,
// exactly like UpdateGeneral: only submitted keys count, file-managed keys and a locked
// section are refused unless unchanged, the result must pass config.ValidateGELF and
// the static destination policy, and the rows, the revision and the audit row commit
// together. A changed pin also writes admin.integrations.gelf.pin in the same
// transaction. The caller (the integrations service) applies the new target after
// this returns, so the update row is shipped through the old one.
func (s *Service) UpdateIntegrations(ctx context.Context, a admin.Actor, rev int64, form map[string]string,
	pin PinOrigin) ([]Change, error) {
	cur := s.Current()
	next, err := applyIntegrationsForm(cur, form)
	if err != nil {
		s.denyTarget(ctx, a, ActionIntegrationsUpdate, auditTargetGELF, err)
		return nil, err
	}
	if p := checkGELF(next, s.cfg.File.GELFNetworks()); len(p) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(p, "; "))
	}
	changes := Diff(config.IntegrationKeys(), integrationValues(cur.Integrations), integrationValues(next), integrationsPublic)
	if len(changes) == 0 {
		return nil, nil
	}
	err = s.commit(ctx, rev, func(tx *store.Tx, newRev int64) error {
		if werr := s.writeIntegrations(ctx, tx, a, cur.Integrations, next); werr != nil {
			return werr
		}
		e := entry(a, ActionIntegrationsUpdate, params(auditTargetGELF, changes, map[string]any{"rev": newRev}))
		if _, rerr := s.cfg.Audit.RecordTx(ctx, tx, e); rerr != nil {
			return rerr
		}
		if next.PinSHA256 == cur.Integrations.PinSHA256 || next.PinSHA256 == "" {
			return nil
		}
		_, rerr := s.cfg.Audit.RecordTx(ctx, tx, entry(a, ActionIntegrationsPin, pinParams(pin)))
		return rerr
	})
	if errors.Is(err, ErrConflict) {
		s.denyTarget(ctx, a, ActionIntegrationsUpdate, auditTargetGELF, err)
	}
	if err != nil {
		return nil, err
	}
	return changes, nil
}

func pinParams(p PinOrigin) map[string]any {
	via := p.Via
	if via == "" {
		via = "manual"
	}
	out := map[string]any{"target": auditTargetGELF, "pin_via": via}
	if p.Pinned != "" {
		out["pinned"] = p.Pinned
	}
	return out
}

func applyIntegrationsForm(cur Effective, form map[string]string) (config.GELF, error) {
	next := cur.Integrations
	for _, spec := range IntegrationSpecs() {
		raw, ok := form[spec.Key]
		if !ok {
			continue
		}
		v, err := spec.parseForm(raw)
		if err != nil {
			return config.GELF{}, fmt.Errorf("%w: %v", ErrInvalid, err)
		}
		if v == getI(cur.Integrations, spec.Key) {
			continue
		}
		if !cur.IntegrationEditable(spec.Key) {
			return config.GELF{}, fmt.Errorf("%w: %s", ErrLocked, spec.Key)
		}
		next = setI(next, spec.Key, v)
	}
	return next, nil
}

func (s *Service) writeIntegrations(ctx context.Context, tx *store.Tx, a admin.Actor, before, after config.GELF) error {
	now := s.cfg.Now()
	for _, spec := range IntegrationSpecs() {
		v := getI(after, spec.Key)
		if v == getI(before, spec.Key) {
			continue
		}
		row := store.SettingRow{Key: spec.Key, ValueJSON: spec.encode(v), UpdatedAt: now, UpdatedBy: a.Username}
		if err := tx.Settings().Put(ctx, row); err != nil {
			return err
		}
	}
	return nil
}

// commit runs fn in a transaction after bumping the revision (compare-and-set on rev),
// then re-reads and publishes the settings. A stale revision is ErrConflict.
func (s *Service) commit(ctx context.Context, rev int64, fn func(tx *store.Tx, newRev int64) error) error {
	var published Effective
	err := s.cfg.DB.WithTx(ctx, func(tx *store.Tx) error {
		newRev, err := tx.Settings().BumpRev(ctx, rev)
		if err != nil {
			return err
		}
		if err = fn(tx, newRev); err != nil {
			return err
		}
		published, err = s.load(ctx, tx.Settings())
		return err
	})
	if errors.Is(err, store.ErrConflict) {
		return ErrConflict
	}
	if err != nil {
		return err
	}
	s.provider.publish(published)
	return nil
}

// ResetIntegrations deletes the saved value of one GELF key so it falls back to the
// file's or built-in value (file-managed keys and a locked section are refused). A key
// with nothing saved is a no-op. The delete and its audit row commit together.
func (s *Service) ResetIntegrations(ctx context.Context, a admin.Actor, rev int64, key string) ([]Change, error) {
	cur := s.Current()
	if _, known := integrationSpecFor(key); !known {
		return nil, fmt.Errorf("%w: unknown setting", ErrInvalid)
	}
	if !cur.IntegrationEditable(key) {
		s.denyTarget(ctx, a, ActionIntegrationsReset, auditTargetGELF, ErrLocked)
		return nil, fmt.Errorf("%w: %s", ErrLocked, key)
	}
	if f, _ := cur.IntegrationField(key); f.Source != SourceDB {
		return nil, nil
	}
	next := setI(cur.Integrations, key, getI(s.cfg.File.GELF(), key))
	if p := checkGELF(next, s.cfg.File.GELFNetworks()); len(p) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrInvalid, strings.Join(p, "; "))
	}
	changes := Diff([]string{key}, integrationValues(cur.Integrations), integrationValues(next), integrationsPublic)
	err := s.commit(ctx, rev, func(tx *store.Tx, newRev int64) error {
		if err := tx.Settings().Delete(ctx, key); err != nil {
			return err
		}
		e := entry(a, ActionIntegrationsReset, params(auditTargetGELF, changes, map[string]any{"rev": newRev}))
		_, err := s.cfg.Audit.RecordTx(ctx, tx, e)
		return err
	})
	if errors.Is(err, ErrConflict) {
		s.denyTarget(ctx, a, ActionIntegrationsReset, auditTargetGELF, err)
	}
	if err != nil {
		return nil, err
	}
	return changes, nil
}
