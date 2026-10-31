package notify

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/store"
)

// Audit actions written by the service.
const (
	ActionTargetCreate = "admin.notify.create"
	ActionTargetUpdate = "admin.notify.update"
	ActionTargetDelete = "admin.notify.delete"
	ActionTargetTest   = "admin.notify.test"
)

// change is one audited field change; secrets appear as versions only.
type change struct {
	Field, Before, After string
}

// Create stores a new browser-managed target. Validation errors wrap ErrInvalid and
// are not audited (nothing was attempted); refusals are.
func (s *Service) Create(ctx context.Context, a admin.Actor, t Target, sec Secrets) error {
	if s.Locked() {
		s.deny(ctx, a, ActionTargetCreate, t.ID, "locked")
		return ErrLocked
	}
	s.write.Lock()
	defer s.write.Unlock()
	reg := s.reg.Load()
	if _, ok := reg.byID[t.ID]; ok || slices.Contains(reg.shadowed, t.ID) {
		return ErrExists
	}
	now := s.cfg.Now()
	t.Source, t.UpdatedAt, t.UpdatedBy, t.SecretVersion = SourceDB, now, a.Username, 0
	if !sec.IsZero() {
		t.SecretVersion = 1
	}
	if err := Validate(t, sec); err != nil {
		return err
	}
	return s.save(ctx, a, ActionTargetCreate, t, sec, now, nil)
}

// Update changes a browser-managed target. The id and kind are fixed. Secret fields
// left blank keep the stored value, unless the URL changed: secrets are bound to the
// destination and are never carried to a new one, so they must be entered again.
// clearSecrets removes the stored secrets (optional ones: ntfy token, webhook HMAC key,
// SMTP login).
func (s *Service) Update(ctx context.Context, a admin.Actor, t Target, sec Secrets, clearSecrets bool) error {
	s.write.Lock()
	defer s.write.Unlock()
	cur, ok := s.reg.Load().byID[t.ID]
	switch {
	case !ok:
		return ErrNotFound
	case s.Locked() || cur.t.Source == SourceFile:
		s.deny(ctx, a, ActionTargetUpdate, t.ID, "locked")
		return ErrLocked
	}
	t.Kind, t.Source = cur.t.Kind, SourceDB
	next, secChanged := nextSecrets(cur, t.URL != cur.t.URL, sec, clearSecrets)
	t.SecretVersion = cur.t.SecretVersion
	if secChanged {
		t.SecretVersion++
	}
	if err := Validate(t, next); err != nil {
		return err
	}
	changes := diff(cur.t, t, secChanged)
	if len(changes) == 0 {
		return nil
	}
	now := s.cfg.Now()
	t.UpdatedAt, t.UpdatedBy = now, a.Username
	return s.save(ctx, a, ActionTargetUpdate, t, next, now, changes)
}

// nextSecrets merges the submitted secrets over the stored ones.
func nextSecrets(cur entry, destChanged bool, sec Secrets, drop bool) (Secrets, bool) {
	old := cur.sec
	if cur.unsealErr {
		old = Secrets{}
	}
	switch {
	case drop:
		return Secrets{}, !old.IsZero() || cur.unsealErr
	case destChanged:
		return sec, !old.IsZero() || !sec.IsZero() || cur.unsealErr
	}
	next := old
	if !sec.Token.IsZero() {
		next.Token = sec.Token
	}
	if !sec.User.IsZero() {
		next.User = sec.User
	}
	if !sec.Password.IsZero() {
		next.Password = sec.Password
	}
	return next, !sec.IsZero()
}

// save seals the secrets and writes the row and its audit entry in one transaction.
func (s *Service) save(ctx context.Context, a admin.Actor, action string, t Target, sec Secrets, now time.Time,
	changes []change) error {
	var enc []byte
	if !sec.IsZero() {
		var err error
		if enc, err = s.cfg.Sealer.Seal(t, sec); err != nil {
			return err
		}
	}
	row, err := toRow(t, enc)
	if err != nil {
		return err
	}
	row.CreatedAt = now
	err = s.cfg.DB.WithTx(ctx, func(tx *store.Tx) error {
		if perr := tx.Notify().PutTarget(ctx, row); perr != nil {
			return perr
		}
		_, rerr := s.cfg.Audit.RecordTx(ctx, tx, auditEntry(a, action, targetParams(t, changes)))
		return rerr
	})
	if err != nil {
		return err
	}
	return s.reload(ctx)
}

// Delete removes a browser-managed target.
func (s *Service) Delete(ctx context.Context, a admin.Actor, id string) error {
	s.write.Lock()
	defer s.write.Unlock()
	cur, ok := s.reg.Load().byID[id]
	switch {
	case !ok:
		return ErrNotFound
	case s.Locked() || cur.t.Source == SourceFile:
		s.deny(ctx, a, ActionTargetDelete, id, "locked")
		return ErrLocked
	}
	err := s.cfg.DB.WithTx(ctx, func(tx *store.Tx) error {
		if err := tx.Notify().DeleteTarget(ctx, id); err != nil {
			return err
		}
		_, err := s.cfg.Audit.RecordTx(ctx, tx, auditEntry(a, ActionTargetDelete, targetParams(cur.t, nil)))
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	s.disp.Forget(id)
	return s.reload(ctx)
}

// SendTest delivers a test message to one target now (file-managed targets included)
// and audits the outcome class. The returned error carries only a class.
func (s *Service) SendTest(ctx context.Context, a admin.Actor, id string) error {
	en, ok := s.reg.Load().byID[id]
	if !ok {
		return ErrNotFound
	}
	e := Event{ID: newEventID(), Class: ClassTest, Severity: SeverityInfo, Key: "test/" + id, At: s.cfg.Now(),
		Title: "Test from oob-manager",
		Message: "This is a test notification for the target " + en.t.Name + ", sent by " + a.Username +
			" from Settings → Notifications."}
	var err error
	if en.unsealErr {
		err = failed(classSecrets, false, "notify: stored secrets cannot be opened")
	} else {
		err = s.disp.SendNow(ctx, en.t, en.sec, e)
	}
	ae := auditEntry(a, ActionTargetTest, targetParams(en.t, nil))
	if err != nil {
		ae.Result, ae.ErrorClass = audit.ResultError, ErrorClass(err)
	}
	if _, rerr := s.cfg.Audit.Record(ctx, ae); rerr != nil {
		s.cfg.Logger.Error("notify: test audit failed", "err", rerr)
	}
	return err
}

func (s *Service) deny(ctx context.Context, a admin.Actor, action, id, class string) {
	if s.cfg.Audit == nil {
		return
	}
	e := auditEntry(a, action, map[string]any{"target": id})
	e.Result, e.ErrorClass = audit.ResultDenied, class
	if _, err := s.cfg.Audit.Record(ctx, e); err != nil {
		s.cfg.Logger.Error("notify: denial audit failed", "err", err)
	}
}

func auditEntry(a admin.Actor, action string, p map[string]any) audit.Entry {
	return audit.Entry{Principal: a.Username, AuthMethod: a.Method, Role: string(a.Role), SrcIP: a.IP,
		Action: action, Params: p, Result: audit.ResultOK}
}

// targetParams never includes the URL path or query (an ntfy topic or webhook path can
// act as a credential) or any secret: only the host and secret versions.
func targetParams(t Target, changes []change) map[string]any {
	p := map[string]any{"target": t.ID, "kind": string(t.Kind), "name": t.Name, "host": t.Host()}
	if len(changes) > 0 {
		list := make([]map[string]string, 0, len(changes))
		for _, c := range changes {
			list = append(list, map[string]string{"field": c.Field, "before": c.Before, "after": c.After})
		}
		p["changes"] = list
	}
	return p
}

// diff lists the changed fields of a target.
func diff(a, b Target, secChanged bool) []change {
	var out []change
	add := func(field, before, after string) {
		if before != after {
			out = append(out, change{field, before, after})
		}
	}
	add("name", a.Name, b.Name)
	if a.URL != b.URL {
		out = append(out, change{"destination", a.Host(), destLabel(a, b)})
	}
	add("enabled", strconv.FormatBool(a.Enabled), strconv.FormatBool(b.Enabled))
	add("allow_plaintext", strconv.FormatBool(a.AllowPlaintext), strconv.FormatBool(b.AllowPlaintext))
	add("include_detail", strconv.FormatBool(a.IncludeDetail), strconv.FormatBool(b.IncludeDetail))
	add("pushover_emergency", strconv.FormatBool(a.PushoverEmergency), strconv.FormatBool(b.PushoverEmergency))
	add("classes", classList(a.Classes), classList(b.Classes))
	add("min_severity", a.MinSeverity.String(), b.MinSeverity.String())
	add("email_from", a.EmailFrom, b.EmailFrom)
	add("email_to", strings.Join(a.EmailTo, ","), strings.Join(b.EmailTo, ","))
	add("email_security", string(a.EmailSecurity), string(b.EmailSecurity))
	if secChanged {
		out = append(out, change{"secrets", "[redacted] v" + strconv.Itoa(a.SecretVersion),
			"[redacted] v" + strconv.Itoa(b.SecretVersion)})
	}
	return out
}

// destLabel describes the new destination by host only; a change of path, topic or
// query on the same host is marked, never shown.
func destLabel(a, b Target) string {
	if a.Host() == b.Host() {
		return b.Host() + " (path or query changed)"
	}
	return b.Host()
}

func classList(cs []Class) string {
	names := make([]string, 0, len(cs))
	for _, c := range cs {
		names = append(names, string(c))
	}
	return strings.Join(names, ",")
}
