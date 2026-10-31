package bmcsec

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/bmc/textclean"
	"oob-manager/internal/store"
)

// CleanComment validates an acceptance comment: one line of text (no control
// characters, valid UTF-8), then sanitized like BMC text (textclean: zero-width and
// bidirectional format characters removed, trimmed), 1 to MaxComment bytes. The
// comment reaches notification targets, so it must read as it is.
func CleanComment(s string) (string, error) {
	if !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl) {
		return "", fmt.Errorf("%w: the comment must be one line of text", ErrInvalid)
	}
	s = textclean.Clean(s, 0)
	switch {
	case s == "":
		return "", fmt.Errorf("%w: say why the risk is accepted", ErrInvalid)
	case len(s) > MaxComment:
		return "", fmt.Errorf("%w: the comment is longer than %d bytes", ErrInvalid, MaxComment)
	}
	return s, nil
}

// Accept records an admin's decision to accept a finding as a risk: it stops counting
// as a problem and is not notified. It covers exactly the current result and subject
// (by hash of the whole subject) on the BMC address the server has now; when the
// finding changes or is resolved, or the server moves, the acceptance ends
// (expireAcceptances). Accepting again replaces the comment. The finding is evaluated
// under the write lock and compared with seen, the finding as the page showed it
// (Finding.Seen: result and subject hash): a finding that changed since is refused
// with ErrChanged, so an admin never accepts something they did not look at.
func (s *Service) Accept(ctx context.Context, a admin.Actor, serverID, checkID, comment, seen string) error {
	text, err := CleanComment(comment)
	if err != nil {
		return err
	}
	if s.cfg.DB == nil {
		return ErrUnavailable
	}
	s.write.Lock()
	defer s.write.Unlock()
	f, addr, err := s.acceptable(serverID, checkID)
	if err != nil {
		return err
	}
	if f.Seen() != seen {
		return ErrChanged
	}
	row := store.SecurityAcceptRow{ServerID: serverID, ServerAddr: addr, CheckID: checkID, Result: string(f.Result),
		Subject: f.Subject, SubjectHash: f.SubjectHash, Comment: text, AcceptedBy: a.Username, AcceptedAt: s.cfg.Now().UTC()}
	return s.change(ctx, func(tx *store.Tx) error {
		if err := tx.Security().PutAccept(ctx, row); err != nil {
			return err
		}
		_, err := s.cfg.Audit.RecordTx(ctx, tx, auditEntry(a, serverID, ActionAccept,
			map[string]any{"check": checkID, "title": f.Check.Title, "result": string(f.Result), "subject_hash": f.SubjectHash,
				"comment": text}, audit.ResultOK, ""))
		return err
	})
}

// acceptable is the finding an acceptance would cover right now and the BMC address it
// binds to; the caller holds write.
func (s *Service) acceptable(serverID, checkID string) (Finding, string, error) {
	r, in, ok := s.evaluate(serverID)
	if !ok || in.Address == "" {
		return Finding{}, "", ErrNotFound
	}
	f, ok := r.Finding(checkID)
	switch {
	case !ok:
		return Finding{}, "", ErrNotFound
	case !f.Result.Problem():
		return Finding{}, "", ErrNotProblem
	}
	return f, in.Address, nil
}

// Unaccept removes an acceptance: the finding counts again.
func (s *Service) Unaccept(ctx context.Context, a admin.Actor, serverID, checkID string) error {
	if s.cfg.DB == nil {
		return ErrUnavailable
	}
	s.write.Lock()
	defer s.write.Unlock()
	return s.drop(ctx, a, serverID, checkID, "removed")
}

// drop deletes one acceptance with its audit row; the caller holds write.
func (s *Service) drop(ctx context.Context, a admin.Actor, serverID, checkID, reason string) error {
	return s.change(ctx, func(tx *store.Tx) error {
		if err := tx.Security().DeleteAccept(ctx, serverID, checkID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return ErrNotFound
			}
			return err
		}
		_, err := s.cfg.Audit.RecordTx(ctx, tx, auditEntry(a, serverID, ActionUnaccept,
			map[string]any{"check": checkID, "title": checkTitle(checkID), "reason": reason}, audit.ResultOK, ""))
		return err
	})
}

// checkTitle is the catalog title of a check ("" for an unknown ID).
func checkTitle(id string) string {
	for _, c := range Catalog() {
		if c.ID == id {
			return c.Title
		}
	}
	return ""
}

// change runs fn in one transaction, then reloads the acceptances whatever happened:
// the in-memory copy follows the database, so a row another path deleted (a server
// removal) leaves memory as soon as it is touched.
func (s *Service) change(ctx context.Context, fn func(tx *store.Tx) error) error {
	err := s.cfg.DB.WithTx(ctx, fn)
	if rerr := s.reload(ctx); rerr != nil {
		return errors.Join(err, rerr)
	}
	return err
}

// expireAcceptances reloads the acceptances (rows a server removal deleted leave memory
// here at the latest) and ends every one whose server moved to another BMC address, or
// whose finding is resolved (pass, info, or the check no longer applies) or changed
// (another result or subject). A finding that cannot be read right now, or a server
// that is not polled or not configured, keeps its acceptance.
func (s *Service) expireAcceptances(ctx context.Context) {
	s.write.Lock()
	defer s.write.Unlock()
	if err := s.reload(ctx); err != nil {
		s.cfg.Logger.Error("bmcsec: reloading the acceptances failed", "err", err)
		return
	}
	for _, a := range *s.accepts.Load() {
		reason := s.stale(a)
		if reason == "" {
			continue
		}
		if err := s.drop(ctx, systemActor, a.ServerID, a.CheckID, reason); err != nil && !errors.Is(err, ErrNotFound) {
			s.cfg.Logger.Error("bmcsec: ending an acceptance failed", "server", a.ServerID, "check", a.CheckID, "err", err)
		}
	}
}

// stale is why an acceptance no longer applies ("" while it does).
func (s *Service) stale(a Acceptance) string {
	if in, ok := s.cfg.Inputs(a.ServerID); ok && in.Address != "" && in.Address != a.ServerAddr {
		return "server changed"
	}
	r, _, ok := s.evaluate(a.ServerID)
	if !ok {
		return ""
	}
	f, ok := r.Finding(a.CheckID)
	switch {
	case !ok, f.Result == Pass, f.Result == Info:
		return "resolved"
	case !f.Result.Problem():
		return ""
	case !a.Covers(f):
		return "changed"
	default:
		return ""
	}
}
