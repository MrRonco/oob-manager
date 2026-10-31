package maint

import (
	"context"
	"fmt"

	"oob-manager/internal/admin"
	"oob-manager/internal/authz"
	"oob-manager/internal/store"
)

// Note bodies never reach the audit log (a note may hold anything someone pasted, and
// the audit is shipped off the box): rows carry the note id, its length and author.

// AddNote writes a note on a server as a.
func (s *Service) AddNote(ctx context.Context, a admin.Actor, serverID, body string) (Note, error) {
	text, cerr := CleanNote(body)
	if cerr != nil {
		return Note{}, cerr
	}
	if serverID == "" || len(serverID) > 64 || a.UserID == "" {
		return Note{}, fmt.Errorf("%w: unknown server or user", ErrInvalid)
	}
	s.write.Lock()
	defer s.write.Unlock()
	if len(s.st.Load().notes[serverID]) >= MaxNotesPerServer {
		return Note{}, fmt.Errorf("%w: a server keeps at most %d notes; delete old ones first", ErrInvalid, MaxNotesPerServer)
	}
	now := s.cfg.Now().UTC()
	n := Note{ServerID: serverID, Body: text, AuthorID: a.UserID, Author: a.Username, CreatedAt: now, UpdatedAt: now}
	err := s.change(ctx, func(tx *store.Tx) error {
		id, err := tx.Maint().AddNote(ctx, store.NoteRow{ServerID: serverID, Body: text, AuthorID: a.UserID,
			Author: a.Username, CreatedAt: now, UpdatedAt: now})
		if err != nil {
			return mapStoreErr(err)
		}
		n.ID = id
		_, err = s.cfg.Audit.RecordTx(ctx, tx, entry(a, serverID, ActionNoteAdd, map[string]any{"note": id, "bytes": len(text)}))
		return err
	})
	if err != nil {
		return Note{}, err
	}
	return n, nil
}

// EditNote replaces the body of a's own note.
func (s *Service) EditNote(ctx context.Context, a admin.Actor, serverID string, id int64, body string) error {
	text, err := CleanNote(body)
	if err != nil {
		return err
	}
	s.write.Lock()
	defer s.write.Unlock()
	n, ok := s.Note(serverID, id)
	if !ok {
		return ErrNotFound
	}
	if n.AuthorID != a.UserID {
		return ErrForbidden
	}
	if n.Body == text {
		return nil
	}
	return s.change(ctx, func(tx *store.Tx) error {
		if err := tx.Maint().UpdateNote(ctx, id, text, s.cfg.Now().UTC()); err != nil {
			return mapStoreErr(err)
		}
		_, err := s.cfg.Audit.RecordTx(ctx, tx, entry(a, serverID, ActionNoteEdit,
			map[string]any{"note": id, "bytes_before": len(n.Body), "bytes": len(text)}))
		return err
	})
}

// DeleteNote removes a's own note; an admin may delete anyone's.
func (s *Service) DeleteNote(ctx context.Context, a admin.Actor, serverID string, id int64) error {
	s.write.Lock()
	defer s.write.Unlock()
	n, ok := s.Note(serverID, id)
	if !ok {
		return ErrNotFound
	}
	if n.AuthorID != a.UserID && a.Role != authz.RoleAdmin {
		return ErrForbidden
	}
	return s.change(ctx, func(tx *store.Tx) error {
		if err := tx.Maint().DeleteNote(ctx, id); err != nil {
			return mapStoreErr(err)
		}
		_, err := s.cfg.Audit.RecordTx(ctx, tx, entry(a, serverID, ActionNoteDelete,
			map[string]any{"note": id, "author": n.Author, "bytes": len(n.Body), "pinned": n.Pinned}))
		return err
	})
}

// PinNote pins note id to the top of the server page (replacing any other pin); id 0
// unpins. Anyone who may write notes may pin any note of the server.
func (s *Service) PinNote(ctx context.Context, a admin.Actor, serverID string, id int64) error {
	s.write.Lock()
	defer s.write.Unlock()
	if id != 0 {
		if _, ok := s.Note(serverID, id); !ok {
			return ErrNotFound
		}
	}
	return s.change(ctx, func(tx *store.Tx) error {
		if err := tx.Maint().SetPin(ctx, serverID, id); err != nil {
			return mapStoreErr(err)
		}
		p := map[string]any{"note": id, "pinned": id != 0}
		_, err := s.cfg.Audit.RecordTx(ctx, tx, entry(a, serverID, ActionNotePin, p))
		return err
	})
}
