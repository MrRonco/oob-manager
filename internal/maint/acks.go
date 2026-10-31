package maint

import (
	"context"
	"fmt"

	"oob-manager/internal/admin"
	"oob-manager/internal/store"
)

// maxAuditedEntries bounds the entry ids listed in one acknowledgement audit row.
const maxAuditedEntries = 20

// Ack acknowledges log entries of one server with an optional comment, in one
// transaction with one audit row. The caller has checked that each entry exists and
// is a warning or critical entry; refs must all name serverID. Acknowledging an entry
// again replaces the comment and the acknowledger. It returns how many were saved.
func (s *Service) Ack(ctx context.Context, a admin.Actor, serverID string, refs []EventRef, comment string) (int, error) {
	text, cerr := CleanComment(comment)
	if cerr != nil {
		return 0, cerr
	}
	if len(refs) == 0 || len(refs) > MaxAcksPerRequest {
		return 0, fmt.Errorf("%w: acknowledge between 1 and %d entries at a time", ErrInvalid, MaxAcksPerRequest)
	}
	for _, r := range refs {
		if r.ServerID != serverID {
			return 0, fmt.Errorf("%w: entries of another server", ErrInvalid)
		}
		if err := ValidRef(r); err != nil {
			return 0, err
		}
	}
	s.write.Lock()
	defer s.write.Unlock()
	now := s.cfg.Now().UTC()
	err := s.change(ctx, func(tx *store.Tx) error {
		for _, r := range refs {
			if err := tx.Maint().PutAck(ctx, store.AckRow{ServerID: r.ServerID, Log: r.Log, EntryID: r.EntryID,
				CreatedMS: createdMS(r.Created), Comment: text, AckedBy: a.Username, AckedAt: now}); err != nil {
				return mapStoreErr(err)
			}
		}
		_, err := s.cfg.Audit.RecordTx(ctx, tx, entry(a, serverID, ActionAck, ackParams(refs, text)))
		return err
	})
	if err != nil {
		return 0, err
	}
	return len(refs), nil
}

func ackParams(refs []EventRef, comment string) map[string]any {
	ids := make([]string, 0, min(len(refs), maxAuditedEntries))
	for _, r := range refs[:min(len(refs), maxAuditedEntries)] {
		ids = append(ids, r.Log+":"+r.EntryID)
	}
	p := map[string]any{"count": len(refs), "entries": ids}
	if comment != "" {
		p["comment"] = comment
	}
	return p
}

// Unack removes an acknowledgement (the entry counts as a problem again).
func (s *Service) Unack(ctx context.Context, a admin.Actor, r EventRef) error {
	if err := ValidRef(r); err != nil {
		return err
	}
	s.write.Lock()
	defer s.write.Unlock()
	if _, ok := s.AckOf(r); !ok {
		return ErrNotFound
	}
	return s.change(ctx, func(tx *store.Tx) error {
		if err := tx.Maint().DeleteAck(ctx, r.ServerID, r.Log, r.EntryID, createdMS(r.Created)); err != nil {
			return mapStoreErr(err)
		}
		_, err := s.cfg.Audit.RecordTx(ctx, tx, entry(a, r.ServerID, ActionUnack,
			map[string]any{"count": 1, "entries": []string{r.Log + ":" + r.EntryID}}))
		return err
	})
}
