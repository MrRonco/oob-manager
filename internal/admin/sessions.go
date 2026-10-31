package admin

import (
	"context"
	"encoding/hex"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/store"
)

// SessionRow is one browser session. ID is the hex of the stored hash of the cookie;
// it identifies the session for revocation and cannot be turned back into a cookie.
type SessionRow struct {
	ID        string
	CreatedAt time.Time
	LastSeen  time.Time
	IP        string
	UserAgent string
	Pending   bool // password accepted, TOTP outstanding
}

// sessionIDLen is the hex length of a SHA-256 session hash.
const sessionIDLen = 64

// Sessions lists a user's sessions, most recently seen first.
func (s *Service) Sessions(ctx context.Context, userID string) ([]SessionRow, error) {
	list, err := s.cfg.DB.Sessions().ListForUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	out := make([]SessionRow, 0, len(list))
	for _, x := range list {
		out = append(out, SessionRow{ID: hex.EncodeToString(x.IDHash), CreatedAt: x.CreatedAt, LastSeen: x.LastSeen,
			IP: x.IP, UserAgent: x.UA, Pending: x.Level != store.SessionFull})
	}
	return out, nil
}

// RevokeSession ends one session of userID. sid must be a SessionRow.ID of that user.
func (s *Service) RevokeSession(ctx context.Context, a Actor, userID, sid string) error {
	h, err := hex.DecodeString(sid)
	if err != nil || len(sid) != sessionIDLen {
		return ErrNotFound
	}
	base := map[string]any{"target_id": userID, "session": sid[:8]}
	return s.changeOrDeny(ctx, a.entry("admin.session.revoke", base), func(tx *store.Tx) (audit.Entry, error) {
		u, err := tx.Users().ByID(ctx, userID)
		if err != nil {
			return audit.Entry{}, err
		}
		err = tx.Sessions().DeleteOwned(ctx, userID, h)
		return a.entry("admin.session.revoke", with(base, "target", u.Username)), err
	})
}

// RevokeSessions ends every session of userID and returns how many there were.
func (s *Service) RevokeSessions(ctx context.Context, a Actor, userID string) (int64, error) {
	base := map[string]any{"target_id": userID}
	var n int64
	err := s.changeOrDeny(ctx, a.entry("admin.session.revoke_all", base), func(tx *store.Tx) (audit.Entry, error) {
		u, err := tx.Users().ByID(ctx, userID)
		if err != nil {
			return audit.Entry{}, err
		}
		if n, err = tx.Sessions().DeleteForUser(ctx, userID); err != nil {
			return audit.Entry{}, err
		}
		return a.entry("admin.session.revoke_all", with(base, "target", u.Username, "count", n)), nil
	})
	return n, err
}
