package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

type sessionRepo struct{ db querier }

const sessionColumns = `id_hash, user_id, level, created_at, last_seen, stepup_at, ip, ua`

const sessionInsert = `INSERT INTO sessions (` + sessionColumns + `) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

func sessionArgs(op string, s Session) ([]any, error) {
	if len(s.IDHash) == 0 || s.UserID == "" {
		return nil, invalid(op, "id_hash and user_id are required")
	}
	level := s.Level
	if level == 0 {
		level = SessionPending
	}
	return []any{s.IDHash, s.UserID, int(level), toMS(s.CreatedAt), toMS(s.LastSeen),
		nullMS(s.StepUpAt), s.IP, s.UA}, nil
}

func (r sessionRepo) Create(ctx context.Context, s Session) error {
	const op = "create session"
	args, err := sessionArgs(op, s)
	if err != nil {
		return err
	}
	_, err = r.db.ExecContext(ctx, sessionInsert, args...)
	return mapErr(op, err)
}

// Replace deletes oldIDHash and inserts s in one transaction. If oldIDHash is gone
// (logged out concurrently) nothing is inserted and ErrNotFound is returned.
func (r sessionRepo) Replace(ctx context.Context, oldIDHash []byte, s Session) error {
	const op = "replace session"
	args, err := sessionArgs(op, s)
	if err != nil {
		return err
	}
	return inTx(ctx, r.db, op, func(q querier) error {
		res, err := q.ExecContext(ctx, `DELETE FROM sessions WHERE id_hash = ?`, oldIDHash)
		if err != nil {
			return mapErr(op, err)
		}
		n, err := res.RowsAffected()
		if err != nil || n == 0 {
			return errors.Join(fmt.Errorf("store: %s: %w", op, ErrNotFound), err)
		}
		_, err = q.ExecContext(ctx, sessionInsert, args...)
		return mapErr(op, err)
	})
}

func (r sessionRepo) Get(ctx context.Context, idHash []byte) (Session, error) {
	return scanSession("get session", r.db.QueryRowContext(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE id_hash = ?`, idHash))
}

func scanSession(op string, row rowScanner) (Session, error) {
	var (
		s             Session
		level         int
		created, seen int64
		stepup        sql.NullInt64
	)
	if err := row.Scan(&s.IDHash, &s.UserID, &level, &created, &seen, &stepup, &s.IP, &s.UA); err != nil {
		return Session{}, mapErr(op, err)
	}
	s.Level = SessionLevel(level)
	s.CreatedAt, s.LastSeen, s.StepUpAt = fromMS(created), fromMS(seen), fromNullMS(stepup)
	return s, nil
}

func (r sessionRepo) Touch(ctx context.Context, idHash []byte, at time.Time) error {
	return execOne(ctx, r.db, "touch session", `UPDATE sessions SET last_seen = ? WHERE id_hash = ?`, toMS(at), idHash)
}

func (r sessionRepo) MarkStepUp(ctx context.Context, idHash []byte, at time.Time) error {
	return execOne(ctx, r.db, "step-up session", `UPDATE sessions SET stepup_at = ? WHERE id_hash = ?`, toMS(at), idHash)
}

func (r sessionRepo) Delete(ctx context.Context, idHash []byte) error {
	return execOne(ctx, r.db, "delete session", `DELETE FROM sessions WHERE id_hash = ?`, idHash)
}

func (r sessionRepo) DeleteForUser(ctx context.Context, userID string) (int64, error) {
	return execCount(ctx, r.db, "delete user sessions", `DELETE FROM sessions WHERE user_id = ?`, userID)
}

func (r sessionRepo) DeleteExpired(ctx context.Context, idleBefore, createdBefore time.Time) (int64, error) {
	return execCount(ctx, r.db, "delete expired sessions",
		`DELETE FROM sessions WHERE last_seen < ? OR created_at < ?`, toMS(idleBefore), toMS(createdBefore))
}

func (r sessionRepo) ListForUser(ctx context.Context, userID string) ([]Session, error) {
	const op = "list user sessions"
	rows, err := r.db.QueryContext(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE user_id = ?
		ORDER BY last_seen DESC, created_at DESC`, userID)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(op, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, mapErr(op, rows.Err())
}

func (r sessionRepo) DeleteOwned(ctx context.Context, userID string, idHash []byte) error {
	return execOne(ctx, r.db, "delete owned session", `DELETE FROM sessions WHERE id_hash = ? AND user_id = ?`,
		idHash, userID)
}

func (r sessionRepo) CountByUser(ctx context.Context) (map[string]int, error) {
	const op = "count sessions"
	rows, err := r.db.QueryContext(ctx, `SELECT user_id, count(*) FROM sessions GROUP BY user_id`)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var (
			id string
			n  int
		)
		if err := rows.Scan(&id, &n); err != nil {
			return nil, mapErr(op, err)
		}
		out[id] = n
	}
	return out, mapErr(op, rows.Err())
}
