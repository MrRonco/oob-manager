package store

import (
	"context"
	"database/sql"
	"time"
)

type enrolmentRepo struct{ db querier }

const enrolmentColumns = `id, user_id, token_hash, purpose, created_by, created_at, expires_at, used_at`

func (r enrolmentRepo) Create(ctx context.Context, e EnrolmentToken) error {
	const op = "create enrolment"
	switch {
	case e.ID == "" || e.UserID == "" || len(e.TokenHash) == 0 || e.CreatedBy == "":
		return invalid(op, "id, user_id, token_hash and created_by are required")
	case !e.Purpose.Valid():
		return invalid(op, "unknown purpose")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO enrolment_tokens (`+enrolmentColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, e.ID, e.UserID, e.TokenHash, string(e.Purpose), e.CreatedBy,
		toMS(e.CreatedAt), toMS(e.ExpiresAt), nullMS(e.UsedAt))
	return mapErr(op, err)
}

func (r enrolmentRepo) ByHash(ctx context.Context, hash []byte) (EnrolmentToken, error) {
	return scanEnrolment("enrolment by hash", r.db.QueryRowContext(ctx,
		`SELECT `+enrolmentColumns+` FROM enrolment_tokens WHERE token_hash = ?`, hash))
}

// Consume is one UPDATE … RETURNING: the unused/unexpired check and the claim are a
// single statement, so two redemptions of one link cannot both succeed.
func (r enrolmentRepo) Consume(ctx context.Context, hash []byte, now time.Time) (EnrolmentToken, error) {
	return scanEnrolment("consume enrolment", r.db.QueryRowContext(ctx, `UPDATE enrolment_tokens SET used_at = ?
		WHERE token_hash = ? AND used_at IS NULL AND expires_at > ? RETURNING `+enrolmentColumns,
		toMS(now), hash, toMS(now)))
}

func (r enrolmentRepo) InvalidateForUser(ctx context.Context, userID string, at time.Time) (int64, error) {
	return execCount(ctx, r.db, "invalidate enrolments",
		`UPDATE enrolment_tokens SET used_at = ? WHERE user_id = ? AND used_at IS NULL`, toMS(at), userID)
}

func (r enrolmentRepo) Pending(ctx context.Context, now time.Time) ([]EnrolmentToken, error) {
	const op = "pending enrolments"
	rows, err := r.db.QueryContext(ctx, `SELECT `+enrolmentColumns+` FROM enrolment_tokens
		WHERE used_at IS NULL AND expires_at > ? ORDER BY created_at DESC, id`, toMS(now))
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []EnrolmentToken
	for rows.Next() {
		e, err := scanEnrolment(op, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, mapErr(op, rows.Err())
}

func (r enrolmentRepo) Prune(ctx context.Context, before time.Time) (int64, error) {
	return execCount(ctx, r.db, "prune enrolments", `DELETE FROM enrolment_tokens WHERE expires_at < ?`, toMS(before))
}

func scanEnrolment(op string, row rowScanner) (EnrolmentToken, error) {
	var (
		e                EnrolmentToken
		purpose          string
		created, expires int64
		used             sql.NullInt64
	)
	err := row.Scan(&e.ID, &e.UserID, &e.TokenHash, &purpose, &e.CreatedBy, &created, &expires, &used)
	if err != nil {
		return EnrolmentToken{}, mapErr(op, err)
	}
	e.Purpose, e.CreatedAt, e.ExpiresAt, e.UsedAt = EnrolPurpose(purpose), fromMS(created), fromMS(expires), fromNullMS(used)
	return e, nil
}
