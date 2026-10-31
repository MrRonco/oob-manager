package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type lockoutRepo struct{ db querier }

func (r lockoutRepo) Get(ctx context.Context, key string) (LockoutState, error) {
	var (
		st   LockoutState
		last int64
	)
	err := r.db.QueryRowContext(ctx, `SELECT failures, last_failure FROM login_failures WHERE key = ?`, key).
		Scan(&st.Failures, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return LockoutState{}, nil
	}
	if err != nil {
		return LockoutState{}, mapErr("get lockout", err)
	}
	st.LastFailure = fromMS(last)
	return st, nil
}

// RecordFailure is one UPSERT ... RETURNING statement: increment and read-back are atomic.
func (r lockoutRepo) RecordFailure(ctx context.Context, key string, at time.Time) (LockoutState, error) {
	const op = "record login failure"
	if key == "" {
		return LockoutState{}, invalid(op, "key is required")
	}
	var (
		st   LockoutState
		last int64
	)
	err := r.db.QueryRowContext(ctx, `INSERT INTO login_failures (key, failures, last_failure) VALUES (?, 1, ?)
		ON CONFLICT (key) DO UPDATE SET failures = failures + 1, last_failure = excluded.last_failure
		RETURNING failures, last_failure`, key, toMS(at)).Scan(&st.Failures, &last)
	if err != nil {
		return LockoutState{}, mapErr(op, err)
	}
	st.LastFailure = fromMS(last)
	return st, nil
}

func (r lockoutRepo) Reset(ctx context.Context, key string) error {
	_, err := execCount(ctx, r.db, "reset lockout", `DELETE FROM login_failures WHERE key = ?`, key)
	return err
}

func (r lockoutRepo) Prune(ctx context.Context, before time.Time) (int64, error) {
	return execCount(ctx, r.db, "prune lockouts", `DELETE FROM login_failures WHERE last_failure < ?`, toMS(before))
}
