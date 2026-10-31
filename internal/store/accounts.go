package store

import (
	"context"
	"fmt"
)

type accountRepo struct{ db querier }

// otherEnabledAdmin is true when an enabled admin other than ?1 exists.
const otherEnabledAdmin = `EXISTS (SELECT 1 FROM users o WHERE o.role = 'admin' AND o.disabled = 0 AND o.id <> ?1)`

// SetRoleGuarded: ?1 target, ?2 actor, ?3 role. A demotion of an admin needs the target
// to be someone else and another enabled admin to remain.
func (r accountRepo) SetRoleGuarded(ctx context.Context, actorID, id string, role Role) error {
	const op = "set role"
	if !role.Valid() {
		return invalid(op, "unknown role")
	}
	return r.guarded(ctx, op, id, `UPDATE users SET role = ?3 WHERE id = ?1 AND (?3 = 'admin' OR role <> 'admin'
		OR (id <> ?2 AND `+otherEnabledAdmin+`))`, id, actorID, string(role))
}

// SetDisabledGuarded: disabling needs the target to be someone else and, for an admin,
// another enabled admin to remain. Enabling is never refused.
func (r accountRepo) SetDisabledGuarded(ctx context.Context, actorID, id string, disabled bool) error {
	const op = "set disabled"
	if !disabled {
		return r.guarded(ctx, op, id, `UPDATE users SET disabled = 0 WHERE id = ?1`, id)
	}
	return r.guarded(ctx, op, id, `UPDATE users SET disabled = 1 WHERE id = ?1 AND id <> ?2
		AND (role <> 'admin' OR `+otherEnabledAdmin+`)`, id, actorID)
}

func (r accountRepo) ClearTOTP(ctx context.Context, actorID, id string) error {
	return r.guarded(ctx, "clear totp", id, `UPDATE users SET totp_secret_enc = NULL, totp_confirmed = 0,
		totp_last_step = 0 WHERE id = ?1 AND id <> ?2`, id, actorID)
}

func (r accountRepo) EnabledAdmins(ctx context.Context) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND disabled = 0`).Scan(&n)
	return n, mapErr("count admins", err)
}

// guarded runs a conditional UPDATE. When it changes nothing, the user either does not
// exist (ErrNotFound) or the guard refused (ErrRefused).
func (r accountRepo) guarded(ctx context.Context, op, id, q string, args ...any) error {
	n, err := execCount(ctx, r.db, op, q, args...)
	if err != nil || n == 1 {
		return err
	}
	var exists int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM users WHERE id = ?`, id).Scan(&exists); err != nil {
		return mapErr(op, err)
	}
	if exists == 0 {
		return fmt.Errorf("store: %s: %w", op, ErrNotFound)
	}
	return fmt.Errorf("store: %s: %w", op, ErrRefused)
}
