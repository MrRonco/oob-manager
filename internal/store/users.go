package store

import (
	"context"
	"fmt"
)

type userRepo struct{ db querier }

const userColumns = `id, username, COALESCE(email, ''), role, pw_hash, totp_secret_enc,
	totp_confirmed, totp_last_step, disabled, created_at`

const userInsert = `INSERT INTO users (id, username, email, role, pw_hash, totp_secret_enc,
	totp_confirmed, totp_last_step, disabled, created_at)`

func validateUser(op string, u User) error {
	switch {
	case u.ID == "" || u.Username == "" || u.PwHash == "":
		return invalid(op, "id, username and pw_hash are required")
	case !u.Role.Valid():
		return invalid(op, "unknown role")
	}
	return nil
}

func userArgs(u User) []any {
	return []any{u.ID, u.Username, nullString(u.Email), string(u.Role), u.PwHash, u.TOTPSecretEnc,
		boolInt(u.TOTPConfirmed), u.TOTPLastStep, boolInt(u.Disabled), toMS(u.CreatedAt)}
}

func (r userRepo) Create(ctx context.Context, u User) error {
	const op = "create user"
	if err := validateUser(op, u); err != nil {
		return err
	}
	_, err := r.db.ExecContext(ctx, userInsert+` VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, userArgs(u)...)
	return mapErr(op, err)
}

// CreateFirst is a single INSERT ... SELECT ... WHERE NOT EXISTS statement, so the
// emptiness check and the insert are one atomic step in SQLite.
func (r userRepo) CreateFirst(ctx context.Context, u User) error {
	const op = "create first user"
	if err := validateUser(op, u); err != nil {
		return err
	}
	n, err := execCount(ctx, r.db, op, userInsert+
		` SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM users)`, userArgs(u)...)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: %s: %w: users already exist", op, ErrConflict)
	}
	return nil
}

func (r userRepo) ByID(ctx context.Context, id string) (User, error) {
	return scanUser("user by id", r.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

func (r userRepo) ByUsername(ctx context.Context, username string) (User, error) {
	return scanUser("user by username",
		r.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE username = ?`, username))
}

func (r userRepo) List(ctx context.Context) ([]User, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+userColumns+` FROM users ORDER BY username`)
	if err != nil {
		return nil, mapErr("list users", err)
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser("list users", rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, mapErr("list users", rows.Err())
}

func (r userRepo) Count(ctx context.Context) (int, error) {
	var n int
	err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM users`).Scan(&n)
	return n, mapErr("count users", err)
}

func (r userRepo) SetPasswordHash(ctx context.Context, id, hash string) error {
	return execOne(ctx, r.db, "set password", `UPDATE users SET pw_hash = ? WHERE id = ?`, hash, id)
}

func (r userRepo) SetTOTPSecret(ctx context.Context, id string, enc []byte) error {
	return execOne(ctx, r.db, "set totp",
		`UPDATE users SET totp_secret_enc = ?, totp_last_step = 0, totp_confirmed = 0 WHERE id = ?`, enc, id)
}

func (r userRepo) SetTOTP(ctx context.Context, id string, enc []byte, confirmed bool) error {
	return execOne(ctx, r.db, "set totp",
		`UPDATE users SET totp_secret_enc = ?, totp_confirmed = ? WHERE id = ?`, enc, boolInt(confirmed), id)
}

func (r userRepo) AdvanceTOTPStep(ctx context.Context, id string, step int64) (bool, error) {
	n, err := execCount(ctx, r.db, "advance totp",
		`UPDATE users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, id, step)
	return n == 1, err
}

func (r userRepo) SetDisabled(ctx context.Context, id string, disabled bool) error {
	return execOne(ctx, r.db, "set disabled", `UPDATE users SET disabled = ? WHERE id = ?`, boolInt(disabled), id)
}

func (r userRepo) SetRole(ctx context.Context, id string, role Role) error {
	if !role.Valid() {
		return invalid("set role", "unknown role")
	}
	return execOne(ctx, r.db, "set role", `UPDATE users SET role = ? WHERE id = ?`, string(role), id)
}

type rowScanner interface{ Scan(dest ...any) error }

func scanUser(op string, row rowScanner) (User, error) {
	var (
		u                   User
		role                string
		confirmed, disabled int
		created             int64
	)
	err := row.Scan(&u.ID, &u.Username, &u.Email, &role, &u.PwHash, &u.TOTPSecretEnc,
		&confirmed, &u.TOTPLastStep, &disabled, &created)
	if err != nil {
		return User{}, mapErr(op, err)
	}
	u.Role, u.CreatedAt = Role(role), fromMS(created)
	u.TOTPConfirmed, u.Disabled = confirmed == 1, disabled == 1
	return u, nil
}
