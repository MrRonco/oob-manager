package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type tokenRepo struct{ db querier }

const tokenColumns = `id, name, token_hash, scope, created_by, created_at, last_used_at, revoked_at, expires_at` //nolint:gosec // G101: SQL column list, not a credential

func (r tokenRepo) Create(ctx context.Context, t APIToken) error {
	const op = "create token"
	if t.ID == "" || t.Name == "" || len(t.TokenHash) == 0 || t.CreatedBy == "" {
		return invalid(op, "id, name, token_hash and created_by are required")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO api_tokens (`+tokenColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.Name, t.TokenHash, string(t.Scope), t.CreatedBy, toMS(t.CreatedAt),
		nullMS(t.LastUsedAt), nullMS(t.RevokedAt), nullMS(t.ExpiresAt))
	return mapErr(op, err)
}

func (r tokenRepo) ByHash(ctx context.Context, hash []byte) (APIToken, error) {
	return scanToken("token by hash",
		r.db.QueryRowContext(ctx, `SELECT `+tokenColumns+` FROM api_tokens WHERE token_hash = ?`, hash))
}

func (r tokenRepo) List(ctx context.Context) ([]APIToken, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT `+tokenColumns+` FROM api_tokens ORDER BY created_at, id`)
	if err != nil {
		return nil, mapErr("list tokens", err)
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		t, err := scanToken("list tokens", rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, mapErr("list tokens", rows.Err())
}

func (r tokenRepo) Touch(ctx context.Context, id string, at time.Time) error {
	return execOne(ctx, r.db, "touch token", `UPDATE api_tokens SET last_used_at = ? WHERE id = ?`, toMS(at), id)
}

func (r tokenRepo) Revoke(ctx context.Context, id string, at time.Time) error {
	return execOne(ctx, r.db, "revoke token",
		`UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, toMS(at), id)
}

func scanToken(op string, row rowScanner) (APIToken, error) {
	var (
		t             APIToken
		scope         string
		created       int64
		used, revoked sql.NullInt64
		expires       sql.NullInt64
	)
	if err := row.Scan(&t.ID, &t.Name, &t.TokenHash, &scope, &t.CreatedBy, &created, &used, &revoked,
		&expires); err != nil {
		return APIToken{}, mapErr(op, err)
	}
	t.Scope, t.CreatedAt = TokenScope(scope), fromMS(created)
	t.LastUsedAt, t.RevokedAt, t.ExpiresAt = fromNullMS(used), fromNullMS(revoked), fromNullMS(expires)
	return t, nil
}

type capabilityRepo struct{ db querier }

func (r capabilityRepo) Put(ctx context.Context, c Capability) error {
	const op = "put capability"
	if c.ServerID == "" || !json.Valid([]byte(c.JSON)) {
		return invalid(op, "server_id and valid JSON are required")
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO capabilities (server_id, probed_at, json) VALUES (?, ?, ?)
		ON CONFLICT (server_id) DO UPDATE SET probed_at = excluded.probed_at, json = excluded.json`,
		c.ServerID, toMS(c.ProbedAt), c.JSON)
	return mapErr(op, err)
}

func (r capabilityRepo) Get(ctx context.Context, serverID string) (Capability, error) {
	var (
		c      Capability
		probed int64
	)
	err := r.db.QueryRowContext(ctx, `SELECT server_id, probed_at, json FROM capabilities WHERE server_id = ?`,
		serverID).Scan(&c.ServerID, &probed, &c.JSON)
	if err != nil {
		return Capability{}, mapErr("get capability", err)
	}
	c.ProbedAt = fromMS(probed)
	return c, nil
}
