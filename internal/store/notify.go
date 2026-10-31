package store

import (
	"context"
	"time"
)

// NotifyTargetRow is one notification target saved from the browser (notify_targets).
// SecretEnc is opaque here: internal/notify seals and opens it.
type NotifyTargetRow struct {
	ID            string
	Name          string
	Kind          string
	URL           string
	Enabled       bool
	OptionsJSON   string
	SubsJSON      string
	SecretVersion int
	SecretEnc     []byte
	CreatedAt     time.Time
	UpdatedAt     time.Time
	UpdatedBy     string
}

// NotifyRepository stores notification targets. (Per-server mutes became maintenance
// windows in 0009, see MaintRepository.)
type NotifyRepository interface {
	// Targets returns every saved target, ordered by id.
	Targets(ctx context.Context) ([]NotifyTargetRow, error)
	// PutTarget inserts or replaces a target (created_at is kept on replace).
	PutTarget(ctx context.Context, row NotifyTargetRow) error
	// DeleteTarget removes a target; ErrNotFound when there is none.
	DeleteTarget(ctx context.Context, id string) error
}

// Notify returns the notifications repository.
func (d *DB) Notify() NotifyRepository { return notifyRepo{d.sql} }

// Notify returns the notifications repository inside the transaction.
func (t *Tx) Notify() NotifyRepository { return notifyRepo{t.tx} }

type notifyRepo struct{ db querier }

func (r notifyRepo) Targets(ctx context.Context) ([]NotifyTargetRow, error) {
	const op = "notify targets"
	rows, err := r.db.QueryContext(ctx, `SELECT id, name, kind, url, enabled, options_json, subs_json,
		secret_version, secret_enc, created_at, updated_at, updated_by FROM notify_targets ORDER BY id`)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []NotifyTargetRow
	for rows.Next() {
		var row NotifyTargetRow
		var enabled int
		var created, updated int64
		if err := rows.Scan(&row.ID, &row.Name, &row.Kind, &row.URL, &enabled, &row.OptionsJSON, &row.SubsJSON,
			&row.SecretVersion, &row.SecretEnc, &created, &updated, &row.UpdatedBy); err != nil {
			return nil, mapErr(op, err)
		}
		row.Enabled, row.CreatedAt, row.UpdatedAt = enabled == 1, fromMS(created), fromMS(updated)
		out = append(out, row)
	}
	return out, mapErr(op, rows.Err())
}

func (r notifyRepo) PutTarget(ctx context.Context, row NotifyTargetRow) error {
	enabled := 0
	if row.Enabled {
		enabled = 1
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO notify_targets (id, name, kind, url, enabled, options_json,
		subs_json, secret_version, secret_enc, created_at, updated_at, updated_by)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET name = excluded.name, kind = excluded.kind, url = excluded.url,
		enabled = excluded.enabled, options_json = excluded.options_json, subs_json = excluded.subs_json,
		secret_version = excluded.secret_version, secret_enc = excluded.secret_enc,
		updated_at = excluded.updated_at, updated_by = excluded.updated_by`,
		row.ID, row.Name, row.Kind, row.URL, enabled, row.OptionsJSON, row.SubsJSON, row.SecretVersion, row.SecretEnc,
		toMS(row.CreatedAt), toMS(row.UpdatedAt), row.UpdatedBy)
	return mapErr("put notify target", err)
}

func (r notifyRepo) DeleteTarget(ctx context.Context, id string) error {
	return execOne(ctx, r.db, "delete notify target", `DELETE FROM notify_targets WHERE id = ?`, id)
}
