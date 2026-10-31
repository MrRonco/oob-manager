package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// Results of a BMC restart row (bmc_resets.result).
const (
	BMCResetSent     = "sent"     // the POST was sent; the restart window is open
	BMCResetRefused  = "refused"  // the BMC answered the POST with an error
	BMCResetVerified = "verified" // the BMC answered a poll again after the reset
	BMCResetTimeout  = "timeout"  // it did not by the deadline (or the window ended otherwise)
)

// Details of a verified row: the BMC did not report a newer LastResetTime; or the POST
// got no answer and nothing else confirms the restart.
const (
	BMCResetUnchanged   = "last_reset_time_unchanged"
	BMCResetUnconfirmed = "restart_unconfirmed"
)

// BMCResetRow is one Manager.Reset the app sent (bmc_resets). Zero BackAt: not back.
type BMCResetRow struct {
	ID            int64
	ServerID      string
	CorrelationID string
	RequestedAt   time.Time
	SentAt        time.Time
	RequestedBy   string
	ResetType     string
	Result        string
	BackAt        time.Time
	DeadlineAt    time.Time
	ErrorClass    string
	Unconfirmed   bool
	Detail        string
}

// BMCResetRepository stores BMC restarts (docs/tech_doc.md §37).
type BMCResetRepository interface {
	// Insert adds a row and returns its id.
	Insert(ctx context.Context, r BMCResetRow) (int64, error)
	// MarkUnconfirmed records that an open row's POST got no answer; ErrNotFound when the
	// row is not open.
	MarkUnconfirmed(ctx context.Context, id int64) error
	// Finish closes an open (sent) row with a final result; ErrConflict when the row is
	// not open (already finished, or unknown), so the first outcome wins.
	Finish(ctx context.Context, id int64, result string, backAt time.Time, class, detail string) error
	// Open returns every row still marked sent, oldest first.
	Open(ctx context.Context) ([]BMCResetRow, error)
	// Latest returns the newest row of every server, ordered by server.
	Latest(ctx context.Context) ([]BMCResetRow, error)
	// LastVerified returns the newest confirmed restart of every server (verified with an
	// empty detail), ordered by server.
	LastVerified(ctx context.Context) ([]BMCResetRow, error)
	// Prune deletes rows requested before the cutoff.
	Prune(ctx context.Context, before time.Time) (int64, error)
}

// BMCResets returns the BMC restart repository.
func (d *DB) BMCResets() BMCResetRepository { return bmcResetRepo{d.sql} }

type bmcResetRepo struct{ db querier }

const bmcResetCols = `id, server_id, correlation_id, requested_at, sent_at, requested_by, reset_type, result,
	back_at, deadline_at, error_class, unconfirmed, detail`

func (r bmcResetRepo) Insert(ctx context.Context, x BMCResetRow) (int64, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO bmc_resets (server_id, correlation_id, requested_at, sent_at,
		requested_by, reset_type, result, back_at, deadline_at, error_class, unconfirmed, detail)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		x.ServerID, x.CorrelationID, toMS(x.RequestedAt), toMS(x.SentAt), x.RequestedBy, x.ResetType, x.Result,
		nullMS(x.BackAt), toMS(x.DeadlineAt), x.ErrorClass, boolInt(x.Unconfirmed), x.Detail)
	if err != nil {
		return 0, mapErr("insert bmc reset", err)
	}
	id, err := res.LastInsertId()
	return id, mapErr("insert bmc reset", err)
}

func (r bmcResetRepo) MarkUnconfirmed(ctx context.Context, id int64) error {
	return execOne(ctx, r.db, "mark bmc reset unconfirmed",
		`UPDATE bmc_resets SET unconfirmed = 1 WHERE id = ? AND result = 'sent'`, id)
}

func (r bmcResetRepo) Finish(ctx context.Context, id int64, result string, backAt time.Time, class, detail string) error {
	const op = "finish bmc reset"
	if result == BMCResetSent {
		return invalid(op, "a final result is required")
	}
	n, err := execCount(ctx, r.db, op, `UPDATE bmc_resets SET result = ?, back_at = ?, error_class = ?, detail = ?
		WHERE id = ? AND result = 'sent'`, result, nullMS(backAt), class, detail, id)
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("store: %s: %w: the row is not open", op, ErrConflict)
	}
	return nil
}

func (r bmcResetRepo) Open(ctx context.Context) ([]BMCResetRow, error) {
	return r.query(ctx, "open bmc resets", `SELECT `+bmcResetCols+` FROM bmc_resets WHERE result = 'sent' ORDER BY id`)
}

func (r bmcResetRepo) Latest(ctx context.Context) ([]BMCResetRow, error) {
	return r.query(ctx, "latest bmc resets", `SELECT `+bmcResetCols+` FROM bmc_resets b
		WHERE id = (SELECT max(id) FROM bmc_resets WHERE server_id = b.server_id) ORDER BY server_id`)
}

func (r bmcResetRepo) LastVerified(ctx context.Context) ([]BMCResetRow, error) {
	return r.query(ctx, "verified bmc resets", `SELECT `+bmcResetCols+` FROM bmc_resets b
		WHERE id = (SELECT max(id) FROM bmc_resets WHERE server_id = b.server_id AND result = 'verified' AND detail = '')
		ORDER BY server_id`)
}

func (r bmcResetRepo) Prune(ctx context.Context, before time.Time) (int64, error) {
	return execCount(ctx, r.db, "prune bmc resets", `DELETE FROM bmc_resets WHERE requested_at < ?`, toMS(before))
}

func (r bmcResetRepo) query(ctx context.Context, op, q string) ([]BMCResetRow, error) {
	rows, err := r.db.QueryContext(ctx, q)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []BMCResetRow
	for rows.Next() {
		var x BMCResetRow
		var req, sent, deadline, unconfirmed int64
		var back sql.NullInt64
		if err := rows.Scan(&x.ID, &x.ServerID, &x.CorrelationID, &req, &sent, &x.RequestedBy, &x.ResetType, &x.Result,
			&back, &deadline, &x.ErrorClass, &unconfirmed, &x.Detail); err != nil {
			return nil, mapErr(op, err)
		}
		x.RequestedAt, x.SentAt, x.DeadlineAt, x.Unconfirmed = fromMS(req), fromMS(sent), fromMS(deadline), unconfirmed == 1
		if back.Valid {
			x.BackAt = fromMS(back.Int64)
		}
		out = append(out, x)
	}
	return out, mapErr(op, rows.Err())
}
