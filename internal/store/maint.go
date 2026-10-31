package store

import (
	"context"
	"database/sql"
	"time"
)

// MaintenanceRow is one server's maintenance window (server_maintenance). A zero EndsAt
// means "until ended".
type MaintenanceRow struct {
	ServerID        string
	StartsAt        time.Time
	EndsAt          time.Time
	Reason          string
	CreatedBy       string
	CreatedAt       time.Time
	StartedNotified bool
	// RemindedAt is when the last open-ended reminder went out (zero: none). PutWindow
	// clears it; MarkReminded sets it.
	RemindedAt time.Time
}

// NoteRow is one plain-text note on a server (server_notes).
type NoteRow struct {
	ID        int64
	ServerID  string
	Body      string
	Pinned    bool
	AuthorID  string
	Author    string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// AckRow acknowledges one BMC log entry (event_acks). CreatedMS is the entry's BMC
// timestamp in unix milliseconds (0 when the BMC sent none).
type AckRow struct {
	ServerID  string
	Log       string
	EntryID   string
	CreatedMS int64
	Comment   string
	AckedBy   string
	AckedAt   time.Time
}

// MaintRepository stores maintenance windows, notes and acknowledgements.
type MaintRepository interface {
	// Windows returns every maintenance row, ordered by server.
	Windows(ctx context.Context) ([]MaintenanceRow, error)
	// PutWindow inserts or replaces a server's window.
	PutWindow(ctx context.Context, w MaintenanceRow) error
	// MarkStarted records that the "started" notification of a window went out.
	MarkStarted(ctx context.Context, serverID string) error
	// MarkReminded records that an open-ended window's reminder went out at at.
	MarkReminded(ctx context.Context, serverID string, at time.Time) error
	// DeleteWindow removes a server's window; ErrNotFound when there is none.
	DeleteWindow(ctx context.Context, serverID string) error

	// Notes returns every note, ordered by server, then newest first.
	Notes(ctx context.Context) ([]NoteRow, error)
	// AddNote inserts a note and returns its id.
	AddNote(ctx context.Context, n NoteRow) (int64, error)
	// UpdateNote replaces a note's body; ErrNotFound when there is none.
	UpdateNote(ctx context.Context, id int64, body string, at time.Time) error
	// DeleteNote removes a note; ErrNotFound when there is none.
	DeleteNote(ctx context.Context, id int64) error
	// SetPin pins note id of serverID (unpinning any other) or, with id 0, unpins all.
	SetPin(ctx context.Context, serverID string, id int64) error

	// Acks returns every acknowledgement, ordered by server and time.
	Acks(ctx context.Context) ([]AckRow, error)
	// PutAck inserts or replaces an acknowledgement.
	PutAck(ctx context.Context, a AckRow) error
	// DeleteAck removes an acknowledgement; ErrNotFound when there is none.
	DeleteAck(ctx context.Context, serverID, log, entryID string, createdMS int64) error
	// PruneAcks deletes acknowledgements made before cutoff and returns how many.
	PruneAcks(ctx context.Context, cutoff time.Time) (int64, error)
}

// Maint returns the maintenance repository.
func (d *DB) Maint() MaintRepository { return maintRepo{d.sql} }

// Maint returns the maintenance repository inside the transaction.
func (t *Tx) Maint() MaintRepository { return maintRepo{t.tx} }

type maintRepo struct{ db querier }

func (r maintRepo) Windows(ctx context.Context) ([]MaintenanceRow, error) {
	const op = "maintenance windows"
	rows, err := r.db.QueryContext(ctx, `SELECT server_id, starts_at, ends_at, reason, created_by, created_at,
		started_notified, reminded_at FROM server_maintenance ORDER BY server_id`)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []MaintenanceRow
	for rows.Next() {
		var w MaintenanceRow
		var starts, created int64
		var ends, reminded sql.NullInt64
		var notified int
		if err := rows.Scan(&w.ServerID, &starts, &ends, &w.Reason, &w.CreatedBy, &created, &notified, &reminded); err != nil {
			return nil, mapErr(op, err)
		}
		w.StartsAt, w.CreatedAt, w.StartedNotified = fromMS(starts), fromMS(created), notified == 1
		if ends.Valid {
			w.EndsAt = fromMS(ends.Int64)
		}
		if reminded.Valid {
			w.RemindedAt = fromMS(reminded.Int64)
		}
		out = append(out, w)
	}
	return out, mapErr(op, rows.Err())
}

func (r maintRepo) PutWindow(ctx context.Context, w MaintenanceRow) error {
	var ends any
	if !w.EndsAt.IsZero() {
		ends = toMS(w.EndsAt)
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO server_maintenance (server_id, starts_at, ends_at, reason,
		created_by, created_at, started_notified) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (server_id) DO UPDATE SET starts_at = excluded.starts_at, ends_at = excluded.ends_at,
		reason = excluded.reason, created_by = excluded.created_by, created_at = excluded.created_at,
		started_notified = excluded.started_notified, reminded_at = NULL`,
		w.ServerID, toMS(w.StartsAt), ends, w.Reason, w.CreatedBy, toMS(w.CreatedAt), boolInt(w.StartedNotified))
	return mapErr("put maintenance window", err)
}

func (r maintRepo) MarkStarted(ctx context.Context, serverID string) error {
	return execOne(ctx, r.db, "mark maintenance started",
		`UPDATE server_maintenance SET started_notified = 1 WHERE server_id = ?`, serverID)
}

func (r maintRepo) MarkReminded(ctx context.Context, serverID string, at time.Time) error {
	return execOne(ctx, r.db, "mark maintenance reminded",
		`UPDATE server_maintenance SET reminded_at = ? WHERE server_id = ?`, toMS(at), serverID)
}

func (r maintRepo) DeleteWindow(ctx context.Context, serverID string) error {
	return execOne(ctx, r.db, "delete maintenance window", `DELETE FROM server_maintenance WHERE server_id = ?`, serverID)
}

func (r maintRepo) Notes(ctx context.Context) ([]NoteRow, error) {
	const op = "server notes"
	rows, err := r.db.QueryContext(ctx, `SELECT id, server_id, body, pinned, author_id, author, created_at, updated_at
		FROM server_notes ORDER BY server_id, created_at DESC, id DESC`)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []NoteRow
	for rows.Next() {
		var n NoteRow
		var pinned int
		var created, updated int64
		if err := rows.Scan(&n.ID, &n.ServerID, &n.Body, &pinned, &n.AuthorID, &n.Author, &created, &updated); err != nil {
			return nil, mapErr(op, err)
		}
		n.Pinned, n.CreatedAt, n.UpdatedAt = pinned == 1, fromMS(created), fromMS(updated)
		out = append(out, n)
	}
	return out, mapErr(op, rows.Err())
}

func (r maintRepo) AddNote(ctx context.Context, n NoteRow) (int64, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO server_notes (server_id, body, pinned, author_id, author,
		created_at, updated_at) VALUES (?, ?, 0, ?, ?, ?, ?)`,
		n.ServerID, n.Body, n.AuthorID, n.Author, toMS(n.CreatedAt), toMS(n.UpdatedAt))
	if err != nil {
		return 0, mapErr("add note", err)
	}
	id, err := res.LastInsertId()
	return id, mapErr("add note", err)
}

func (r maintRepo) UpdateNote(ctx context.Context, id int64, body string, at time.Time) error {
	return execOne(ctx, r.db, "update note", `UPDATE server_notes SET body = ?, updated_at = ? WHERE id = ?`,
		body, toMS(at), id)
}

func (r maintRepo) DeleteNote(ctx context.Context, id int64) error {
	return execOne(ctx, r.db, "delete note", `DELETE FROM server_notes WHERE id = ?`, id)
}

func (r maintRepo) SetPin(ctx context.Context, serverID string, id int64) error {
	return inTx(ctx, r.db, "pin note", func(q querier) error {
		if _, err := q.ExecContext(ctx, `UPDATE server_notes SET pinned = 0 WHERE server_id = ? AND pinned = 1`,
			serverID); err != nil {
			return mapErr("pin note", err)
		}
		if id == 0 {
			return nil
		}
		return execOne(ctx, q, "pin note", `UPDATE server_notes SET pinned = 1 WHERE id = ? AND server_id = ?`,
			id, serverID)
	})
}

func (r maintRepo) Acks(ctx context.Context) ([]AckRow, error) {
	const op = "event acks"
	rows, err := r.db.QueryContext(ctx, `SELECT server_id, log, entry_id, created_ms, comment, acked_by, acked_at
		FROM event_acks ORDER BY server_id, acked_at`)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []AckRow
	for rows.Next() {
		var a AckRow
		var at int64
		if err := rows.Scan(&a.ServerID, &a.Log, &a.EntryID, &a.CreatedMS, &a.Comment, &a.AckedBy, &at); err != nil {
			return nil, mapErr(op, err)
		}
		a.AckedAt = fromMS(at)
		out = append(out, a)
	}
	return out, mapErr(op, rows.Err())
}

func (r maintRepo) PutAck(ctx context.Context, a AckRow) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO event_acks (server_id, log, entry_id, created_ms, comment,
		acked_by, acked_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (server_id, log, entry_id, created_ms) DO UPDATE SET comment = excluded.comment,
		acked_by = excluded.acked_by, acked_at = excluded.acked_at`,
		a.ServerID, a.Log, a.EntryID, a.CreatedMS, a.Comment, a.AckedBy, toMS(a.AckedAt))
	return mapErr("put ack", err)
}

func (r maintRepo) DeleteAck(ctx context.Context, serverID, log, entryID string, createdMS int64) error {
	return execOne(ctx, r.db, "delete ack", `DELETE FROM event_acks WHERE server_id = ? AND log = ? AND entry_id = ?
		AND created_ms = ?`, serverID, log, entryID, createdMS)
}

func (r maintRepo) PruneAcks(ctx context.Context, cutoff time.Time) (int64, error) {
	return execCount(ctx, r.db, "prune acks", `DELETE FROM event_acks WHERE acked_at < ?`, toMS(cutoff))
}
