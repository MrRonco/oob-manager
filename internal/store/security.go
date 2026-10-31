package store

import (
	"context"
	"time"
)

// SecurityAcceptRow is one finding an admin accepted as a risk (security_accepts). The
// acceptance binds to SubjectHash (SHA-256 hex of the whole subject) and to ServerAddr
// (the BMC address and port it was made for); Subject is a clipped copy for display.
type SecurityAcceptRow struct {
	ServerID    string
	ServerAddr  string
	CheckID     string
	Result      string // warn or fail
	Subject     string
	SubjectHash string
	Comment     string
	AcceptedBy  string
	AcceptedAt  time.Time
}

// SecurityNotifiedRow is one notification bookkeeping entry (security_notified).
type SecurityNotifiedRow struct {
	ServerID   string
	Item       string
	Value      string
	NotifiedAt time.Time
}

// SecurityRepository stores the BMC security checks' accepted risks and what their
// notifications already reported (docs/tech_doc.md §31).
type SecurityRepository interface {
	// Accepts returns every accepted risk, ordered by server and check.
	Accepts(ctx context.Context) ([]SecurityAcceptRow, error)
	// PutAccept inserts or replaces the acceptance of a server's check.
	PutAccept(ctx context.Context, a SecurityAcceptRow) error
	// DeleteAccept removes an acceptance; ErrNotFound when there is none.
	DeleteAccept(ctx context.Context, serverID, checkID string) error
	// DeleteServer removes every acceptance and bookkeeping row of a server (a server
	// that is being removed); nothing to remove is not an error.
	DeleteServer(ctx context.Context, serverID string) error
	// Notified returns every bookkeeping row, ordered by server and item.
	Notified(ctx context.Context) ([]SecurityNotifiedRow, error)
	// SetNotified replaces every row of serverID with rows (all of that server).
	SetNotified(ctx context.Context, serverID string, rows []SecurityNotifiedRow) error
}

// Security returns the security checks repository.
func (d *DB) Security() SecurityRepository { return securityRepo{d.sql} }

// Security returns the security checks repository inside the transaction.
func (t *Tx) Security() SecurityRepository { return securityRepo{t.tx} }

type securityRepo struct{ db querier }

const acceptCols = `server_id, server_addr, check_id, result, subject, subject_hash, comment, accepted_by, accepted_at`

func (r securityRepo) Accepts(ctx context.Context) ([]SecurityAcceptRow, error) {
	const op = "security accepts"
	rows, err := r.db.QueryContext(ctx, `SELECT `+acceptCols+` FROM security_accepts ORDER BY server_id, check_id`)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []SecurityAcceptRow
	for rows.Next() {
		var a SecurityAcceptRow
		var at int64
		if err := rows.Scan(&a.ServerID, &a.ServerAddr, &a.CheckID, &a.Result, &a.Subject, &a.SubjectHash, &a.Comment,
			&a.AcceptedBy, &at); err != nil {
			return nil, mapErr(op, err)
		}
		a.AcceptedAt = fromMS(at)
		out = append(out, a)
	}
	return out, mapErr(op, rows.Err())
}

func (r securityRepo) PutAccept(ctx context.Context, a SecurityAcceptRow) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO security_accepts (`+acceptCols+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (server_id, check_id) DO UPDATE SET server_addr = excluded.server_addr, result = excluded.result,
		subject = excluded.subject, subject_hash = excluded.subject_hash, comment = excluded.comment,
		accepted_by = excluded.accepted_by, accepted_at = excluded.accepted_at`,
		a.ServerID, a.ServerAddr, a.CheckID, a.Result, a.Subject, a.SubjectHash, a.Comment, a.AcceptedBy, toMS(a.AcceptedAt))
	return mapErr("put security accept", err)
}

func (r securityRepo) DeleteAccept(ctx context.Context, serverID, checkID string) error {
	return execOne(ctx, r.db, "delete security accept",
		`DELETE FROM security_accepts WHERE server_id = ? AND check_id = ?`, serverID, checkID)
}

func (r securityRepo) DeleteServer(ctx context.Context, serverID string) error {
	const op = "delete security rows of a server"
	return inTx(ctx, r.db, op, func(q querier) error {
		for _, table := range []string{"security_accepts", "security_notified"} {
			if _, err := q.ExecContext(ctx, `DELETE FROM `+table+` WHERE server_id = ?`, serverID); err != nil {
				return mapErr(op, err)
			}
		}
		return nil
	})
}

func (r securityRepo) Notified(ctx context.Context) ([]SecurityNotifiedRow, error) {
	const op = "security notified"
	rows, err := r.db.QueryContext(ctx, `SELECT server_id, item, value, notified_at FROM security_notified
		ORDER BY server_id, item`)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []SecurityNotifiedRow
	for rows.Next() {
		var n SecurityNotifiedRow
		var at int64
		if err := rows.Scan(&n.ServerID, &n.Item, &n.Value, &at); err != nil {
			return nil, mapErr(op, err)
		}
		n.NotifiedAt = fromMS(at)
		out = append(out, n)
	}
	return out, mapErr(op, rows.Err())
}

func (r securityRepo) SetNotified(ctx context.Context, serverID string, rows []SecurityNotifiedRow) error {
	const op = "set security notified"
	for _, n := range rows {
		if n.ServerID != serverID {
			return invalid(op, "a row of another server")
		}
	}
	return inTx(ctx, r.db, op, func(q querier) error {
		if _, err := q.ExecContext(ctx, `DELETE FROM security_notified WHERE server_id = ?`, serverID); err != nil {
			return mapErr(op, err)
		}
		for _, n := range rows {
			if _, err := q.ExecContext(ctx, `INSERT INTO security_notified (server_id, item, value, notified_at)
				VALUES (?, ?, ?, ?)`, n.ServerID, n.Item, n.Value, toMS(n.NotifiedAt)); err != nil {
				return mapErr(op, err)
			}
		}
		return nil
	})
}
