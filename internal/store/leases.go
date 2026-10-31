package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

type leaseRepo struct{ db querier }

const leaseColumns = `lease_id, server_id, mode, pct, issued_at, expires_at, requested_by, state,
	original_value, updated_at`

func (r leaseRepo) Create(ctx context.Context, l FanLease) error {
	const op = "create lease"
	if l.LeaseID == "" || l.ServerID == "" || l.RequestedBy == "" {
		return invalid(op, "lease_id, server_id and requested_by are required")
	}
	var orig any
	if l.HasOriginal {
		orig = l.OriginalValue
	}
	_, err := r.db.ExecContext(ctx, `INSERT INTO fan_leases (`+leaseColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		l.LeaseID, l.ServerID, string(l.Mode), l.Pct, toMS(l.IssuedAt), toMS(l.ExpiresAt), l.RequestedBy,
		string(l.State), orig, toMS(l.UpdatedAt))
	return mapErr(op, err)
}

func (r leaseRepo) Get(ctx context.Context, leaseID string) (FanLease, error) {
	return scanLease("get lease", r.db.QueryRowContext(ctx,
		`SELECT `+leaseColumns+` FROM fan_leases WHERE lease_id = ?`, leaseID))
}

func (r leaseRepo) Active(ctx context.Context, serverID string) (FanLease, error) {
	return scanLease("active lease", r.db.QueryRowContext(ctx,
		`SELECT `+leaseColumns+` FROM fan_leases WHERE server_id = ? AND state IN ('pending', 'applied')`, serverID))
}

func (r leaseRepo) ListByStates(ctx context.Context, states ...LeaseState) ([]FanLease, error) {
	const op = "list leases by state"
	if len(states) == 0 {
		return nil, invalid(op, "at least one state is required")
	}
	args := make([]any, len(states))
	for i, s := range states {
		args[i] = string(s)
	}
	marks := strings.TrimSuffix(strings.Repeat("?, ", len(states)), ", ")
	return r.query(ctx, op, `SELECT `+leaseColumns+` FROM fan_leases WHERE state IN (`+marks+`)
		ORDER BY expires_at, lease_id`, args...)
}

func (r leaseRepo) ListByServer(ctx context.Context, serverID string, limit int) ([]FanLease, error) {
	return r.query(ctx, "list leases by server", `SELECT `+leaseColumns+` FROM fan_leases
		WHERE server_id = ? ORDER BY issued_at DESC, rowid DESC LIMIT ?`, serverID, limit)
}

func (r leaseRepo) Transition(ctx context.Context, leaseID string, from, to LeaseState, at time.Time) error {
	const op = "lease transition"
	if !from.Active() {
		return invalid(op, fmt.Sprintf("state %q is terminal", from))
	}
	if !to.Valid() {
		return invalid(op, fmt.Sprintf("unknown state %q", to))
	}
	err := execOne(ctx, r.db, op, `UPDATE fan_leases SET state = ?, updated_at = ? WHERE lease_id = ? AND state = ?`,
		string(to), toMS(at), leaseID, string(from))
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	if _, getErr := r.Get(ctx, leaseID); getErr != nil {
		return getErr
	}
	return fmt.Errorf("store: %s: %w: lease %s is not %s", op, ErrConflict, leaseID, from)
}

func (r leaseRepo) query(ctx context.Context, op, q string, args ...any) ([]FanLease, error) {
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []FanLease
	for rows.Next() {
		l, err := scanLease(op, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, mapErr(op, rows.Err())
}

func scanLease(op string, row rowScanner) (FanLease, error) {
	var (
		l                        FanLease
		mode, state              string
		issued, expires, updated int64
		orig                     sql.NullInt64
	)
	err := row.Scan(&l.LeaseID, &l.ServerID, &mode, &l.Pct, &issued, &expires, &l.RequestedBy, &state, &orig, &updated)
	if err != nil {
		return FanLease{}, mapErr(op, err)
	}
	l.Mode, l.State = LeaseMode(mode), LeaseState(state)
	l.IssuedAt, l.ExpiresAt, l.UpdatedAt = fromMS(issued), fromMS(expires), fromMS(updated)
	l.OriginalValue, l.HasOriginal = int(orig.Int64), orig.Valid
	return l, nil
}
