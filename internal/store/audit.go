package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type auditRepo struct{ db querier }

const auditColumns = `seq, ts, correlation_id, principal, auth_method, role, src_ip, server_id, action,
	params_json, result, bmc_status, error_class, prev_hash, row_hash`

func (r auditRepo) Append(ctx context.Context, build AuditBuilder) (AuditRecord, error) {
	const op = "audit append"
	var rec AuditRecord
	err := inTx(ctx, r.db, op, func(q querier) error {
		last, ok, err := lastAudit(q.QueryRowContext(ctx, `SELECT `+auditColumns+` FROM audit_log ORDER BY seq DESC LIMIT 1`))
		if err != nil {
			return err
		}
		next, err := build(last, ok)
		if err != nil {
			return fmt.Errorf("store: %s: build: %w", op, err)
		}
		if err = checkLink(last, ok, next); err != nil {
			return err
		}
		if _, err = q.ExecContext(ctx, `INSERT INTO audit_log (`+auditColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, auditArgs(next)...); err != nil {
			return mapErr(op, err)
		}
		rec = next
		return nil
	})
	if err != nil {
		return AuditRecord{}, err
	}
	return rec, nil
}

func checkLink(last AuditRecord, ok bool, rec AuditRecord) error {
	want := int64(1)
	if ok {
		want = last.Seq + 1
	}
	if rec.Seq != want {
		return fmt.Errorf("store: audit append: %w: seq %d, want %d", ErrConflict, rec.Seq, want)
	}
	if ok && rec.PrevHash != last.RowHash {
		return fmt.Errorf("store: audit append: %w: prev_hash does not match head", ErrConflict)
	}
	if rec.RowHash == "" || rec.PrevHash == "" {
		return invalid("audit append", "prev_hash and row_hash are required")
	}
	return nil
}

func (r auditRepo) Last(ctx context.Context) (AuditRecord, bool, error) {
	return lastAudit(r.db.QueryRowContext(ctx, `SELECT `+auditColumns+` FROM audit_log ORDER BY seq DESC LIMIT 1`))
}

func lastAudit(row *sql.Row) (AuditRecord, bool, error) {
	rec, err := scanAudit("audit last", row)
	if errors.Is(err, ErrNotFound) {
		return AuditRecord{}, false, nil
	}
	if err != nil {
		return AuditRecord{}, false, err
	}
	return rec, true, nil
}

func (r auditRepo) List(ctx context.Context, afterSeq int64, limit int) ([]AuditRecord, error) {
	const op = "audit list"
	if limit < 1 || limit > MaxAuditPage {
		return nil, invalid(op, fmt.Sprintf("limit must be in [1, %d]", MaxAuditPage))
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+auditColumns+` FROM audit_log WHERE seq > ? ORDER BY seq LIMIT ?`,
		afterSeq, limit)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	out := make([]AuditRecord, 0, limit)
	for rows.Next() {
		rec, err := scanAudit(op, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, mapErr(op, rows.Err())
}

func auditArgs(r AuditRecord) []any {
	return []any{r.Seq, toMS(r.TS), r.CorrelationID, r.Principal, r.AuthMethod, r.Role, r.SrcIP, r.ServerID,
		r.Action, r.ParamsJSON, r.Result, r.BMCStatus, r.ErrorClass, r.PrevHash, r.RowHash}
}

func scanAudit(op string, row rowScanner) (AuditRecord, error) {
	var (
		r  AuditRecord
		ts int64
	)
	err := row.Scan(&r.Seq, &ts, &r.CorrelationID, &r.Principal, &r.AuthMethod, &r.Role, &r.SrcIP, &r.ServerID,
		&r.Action, &r.ParamsJSON, &r.Result, &r.BMCStatus, &r.ErrorClass, &r.PrevHash, &r.RowHash)
	if err != nil {
		return AuditRecord{}, mapErr(op, err)
	}
	r.TS = fromMS(ts)
	return r, nil
}
