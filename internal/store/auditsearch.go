package store

import (
	"context"
	"fmt"
	"strings"
)

// MaxAuditFilterActions bounds AuditFilter.Actions (each is one bound parameter).
const MaxAuditFilterActions = 32

// MaxAuditFilterMatches bounds AuditFilter.Matches (each is two bound parameters).
const MaxAuditFilterMatches = 32

// Search builds its WHERE clause from fixed fragments only; every value is a bound
// parameter, never interpolated.
func (r auditRepo) Search(ctx context.Context, f AuditFilter) ([]AuditRecord, error) {
	const op = "audit search"
	if f.Limit < 1 || f.Limit > MaxAuditPage {
		return nil, invalid(op, fmt.Sprintf("limit must be in [1, %d]", MaxAuditPage))
	}
	where, args := `WHERE 1 = 1`, []any{}
	add := func(frag string, v any) {
		where += ` AND ` + frag
		args = append(args, v)
	}
	if f.BeforeSeq > 0 {
		add(`seq < ?`, f.BeforeSeq)
	}
	for _, c := range []struct{ col, val string }{{"action", f.Action}, {"principal", f.Principal},
		{"server_id", f.ServerID}, {"result", f.Result}} {
		if c.val != "" {
			add(c.col+` = ?`, c.val)
		}
	}
	frag, list, err := listFilters(op, f)
	if err != nil {
		return nil, err
	}
	where, args = where+frag, append(args, list...)
	if !f.Since.IsZero() {
		add(`ts >= ?`, toMS(f.Since))
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+auditColumns+` FROM audit_log `+where+
		` ORDER BY seq DESC LIMIT ?`, append(args, f.Limit)...)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	out := make([]AuditRecord, 0, f.Limit)
	for rows.Next() {
		rec, err := scanAudit(op, rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, mapErr(op, rows.Err())
}

// listFilters is the WHERE part of the filter's lists (Actions, Matches): fixed
// fragments, every value a bound parameter.
func listFilters(op string, f AuditFilter) (string, []any, error) {
	switch {
	case len(f.Actions) > MaxAuditFilterActions:
		return "", nil, invalid(op, fmt.Sprintf("at most %d actions", MaxAuditFilterActions))
	case len(f.Matches) > MaxAuditFilterMatches:
		return "", nil, invalid(op, fmt.Sprintf("at most %d action and result pairs", MaxAuditFilterMatches))
	}
	where, args := "", []any{}
	if len(f.Actions) > 0 {
		where += ` AND action IN (?` + strings.Repeat(`, ?`, len(f.Actions)-1) + `)`
		for _, a := range f.Actions {
			args = append(args, a)
		}
	}
	if len(f.Matches) > 0 {
		where += ` AND ((action = ? AND result = ?)` + strings.Repeat(` OR (action = ? AND result = ?)`, len(f.Matches)-1) + `)`
		for _, m := range f.Matches {
			args = append(args, m.Action, m.Result)
		}
	}
	return where, args, nil
}

// maxAuditActions bounds the filter list (actions are a closed set in code).
const maxAuditActions = 500

func (r auditRepo) Actions(ctx context.Context) ([]string, error) {
	const op = "audit actions"
	rows, err := r.db.QueryContext(ctx, `SELECT DISTINCT action FROM audit_log ORDER BY action LIMIT ?`, maxAuditActions)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, mapErr(op, err)
		}
		out = append(out, a)
	}
	return out, mapErr(op, rows.Err())
}
