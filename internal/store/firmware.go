package store

import (
	"context"
	"database/sql"
	"time"
)

// FirmwareComponentRow is one stored firmware component (firmware_components).
type FirmwareComponentRow struct {
	ServerID, ComponentID, FQDD string
	Kind, Name                  string
	Named                       bool
	Running, Previous, Staged   string
	Stored                      string    // the image the BMC holds when it differs from Running
	ReleaseDate                 time.Time // zero: not reported
	Updateable                  bool
	Identity                    string
	FirstSeen, LastSeen         time.Time
	DocReadAt                   time.Time // zero: never read
}

// FirmwareChangeRow is one version change between scans (firmware_changes).
type FirmwareChangeRow struct {
	ID                          int64
	ServerID, ComponentID, FQDD string
	Name, Field, Before, After  string
	SeenAt                      time.Time
}

// FirmwareScanRow is a server's last scan (firmware_scans).
type FirmwareScanRow struct {
	ServerID             string
	ScannedAt            time.Time
	Listed, Components   int
	Complete             bool
	DocsRead, DocsFailed int
	Model                string // the system model when the scan ran ("" unknown)
	SystemID             string // the vendor system ID ("088F"; "" unknown), plan 08 §8.1
}

// FirmwareRepository stores the firmware view (docs/tech_doc.md §38).
type FirmwareRepository interface {
	// Components returns every stored component, ordered by server, component, FQDD.
	Components(ctx context.Context) ([]FirmwareComponentRow, error)
	// Scans returns every server's last scan, ordered by server.
	Scans(ctx context.Context) ([]FirmwareScanRow, error)
	// Changes returns a server's newest changes first, at most limit (1–1000).
	Changes(ctx context.Context, serverID string, limit int) ([]FirmwareChangeRow, error)
	// ReplaceServer stores a scan in one transaction: the server's components become
	// exactly comps, changes are appended and the scan row is replaced. Every row must
	// belong to scan.ServerID.
	ReplaceServer(ctx context.Context, scan FirmwareScanRow, comps []FirmwareComponentRow, changes []FirmwareChangeRow) error
	// DeleteServer removes every firmware row of a server (it left the registry).
	DeleteServer(ctx context.Context, serverID string) error
	// PruneChanges deletes changes seen before the cutoff.
	PruneChanges(ctx context.Context, before time.Time) (int64, error)
}

// Firmware returns the firmware repository.
func (d *DB) Firmware() FirmwareRepository { return firmwareRepo{d.sql} }

// Firmware returns the firmware repository bound to the transaction.
func (t *Tx) Firmware() FirmwareRepository { return firmwareRepo{t.tx} }

type firmwareRepo struct{ db querier }

const fwCompCols = `server_id, component_id, fqdd, kind, name, named, running, previous, staged, stored,
	release_date, updateable, identity, first_seen, last_seen, doc_read_at`

func (r firmwareRepo) Components(ctx context.Context) ([]FirmwareComponentRow, error) {
	const op = "firmware components"
	rows, err := r.db.QueryContext(ctx, `SELECT `+fwCompCols+` FROM firmware_components
		ORDER BY server_id, component_id, fqdd`)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []FirmwareComponentRow
	for rows.Next() {
		var c FirmwareComponentRow
		var named, upd int
		var rel, doc sql.NullInt64
		var first, last int64
		if err := rows.Scan(&c.ServerID, &c.ComponentID, &c.FQDD, &c.Kind, &c.Name, &named, &c.Running, &c.Previous,
			&c.Staged, &c.Stored, &rel, &upd, &c.Identity, &first, &last, &doc); err != nil {
			return nil, mapErr(op, err)
		}
		c.Named, c.Updateable = named == 1, upd == 1
		c.ReleaseDate, c.DocReadAt = fromNullMS(rel), fromNullMS(doc)
		c.FirstSeen, c.LastSeen = fromMS(first), fromMS(last)
		out = append(out, c)
	}
	return out, mapErr(op, rows.Err())
}

func (r firmwareRepo) Scans(ctx context.Context) ([]FirmwareScanRow, error) {
	const op = "firmware scans"
	rows, err := r.db.QueryContext(ctx, `SELECT server_id, scanned_at, listed, components, complete, docs_read, docs_failed,
		model, system_id FROM firmware_scans ORDER BY server_id`)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []FirmwareScanRow
	for rows.Next() {
		var s FirmwareScanRow
		var at int64
		var complete int
		if err := rows.Scan(&s.ServerID, &at, &s.Listed, &s.Components, &complete, &s.DocsRead, &s.DocsFailed, &s.Model,
			&s.SystemID); err != nil {
			return nil, mapErr(op, err)
		}
		s.ScannedAt, s.Complete = fromMS(at), complete == 1
		out = append(out, s)
	}
	return out, mapErr(op, rows.Err())
}

func (r firmwareRepo) Changes(ctx context.Context, serverID string, limit int) ([]FirmwareChangeRow, error) {
	const op = "firmware changes"
	if limit < 1 || limit > 1000 {
		return nil, invalid(op, "limit must be in [1, 1000]")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, server_id, component_id, fqdd, name, field, before, after, seen_at
		FROM firmware_changes WHERE server_id = ? ORDER BY seen_at DESC, id DESC LIMIT ?`, serverID, limit)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []FirmwareChangeRow
	for rows.Next() {
		var c FirmwareChangeRow
		var at int64
		if err := rows.Scan(&c.ID, &c.ServerID, &c.ComponentID, &c.FQDD, &c.Name, &c.Field, &c.Before, &c.After, &at); err != nil {
			return nil, mapErr(op, err)
		}
		c.SeenAt = fromMS(at)
		out = append(out, c)
	}
	return out, mapErr(op, rows.Err())
}

func (r firmwareRepo) ReplaceServer(ctx context.Context, scan FirmwareScanRow, comps []FirmwareComponentRow,
	changes []FirmwareChangeRow) error {
	const op = "replace firmware"
	for _, c := range comps {
		if c.ServerID != scan.ServerID {
			return invalid(op, "a component of another server")
		}
	}
	for _, c := range changes {
		if c.ServerID != scan.ServerID {
			return invalid(op, "a change of another server")
		}
	}
	return inTx(ctx, r.db, op, func(q querier) error {
		if _, err := q.ExecContext(ctx, `DELETE FROM firmware_components WHERE server_id = ?`, scan.ServerID); err != nil {
			return mapErr(op, err)
		}
		for _, c := range comps {
			if err := insertComponent(ctx, q, c); err != nil {
				return mapErr(op, err)
			}
		}
		for _, c := range changes {
			if _, err := q.ExecContext(ctx, `INSERT INTO firmware_changes (server_id, component_id, fqdd, name, field,
				before, after, seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, c.ServerID, c.ComponentID, c.FQDD, c.Name,
				c.Field, c.Before, c.After, toMS(c.SeenAt)); err != nil {
				return mapErr(op, err)
			}
		}
		_, err := q.ExecContext(ctx, `INSERT INTO firmware_scans (server_id, scanned_at, listed, components, complete,
			docs_read, docs_failed, model, system_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT (server_id) DO UPDATE SET scanned_at = excluded.scanned_at, listed = excluded.listed,
			components = excluded.components, complete = excluded.complete, docs_read = excluded.docs_read,
			docs_failed = excluded.docs_failed, model = excluded.model, system_id = excluded.system_id`, scan.ServerID,
			toMS(scan.ScannedAt), scan.Listed, scan.Components, boolInt(scan.Complete), scan.DocsRead, scan.DocsFailed,
			scan.Model, scan.SystemID)
		return mapErr(op, err)
	})
}

func insertComponent(ctx context.Context, q querier, c FirmwareComponentRow) error {
	_, err := q.ExecContext(ctx, `INSERT INTO firmware_components (`+fwCompCols+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ServerID, c.ComponentID, c.FQDD, c.Kind, c.Name, boolInt(c.Named), c.Running, c.Previous, c.Staged,
		c.Stored, nullMS(c.ReleaseDate), boolInt(c.Updateable), c.Identity, toMS(c.FirstSeen), toMS(c.LastSeen),
		nullMS(c.DocReadAt))
	return err
}

func (r firmwareRepo) DeleteServer(ctx context.Context, serverID string) error {
	const op = "delete firmware rows of a server"
	return inTx(ctx, r.db, op, func(q querier) error {
		for _, table := range []string{"firmware_components", "firmware_changes", "firmware_scans"} {
			if _, err := q.ExecContext(ctx, `DELETE FROM `+table+` WHERE server_id = ?`, serverID); err != nil {
				return mapErr(op, err)
			}
		}
		return nil
	})
}

func (r firmwareRepo) PruneChanges(ctx context.Context, before time.Time) (int64, error) {
	return execCount(ctx, r.db, "prune firmware changes", `DELETE FROM firmware_changes WHERE seen_at < ?`, toMS(before))
}
