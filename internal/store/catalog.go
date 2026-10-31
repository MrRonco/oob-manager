package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// Catalog import states (catalog_imports.state).
const (
	CatalogActive   = "active"
	CatalogHeld     = "held"
	CatalogReplaced = "replaced"
)

// Retention of the catalog tables (plan 08 §9).
const (
	catalogImportsKept = 20
	catalogChecksKept  = 500
)

// CatalogImportRow is one verified, parsed catalog (catalog_imports).
type CatalogImportRow struct {
	ID                      int64
	Source, Origin, State   string
	Version, ReleaseID      string
	PublishedAt, ImportedAt time.Time
	SHA256, Signer          string // Signer "" = unsigned (accepted by configuration)
	ETag, LastModified      string
	Components, Kept        int
	ImportedBy              string
}

// CatalogCheckRow is one check (catalog_checks).
type CatalogCheckRow struct {
	ID             int64
	Source         string
	At             time.Time
	Result, Detail string
	ImportID       int64 // 0: none
}

// CatalogReleaseRow is one kept release (catalog_releases).
type CatalogReleaseRow struct {
	ImportID                                     int64
	SystemID, ComponentID                        string
	VendorID, DeviceID, SubVendorID, SubDeviceID string
	Version                                      string
	ReleasedAt                                   time.Time
	Criticality                                  int
	Name, PackagePath, DetailsURL                string
	RebootRequired                               bool
}

// CatalogModelRow is one catalog model name of a kept system (catalog_models).
type CatalogModelRow struct {
	ImportID        int64
	SystemID, Model string
}

// CatalogRepository stores vendor catalog imports and checks (plan 08 §9).
type CatalogRepository interface {
	// SaveImport stores an import and its releases in one transaction. State active
	// replaces the source's previous active and held imports; state held replaces only
	// a previous held one. Replaced imports keep their row (pruned to the newest 20) but
	// lose their releases.
	SaveImport(ctx context.Context, imp CatalogImportRow, rels []CatalogReleaseRow, models []CatalogModelRow) (int64, error)
	// ActivateHeld makes the source's held import with that ID active; false when it is
	// not (or no longer) the held one.
	ActivateHeld(ctx context.Context, source string, id int64) (bool, error)
	// ReplaceReleases replaces an import's releases and models (a local re-parse after
	// the fleet changed) and its kept count.
	ReplaceReleases(ctx context.Context, importID int64, rels []CatalogReleaseRow, models []CatalogModelRow) error
	// Import returns the source's import in a state (active or held); false when none.
	Import(ctx context.Context, source, state string) (CatalogImportRow, bool, error)
	// Imports returns the source's newest imports first, at most limit (1–100).
	Imports(ctx context.Context, source string, limit int) ([]CatalogImportRow, error)
	// Releases returns an import's releases ordered by system, component and version.
	Releases(ctx context.Context, importID int64) ([]CatalogReleaseRow, error)
	// Models returns an import's model names ordered by system and model.
	Models(ctx context.Context, importID int64) ([]CatalogModelRow, error)
	// AddCheck records a check and prunes checks older than 90 days or beyond 500.
	AddCheck(ctx context.Context, c CatalogCheckRow) error
	// Checks returns the source's newest checks first, at most limit (1–500).
	Checks(ctx context.Context, source string, limit int) ([]CatalogCheckRow, error)
}

// Catalog returns the catalog repository.
func (d *DB) Catalog() CatalogRepository { return catalogRepo{d.sql} }

// Catalog returns the catalog repository bound to the transaction.
func (t *Tx) Catalog() CatalogRepository { return catalogRepo{t.tx} }

type catalogRepo struct{ db querier }

const catImportCols = `id, source, origin, state, version, release_id, published_at, imported_at, sha256, signer,
	etag, last_modified, components, kept, imported_by`

func (r catalogRepo) SaveImport(ctx context.Context, imp CatalogImportRow, rels []CatalogReleaseRow,
	models []CatalogModelRow) (int64, error) {
	const op = "save catalog import"
	if imp.State != CatalogActive && imp.State != CatalogHeld {
		return 0, invalid(op, "state must be active or held")
	}
	var id int64
	err := inTx(ctx, r.db, op, func(q querier) error {
		replace := []string{CatalogHeld}
		if imp.State == CatalogActive {
			replace = append(replace, CatalogActive)
		}
		for _, st := range replace {
			if _, err := q.ExecContext(ctx, `UPDATE catalog_imports SET state = 'replaced' WHERE source = ? AND state = ?`,
				imp.Source, st); err != nil {
				return mapErr(op, err)
			}
		}
		res, err := q.ExecContext(ctx, `INSERT INTO catalog_imports (source, origin, state, version, release_id,
			published_at, imported_at, sha256, signer, etag, last_modified, components, kept, imported_by)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, imp.Source, imp.Origin, imp.State, imp.Version,
			imp.ReleaseID, nullMS(imp.PublishedAt), toMS(imp.ImportedAt), imp.SHA256, imp.Signer, imp.ETag,
			imp.LastModified, imp.Components, len(rels), imp.ImportedBy)
		if err != nil {
			return mapErr(op, err)
		}
		if id, err = res.LastInsertId(); err != nil {
			return mapErr(op, err)
		}
		if err := insertReleases(ctx, q, id, rels, models); err != nil {
			return mapErr(op, err)
		}
		return pruneImports(ctx, q, op, imp.Source)
	})
	return id, err
}

// pruneImports drops the releases and models of replaced imports and keeps the newest
// 20 rows.
func pruneImports(ctx context.Context, q querier, op, source string) error {
	for _, table := range []string{"catalog_releases", "catalog_models"} {
		if _, err := q.ExecContext(ctx, `DELETE FROM `+table+` WHERE import_id IN
			(SELECT id FROM catalog_imports WHERE source = ? AND state = 'replaced')`, source); err != nil {
			return mapErr(op, err)
		}
	}
	_, err := q.ExecContext(ctx, `DELETE FROM catalog_imports WHERE source = ? AND state = 'replaced' AND id NOT IN
		(SELECT id FROM catalog_imports WHERE source = ? ORDER BY id DESC LIMIT ?)`, source, source, catalogImportsKept)
	return mapErr(op, err)
}

func insertReleases(ctx context.Context, q querier, importID int64, rels []CatalogReleaseRow, models []CatalogModelRow) error {
	for _, m := range models {
		if _, err := q.ExecContext(ctx, `INSERT INTO catalog_models (import_id, system_id, model) VALUES (?, ?, ?)`,
			importID, m.SystemID, m.Model); err != nil {
			return err
		}
	}
	for _, rel := range rels {
		if _, err := q.ExecContext(ctx, `INSERT INTO catalog_releases (import_id, system_id, component_id, vendor_id,
			device_id, sub_vendor_id, sub_device_id, version, released_at, criticality, name, package_path, details_url,
			reboot_required) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, importID, rel.SystemID, rel.ComponentID,
			rel.VendorID, rel.DeviceID, rel.SubVendorID, rel.SubDeviceID, rel.Version, nullMS(rel.ReleasedAt),
			rel.Criticality, rel.Name, rel.PackagePath, rel.DetailsURL, boolInt(rel.RebootRequired)); err != nil {
			return err
		}
	}
	return nil
}

func (r catalogRepo) ActivateHeld(ctx context.Context, source string, want int64) (bool, error) {
	const op = "activate held catalog import"
	found := false
	err := inTx(ctx, r.db, op, func(q querier) error {
		var id int64
		err := q.QueryRowContext(ctx, `SELECT id FROM catalog_imports WHERE source = ? AND state = 'held' AND id = ?`,
			source, want).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return mapErr(op, err)
		}
		found = true
		if _, err := q.ExecContext(ctx, `UPDATE catalog_imports SET state = 'replaced' WHERE source = ? AND state = 'active'`,
			source); err != nil {
			return mapErr(op, err)
		}
		if _, err := q.ExecContext(ctx, `UPDATE catalog_imports SET state = 'active' WHERE id = ?`, id); err != nil {
			return mapErr(op, err)
		}
		return pruneImports(ctx, q, op, source)
	})
	return found, err
}

func (r catalogRepo) ReplaceReleases(ctx context.Context, importID int64, rels []CatalogReleaseRow,
	models []CatalogModelRow) error {
	const op = "replace catalog releases"
	return inTx(ctx, r.db, op, func(q querier) error {
		res, err := q.ExecContext(ctx, `UPDATE catalog_imports SET kept = ? WHERE id = ? AND state <> 'replaced'`,
			len(rels), importID)
		if err != nil {
			return mapErr(op, err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fmt.Errorf("store: %s: %w", op, ErrNotFound)
		}
		for _, table := range []string{"catalog_releases", "catalog_models"} {
			if _, err := q.ExecContext(ctx, `DELETE FROM `+table+` WHERE import_id = ?`, importID); err != nil {
				return mapErr(op, err)
			}
		}
		return mapErr(op, insertReleases(ctx, q, importID, rels, models))
	})
}

func (r catalogRepo) Import(ctx context.Context, source, state string) (CatalogImportRow, bool, error) {
	const op = "catalog import"
	rows, err := r.db.QueryContext(ctx, `SELECT `+catImportCols+` FROM catalog_imports WHERE source = ? AND state = ?`,
		source, state)
	if err != nil {
		return CatalogImportRow{}, false, mapErr(op, err)
	}
	list, err := scanImports(rows, op)
	if err != nil || len(list) == 0 {
		return CatalogImportRow{}, false, err
	}
	return list[0], true, nil
}

func (r catalogRepo) Imports(ctx context.Context, source string, limit int) ([]CatalogImportRow, error) {
	const op = "catalog imports"
	if limit < 1 || limit > 100 {
		return nil, invalid(op, "limit must be in [1, 100]")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT `+catImportCols+` FROM catalog_imports WHERE source = ?
		ORDER BY id DESC LIMIT ?`, source, limit)
	if err != nil {
		return nil, mapErr(op, err)
	}
	return scanImports(rows, op)
}

func scanImports(rows *sql.Rows, op string) ([]CatalogImportRow, error) {
	defer rows.Close()
	var out []CatalogImportRow
	for rows.Next() {
		var i CatalogImportRow
		var pub sql.NullInt64
		var at int64
		if err := rows.Scan(&i.ID, &i.Source, &i.Origin, &i.State, &i.Version, &i.ReleaseID, &pub, &at, &i.SHA256,
			&i.Signer, &i.ETag, &i.LastModified, &i.Components, &i.Kept, &i.ImportedBy); err != nil {
			return nil, mapErr(op, err)
		}
		i.PublishedAt, i.ImportedAt = fromNullMS(pub), fromMS(at)
		out = append(out, i)
	}
	return out, mapErr(op, rows.Err())
}

func (r catalogRepo) Releases(ctx context.Context, importID int64) ([]CatalogReleaseRow, error) {
	const op = "catalog releases"
	rows, err := r.db.QueryContext(ctx, `SELECT import_id, system_id, component_id, vendor_id, device_id, sub_vendor_id,
		sub_device_id, version, released_at, criticality, name, package_path, details_url, reboot_required
		FROM catalog_releases WHERE import_id = ? ORDER BY system_id, component_id, version, vendor_id, device_id,
		sub_vendor_id, sub_device_id`, importID)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []CatalogReleaseRow
	for rows.Next() {
		var c CatalogReleaseRow
		var rel sql.NullInt64
		var reboot int
		if err := rows.Scan(&c.ImportID, &c.SystemID, &c.ComponentID, &c.VendorID, &c.DeviceID, &c.SubVendorID,
			&c.SubDeviceID, &c.Version, &rel, &c.Criticality, &c.Name, &c.PackagePath, &c.DetailsURL, &reboot); err != nil {
			return nil, mapErr(op, err)
		}
		c.ReleasedAt, c.RebootRequired = fromNullMS(rel), reboot == 1
		out = append(out, c)
	}
	return out, mapErr(op, rows.Err())
}

func (r catalogRepo) Models(ctx context.Context, importID int64) ([]CatalogModelRow, error) {
	const op = "catalog models"
	rows, err := r.db.QueryContext(ctx, `SELECT import_id, system_id, model FROM catalog_models WHERE import_id = ?
		ORDER BY system_id, model`, importID)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []CatalogModelRow
	for rows.Next() {
		var m CatalogModelRow
		if err := rows.Scan(&m.ImportID, &m.SystemID, &m.Model); err != nil {
			return nil, mapErr(op, err)
		}
		out = append(out, m)
	}
	return out, mapErr(op, rows.Err())
}

func (r catalogRepo) AddCheck(ctx context.Context, c CatalogCheckRow) error {
	const op = "add catalog check"
	var importID any
	if c.ImportID > 0 {
		importID = c.ImportID
	}
	return inTx(ctx, r.db, op, func(q querier) error {
		if _, err := q.ExecContext(ctx, `INSERT INTO catalog_checks (source, at, result, detail, import_id)
			VALUES (?, ?, ?, ?, ?)`, c.Source, toMS(c.At), c.Result, c.Detail, importID); err != nil {
			return mapErr(op, err)
		}
		cutoff := toMS(c.At.Add(-90 * 24 * time.Hour))
		_, err := q.ExecContext(ctx, `DELETE FROM catalog_checks WHERE source = ? AND (at < ? OR id NOT IN
			(SELECT id FROM catalog_checks WHERE source = ? ORDER BY at DESC, id DESC LIMIT ?))`,
			c.Source, cutoff, c.Source, catalogChecksKept)
		return mapErr(op, err)
	})
}

func (r catalogRepo) Checks(ctx context.Context, source string, limit int) ([]CatalogCheckRow, error) {
	const op = "catalog checks"
	if limit < 1 || limit > catalogChecksKept {
		return nil, invalid(op, "limit must be in [1, 500]")
	}
	rows, err := r.db.QueryContext(ctx, `SELECT id, source, at, result, detail, import_id FROM catalog_checks
		WHERE source = ? ORDER BY at DESC, id DESC LIMIT ?`, source, limit)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []CatalogCheckRow
	for rows.Next() {
		var c CatalogCheckRow
		var at int64
		var imp sql.NullInt64
		if err := rows.Scan(&c.ID, &c.Source, &at, &c.Result, &c.Detail, &imp); err != nil {
			return nil, mapErr(op, err)
		}
		c.At, c.ImportID = fromMS(at), imp.Int64
		out = append(out, c)
	}
	return out, mapErr(op, rows.Err())
}

// FirmwareUpdateSkipRow is one "skip this version" (firmware_update_skips).
type FirmwareUpdateSkipRow struct {
	ServerID, ComponentID, FQDD string
	Version, Comment, SkippedBy string
	SkippedAt                   time.Time
}

// FirmwareUpdateRepository stores the per-component update decisions (plan 08 §9).
type FirmwareUpdateRepository interface {
	// Skips returns every skip, ordered by server, component, FQDD.
	Skips(ctx context.Context) ([]FirmwareUpdateSkipRow, error)
	// PutSkip records or replaces the skip of one component.
	PutSkip(ctx context.Context, s FirmwareUpdateSkipRow) error
	// DeleteSkip removes the skip of one component; false when none was recorded.
	DeleteSkip(ctx context.Context, serverID, componentID, fqdd string) (bool, error)
	// MarkNotified records (server, component, version) triples as notified and returns
	// the ones that were new.
	MarkNotified(ctx context.Context, rows []FirmwareUpdateNotifiedRow) ([]FirmwareUpdateNotifiedRow, error)
	// DeleteServer removes a server's skips and notified rows (it left the registry).
	DeleteServer(ctx context.Context, serverID string) error
}

// FirmwareUpdateNotifiedRow is one notified update (firmware_update_notified).
type FirmwareUpdateNotifiedRow struct {
	ServerID, ComponentID, FQDD, Version string
	NotifiedAt                           time.Time
}

// FirmwareUpdates returns the update decisions repository.
func (d *DB) FirmwareUpdates() FirmwareUpdateRepository { return fwUpdateRepo{d.sql} }

// FirmwareUpdates returns the update decisions repository bound to the transaction.
func (t *Tx) FirmwareUpdates() FirmwareUpdateRepository { return fwUpdateRepo{t.tx} }

type fwUpdateRepo struct{ db querier }

func (r fwUpdateRepo) Skips(ctx context.Context) ([]FirmwareUpdateSkipRow, error) {
	const op = "firmware update skips"
	rows, err := r.db.QueryContext(ctx, `SELECT server_id, component_id, fqdd, version, comment, skipped_by, skipped_at
		FROM firmware_update_skips ORDER BY server_id, component_id, fqdd`)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []FirmwareUpdateSkipRow
	for rows.Next() {
		var s FirmwareUpdateSkipRow
		var at int64
		if err := rows.Scan(&s.ServerID, &s.ComponentID, &s.FQDD, &s.Version, &s.Comment, &s.SkippedBy, &at); err != nil {
			return nil, mapErr(op, err)
		}
		s.SkippedAt = fromMS(at)
		out = append(out, s)
	}
	return out, mapErr(op, rows.Err())
}

func (r fwUpdateRepo) PutSkip(ctx context.Context, s FirmwareUpdateSkipRow) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO firmware_update_skips (server_id, component_id, fqdd, version, comment,
		skipped_by, skipped_at) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (server_id, component_id, fqdd) DO UPDATE SET version = excluded.version, comment = excluded.comment,
		skipped_by = excluded.skipped_by, skipped_at = excluded.skipped_at`, s.ServerID, s.ComponentID, s.FQDD, s.Version,
		s.Comment, s.SkippedBy, toMS(s.SkippedAt))
	return mapErr("put firmware update skip", err)
}

func (r fwUpdateRepo) DeleteSkip(ctx context.Context, serverID, componentID, fqdd string) (bool, error) {
	n, err := execCount(ctx, r.db, "delete firmware update skip", `DELETE FROM firmware_update_skips
		WHERE server_id = ? AND component_id = ? AND fqdd = ?`, serverID, componentID, fqdd)
	return n > 0, err
}

func (r fwUpdateRepo) MarkNotified(ctx context.Context, rows []FirmwareUpdateNotifiedRow) ([]FirmwareUpdateNotifiedRow, error) {
	const op = "mark firmware updates notified"
	var fresh []FirmwareUpdateNotifiedRow
	err := inTx(ctx, r.db, op, func(q querier) error {
		for _, n := range rows {
			res, err := q.ExecContext(ctx, `INSERT INTO firmware_update_notified (server_id, component_id, fqdd, version,
				notified_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING`, n.ServerID, n.ComponentID, n.FQDD, n.Version,
				toMS(n.NotifiedAt))
			if err != nil {
				return mapErr(op, err)
			}
			if c, _ := res.RowsAffected(); c == 1 {
				fresh = append(fresh, n)
			}
		}
		return nil
	})
	return fresh, err
}

func (r fwUpdateRepo) DeleteServer(ctx context.Context, serverID string) error {
	const op = "delete firmware update rows of a server"
	return inTx(ctx, r.db, op, func(q querier) error {
		for _, table := range []string{"firmware_update_skips", "firmware_update_notified"} {
			if _, err := q.ExecContext(ctx, `DELETE FROM `+table+` WHERE server_id = ?`, serverID); err != nil {
				return mapErr(op, err)
			}
		}
		return nil
	})
}
