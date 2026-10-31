package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// ServerRow is one server managed in the browser (settings slice S3). Values are
// validated by internal/registry with the config.yaml validator before they are
// written; the table's CHECKs are a second line.
type ServerRow struct {
	ID               string
	Name             string
	Tags             []string
	Kind             string
	Address          string
	Port             int
	TLSPin           string
	VNCPin           string
	SSHHostKey       string
	FanMode          string
	FanSafeMinPct    int
	FanMaxLease      time.Duration
	ConsoleSerial    string
	ConsoleGraphical string
	VNCPort          int
	SSHPort          int
	PowerSelfHost    bool
	PowerImpact      []string
	PollInterval     time.Duration // 0: the app's poll interval
	Enabled          bool
	Rev              int64 // set by the store
	CredSeq          int   // set by the store
	CreatedAt        time.Time
	CreatedBy        string
	UpdatedAt        time.Time
	UpdatedBy        string
}

// Clone returns a copy that shares no slices with r.
func (r ServerRow) Clone() ServerRow {
	r.Tags = slices.Clone(r.Tags)
	r.PowerImpact = slices.Clone(r.PowerImpact)
	return r
}

// CredentialRow is one sealed BMC credential (bmc_credentials).
type CredentialRow struct {
	ServerID  string
	Slot      string
	Version   int
	KeyID     string
	SecretEnc []byte
	CreatedAt time.Time
	CreatedBy string
}

// ServerRepository stores browser-managed servers.
type ServerRepository interface {
	// All returns every row ordered by id.
	All(ctx context.Context) ([]ServerRow, error)
	Get(ctx context.Context, id string) (ServerRow, error)
	// Insert adds a row at rev 1 (ErrConflict when the id exists).
	Insert(ctx context.Context, r ServerRow) error
	// Update replaces every column but id, created_* and cred_seq when the stored rev is
	// expect (compare-and-set), and moves rev to expect+1. ErrConflict on a stale rev,
	// ErrNotFound when the row is gone.
	Update(ctx context.Context, r ServerRow, expect int64) error
	// Delete removes the row (and its credentials) when its rev is expect.
	Delete(ctx context.Context, id string, expect int64) error
	// NextCredVersion increments and returns the server's credential sequence.
	NextCredVersion(ctx context.Context, id string) (int, error)
}

// CredentialRepository stores sealed BMC credentials.
type CredentialRepository interface {
	// List returns a server's credentials ordered by slot.
	List(ctx context.Context, serverID string) ([]CredentialRow, error)
	// All returns every credential ordered by server and slot.
	All(ctx context.Context) ([]CredentialRow, error)
	// Put inserts or replaces the credential of (server, slot).
	Put(ctx context.Context, c CredentialRow) error
	// DeleteAll removes every credential of a server and returns how many.
	DeleteAll(ctx context.Context, serverID string) (int64, error)
}

type serverRepo struct{ db querier }

const serverCols = `id, name, tags_json, kind, address, port, tls_pin_sha256, vnc_pin_sha256, ssh_host_key,
	fan_mode, fan_safe_min_pct, fan_max_lease_ms, console_serial, console_graphical, vnc_port, ssh_port,
	power_self_host, power_impact_json, poll_interval_ms, enabled, rev, cred_seq, created_at, created_by,
	updated_at, updated_by`

func (r serverRepo) All(ctx context.Context) ([]ServerRow, error) {
	const op = "servers"
	rows, err := r.db.QueryContext(ctx, `SELECT `+serverCols+` FROM servers ORDER BY id`)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []ServerRow
	for rows.Next() {
		s, err := scanServer(rows)
		if err != nil {
			return nil, mapErr(op, err)
		}
		out = append(out, s)
	}
	return out, mapErr(op, rows.Err())
}

func (r serverRepo) Get(ctx context.Context, id string) (ServerRow, error) {
	s, err := scanServer(r.db.QueryRowContext(ctx, `SELECT `+serverCols+` FROM servers WHERE id = ?`, id))
	return s, mapErr("server", err)
}

type scanner interface{ Scan(dest ...any) error }

func scanServer(sc scanner) (ServerRow, error) {
	var s ServerRow
	var tags, impact string
	var lease, created, updated int64
	var poll sql.NullInt64
	var selfHost, enabled int
	err := sc.Scan(&s.ID, &s.Name, &tags, &s.Kind, &s.Address, &s.Port, &s.TLSPin, &s.VNCPin, &s.SSHHostKey,
		&s.FanMode, &s.FanSafeMinPct, &lease, &s.ConsoleSerial, &s.ConsoleGraphical, &s.VNCPort, &s.SSHPort,
		&selfHost, &impact, &poll, &enabled, &s.Rev, &s.CredSeq, &created, &s.CreatedBy, &updated, &s.UpdatedBy)
	if err != nil {
		return ServerRow{}, err
	}
	if err := json.Unmarshal([]byte(tags), &s.Tags); err != nil {
		return ServerRow{}, fmt.Errorf("tags: %w", err)
	}
	if err := json.Unmarshal([]byte(impact), &s.PowerImpact); err != nil {
		return ServerRow{}, fmt.Errorf("power impact: %w", err)
	}
	s.FanMaxLease = time.Duration(lease) * time.Millisecond
	if poll.Valid {
		s.PollInterval = time.Duration(poll.Int64) * time.Millisecond
	}
	s.PowerSelfHost, s.Enabled = selfHost == 1, enabled == 1
	s.CreatedAt, s.UpdatedAt = fromMS(created), fromMS(updated)
	return s, nil
}

// args are the columns Insert and Update write, in serverCols order minus rev,
// cred_seq and the created_* pair (handled per statement).
func (r ServerRow) args() ([]any, error) {
	tags, err := json.Marshal(nonNil(r.Tags))
	if err != nil {
		return nil, err
	}
	impact, err := json.Marshal(nonNil(r.PowerImpact))
	if err != nil {
		return nil, err
	}
	var poll any
	if r.PollInterval > 0 {
		poll = r.PollInterval.Milliseconds()
	}
	return []any{r.Name, string(tags), r.Kind, r.Address, r.Port, r.TLSPin, r.VNCPin, r.SSHHostKey, r.FanMode,
		r.FanSafeMinPct, r.FanMaxLease.Milliseconds(), r.ConsoleSerial, r.ConsoleGraphical, r.VNCPort, r.SSHPort,
		boolInt(r.PowerSelfHost), string(impact), poll, boolInt(r.Enabled), toMS(r.UpdatedAt), r.UpdatedBy}, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (r serverRepo) Insert(ctx context.Context, s ServerRow) error {
	args, err := s.args()
	if err != nil {
		return invalid("insert server", err.Error())
	}
	_, err = r.db.ExecContext(ctx, `INSERT INTO servers (name, tags_json, kind, address, port, tls_pin_sha256,
		vnc_pin_sha256, ssh_host_key, fan_mode, fan_safe_min_pct, fan_max_lease_ms, console_serial,
		console_graphical, vnc_port, ssh_port, power_self_host, power_impact_json, poll_interval_ms, enabled,
		updated_at, updated_by, id, created_at, created_by, rev, cred_seq)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0)`,
		append(args, s.ID, toMS(s.CreatedAt), s.CreatedBy)...)
	return mapErr("insert server", err)
}

func (r serverRepo) Update(ctx context.Context, s ServerRow, expect int64) error {
	const op = "update server"
	args, err := s.args()
	if err != nil {
		return invalid(op, err.Error())
	}
	n, err := execCount(ctx, r.db, op, `UPDATE servers SET name = ?, tags_json = ?, kind = ?, address = ?, port = ?,
		tls_pin_sha256 = ?, vnc_pin_sha256 = ?, ssh_host_key = ?, fan_mode = ?, fan_safe_min_pct = ?,
		fan_max_lease_ms = ?, console_serial = ?, console_graphical = ?, vnc_port = ?, ssh_port = ?,
		power_self_host = ?, power_impact_json = ?, poll_interval_ms = ?, enabled = ?, updated_at = ?,
		updated_by = ?, rev = rev + 1 WHERE id = ? AND rev = ?`, append(args, s.ID, expect)...)
	if err != nil || n == 1 {
		return err
	}
	return r.missingOrStale(ctx, op, s.ID)
}

func (r serverRepo) Delete(ctx context.Context, id string, expect int64) error {
	const op = "delete server"
	n, err := execCount(ctx, r.db, op, `DELETE FROM servers WHERE id = ? AND rev = ?`, id, expect)
	if err != nil || n == 1 {
		return err
	}
	return r.missingOrStale(ctx, op, id)
}

// missingOrStale explains a compare-and-set that matched no row.
func (r serverRepo) missingOrStale(ctx context.Context, op, id string) error {
	var one int
	err := r.db.QueryRowContext(ctx, `SELECT 1 FROM servers WHERE id = ?`, id).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store: %s: %w", op, ErrNotFound)
	}
	if err != nil {
		return mapErr(op, err)
	}
	return fmt.Errorf("store: %s: %w: the server was changed elsewhere", op, ErrConflict)
}

func (r serverRepo) NextCredVersion(ctx context.Context, id string) (int, error) {
	var v int
	err := r.db.QueryRowContext(ctx, `UPDATE servers SET cred_seq = cred_seq + 1 WHERE id = ? RETURNING cred_seq`,
		id).Scan(&v)
	return v, mapErr("credential version", err)
}

type credentialRepo struct{ db querier }

const credCols = `server_id, slot, version, key_id, secret_enc, created_at, created_by` //nolint:gosec // G101: column names

func (r credentialRepo) List(ctx context.Context, serverID string) ([]CredentialRow, error) {
	return r.query(ctx, `SELECT `+credCols+` FROM bmc_credentials WHERE server_id = ? ORDER BY slot`, serverID)
}

func (r credentialRepo) All(ctx context.Context) ([]CredentialRow, error) {
	return r.query(ctx, `SELECT `+credCols+` FROM bmc_credentials ORDER BY server_id, slot`)
}

func (r credentialRepo) query(ctx context.Context, q string, args ...any) ([]CredentialRow, error) {
	const op = "credentials"
	rows, err := r.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, mapErr(op, err)
	}
	defer rows.Close()
	var out []CredentialRow
	for rows.Next() {
		var c CredentialRow
		var at int64
		if err := rows.Scan(&c.ServerID, &c.Slot, &c.Version, &c.KeyID, &c.SecretEnc, &at, &c.CreatedBy); err != nil {
			return nil, mapErr(op, err)
		}
		c.CreatedAt = fromMS(at)
		out = append(out, c)
	}
	return out, mapErr(op, rows.Err())
}

func (r credentialRepo) Put(ctx context.Context, c CredentialRow) error {
	_, err := r.db.ExecContext(ctx, `INSERT INTO bmc_credentials (`+credCols+`) VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (server_id, slot) DO UPDATE SET version = excluded.version, key_id = excluded.key_id,
		secret_enc = excluded.secret_enc, created_at = excluded.created_at, created_by = excluded.created_by`,
		c.ServerID, c.Slot, c.Version, c.KeyID, c.SecretEnc, toMS(c.CreatedAt), c.CreatedBy)
	return mapErr("put credential", err)
}

func (r credentialRepo) DeleteAll(ctx context.Context, serverID string) (int64, error) {
	return execCount(ctx, r.db, "delete credentials", `DELETE FROM bmc_credentials WHERE server_id = ?`, serverID)
}
