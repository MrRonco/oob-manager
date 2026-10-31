package audit

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"oob-manager/internal/store"
)

// MaxParamsBytes caps the encoded params_json of one entry.
const MaxParamsBytes = 4 << 10

// Results an entry may record.
const (
	ResultStarted = "started"
	ResultOK      = "ok"
	ResultDenied  = "denied"
	ResultError   = "error"
)

// ErrInvalidEntry is returned for entries that fail validation.
var ErrInvalidEntry = errors.New("audit: invalid entry")

// Entry is what callers record. Params must be JSON-encodable and must not contain
// secrets (secrets.Secret marshals as "[redacted]" anyway).
type Entry struct {
	CorrelationID string // generated when empty
	Principal     string
	AuthMethod    string
	Role          string
	SrcIP         string
	ServerID      string
	Action        string
	Params        map[string]any
	Result        string
	BMCStatus     string
	ErrorClass    string
}

func (e Entry) validate() error {
	switch {
	case e.Action == "":
		return fmt.Errorf("%w: action is required", ErrInvalidEntry)
	case e.Principal == "":
		return fmt.Errorf("%w: principal is required", ErrInvalidEntry)
	}
	switch e.Result {
	case ResultStarted, ResultOK, ResultDenied, ResultError:
		return nil
	default:
		return fmt.Errorf("%w: result %q must be started, ok, denied or error", ErrInvalidEntry, e.Result)
	}
}

// Sink receives GELF copies of recorded entries. Enqueue must never block; false
// means the message was dropped. *Shipper implements it.
type Sink interface {
	Enqueue(m Message) bool
}

// Logger appends entries to the chain and forwards a copy to a Sink.
type Logger struct {
	repo store.AuditRepository
	sink Sink
	now  func() time.Time
	log  *slog.Logger
	host string
}

// NewLogger builds a Logger. sink may be nil (no off-box copy); now defaults to
// time.Now and log to slog.Default().
func NewLogger(repo store.AuditRepository, sink Sink, now func() time.Time, log *slog.Logger) *Logger {
	if now == nil {
		now = time.Now
	}
	if log == nil {
		log = slog.Default()
	}
	return &Logger{repo: repo, sink: sink, now: now, log: log, host: DefaultHost}
}

// Record validates e, appends it to the chain and enqueues the GELF copy. A store
// failure is returned (the caller must not proceed with an unaudited action); a full
// or down sink is not an error.
func (l *Logger) Record(ctx context.Context, e Entry) (store.AuditRecord, error) {
	base, err := l.prepare(e)
	if err != nil {
		return store.AuditRecord{}, err
	}
	rec, err := l.appendTo(ctx, l.repo, base)
	if err != nil {
		return store.AuditRecord{}, err
	}
	l.ship(rec)
	return rec, nil
}

// RecordTx appends e inside the caller's transaction, so the audit row commits or rolls
// back with the change it describes (settings_design.md §3). The GELF copy is enqueued
// only after the transaction commits; a rolled-back change is never shipped.
func (l *Logger) RecordTx(ctx context.Context, tx *store.Tx, e Entry) (store.AuditRecord, error) {
	base, err := l.prepare(e)
	if err != nil {
		return store.AuditRecord{}, err
	}
	rec, err := l.appendTo(ctx, tx.Audit(), base)
	if err != nil {
		return store.AuditRecord{}, err
	}
	tx.AfterCommit(func() { l.ship(rec) })
	return rec, nil
}

// prepare validates e and builds the unchained record (params redacted and encoded).
func (l *Logger) prepare(e Entry) (store.AuditRecord, error) {
	if err := e.validate(); err != nil {
		return store.AuditRecord{}, err
	}
	params, err := encodeParams(redact(e.Params))
	if err != nil {
		return store.AuditRecord{}, err
	}
	corr := e.CorrelationID
	if corr == "" {
		if corr, err = newCorrelationID(); err != nil {
			return store.AuditRecord{}, err
		}
	}
	return store.AuditRecord{TS: l.now().UTC().Truncate(time.Millisecond), CorrelationID: corr,
		Principal: e.Principal, AuthMethod: e.AuthMethod, Role: e.Role, SrcIP: e.SrcIP, ServerID: e.ServerID,
		Action: e.Action, ParamsJSON: params, Result: e.Result, BMCStatus: e.BMCStatus, ErrorClass: e.ErrorClass}, nil
}

func (l *Logger) appendTo(ctx context.Context, repo store.AuditRepository, base store.AuditRecord) (store.AuditRecord, error) {
	rec, err := repo.Append(ctx, func(last store.AuditRecord, ok bool) (store.AuditRecord, error) {
		return link(base, last, ok), nil
	})
	if err != nil {
		l.log.Error("audit append failed", "action", base.Action, "principal", base.Principal, "err", err)
		return store.AuditRecord{}, fmt.Errorf("audit: record: %w", err)
	}
	return rec, nil
}

func (l *Logger) ship(rec store.AuditRecord) {
	if l.sink != nil {
		l.sink.Enqueue(recordMessage(l.host, rec))
	}
}

// link returns a copy of base chained after last.
func link(base, last store.AuditRecord, ok bool) store.AuditRecord {
	r := base
	r.Seq, r.PrevHash = 1, GenesisHash
	if ok {
		r.Seq, r.PrevHash = last.Seq+1, last.RowHash
	}
	r.RowHash = Hash(r)
	return r
}

func encodeParams(p map[string]any) (string, error) {
	if len(p) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(p) // map keys are sorted: deterministic
	if err != nil {
		return "", fmt.Errorf("%w: params: %v", ErrInvalidEntry, err)
	}
	if len(b) > MaxParamsBytes {
		return "", fmt.Errorf("%w: params exceed %d bytes", ErrInvalidEntry, MaxParamsBytes)
	}
	return string(b), nil
}

func newCorrelationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("audit: correlation id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// recordMessage renders an audit record as a GELF message.
func recordMessage(host string, r store.AuditRecord) Message {
	return Message{
		Host:      host,
		Short:     fmt.Sprintf("audit %s by %s: %s", r.Action, r.Principal, r.Result),
		Timestamp: r.TS,
		Level:     LevelNotice,
		Fields: map[string]any{
			"audit_seq": r.Seq, "correlation_id": r.CorrelationID, "principal": r.Principal,
			"auth_method": r.AuthMethod, "role": r.Role, "src_ip": r.SrcIP, "server_id": r.ServerID,
			"action": r.Action, "params": r.ParamsJSON, "result": r.Result, "bmc_status": r.BMCStatus,
			"error_class": r.ErrorClass, "prev_hash": r.PrevHash, "row_hash": r.RowHash, "log_type": "audit",
		},
	}
}
