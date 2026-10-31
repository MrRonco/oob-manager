// Package admin is the settings slice S1 service (docs/settings_design.md): user
// management with one-time enrolment links, session revocation and API tokens. Every
// change and the audit row describing it are written in one database transaction
// (audit.Logger.RecordTx), so a change can never commit unaudited. Refused changes are
// audited too, outside the (rolled-back) transaction.
//
// Authorization and the step-up window are the caller's job (the web UI checks
// authz.AdminUsersManage / AdminTokensManage first). The invariants that must hold
// however the service is called (the last enabled admin, an admin's own account) are
// enforced in SQL by store.AccountRepository.
package admin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/store"
)

// DefaultLinkTTL is how long an enrolment link stays valid.
const DefaultLinkTTL = 24 * time.Hour

// Errors. Messages are safe to show to an admin; none echoes a secret.
var (
	ErrInvalidInput  = errors.New("invalid input")
	ErrNotFound      = errors.New("not found")
	ErrUsernameTaken = errors.New("that username is already taken")
	ErrRefused       = errors.New("refused: this would lock out the last admin or change your own account")
	ErrLinkInvalid   = errors.New("this link is invalid, already used or expired")
)

// Actor is who makes a change. Method is "local" (browser session) or "cli".
type Actor struct {
	UserID   string
	Username string
	Role     authz.Role
	IP       string
	Method   string
}

// Recorder writes audit rows; *audit.Logger implements it.
type Recorder interface {
	Record(ctx context.Context, e audit.Entry) (store.AuditRecord, error)
	RecordTx(ctx context.Context, tx *store.Tx, e audit.Entry) (store.AuditRecord, error)
}

// Config wires a Service. All fields but Now, Logger, Issuer and LinkTTL are required.
type Config struct {
	DB      *store.DB
	Audit   Recorder
	Hasher  *auth.PasswordHasher
	Sealer  auth.Sealer
	Tokens  *auth.TokenService
	Now     func() time.Time
	Logger  *slog.Logger
	Issuer  string // TOTP issuer shown in authenticator apps
	LinkTTL time.Duration
}

// Service runs the S1 admin changes. It holds no mutable state.
type Service struct {
	cfg Config
}

// New validates cfg and returns a Service.
func New(cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Hasher == nil || cfg.Sealer == nil || cfg.Tokens == nil {
		return nil, errors.New("admin: DB, Audit, Hasher, Sealer and Tokens are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Issuer == "" {
		cfg.Issuer = auth.DefaultIssuer
	}
	if cfg.LinkTTL <= 0 {
		cfg.LinkTTL = DefaultLinkTTL
	}
	return &Service{cfg: cfg}, nil
}

// entry starts an audit entry for a change made by a.
func (a Actor) entry(action string, params map[string]any) audit.Entry {
	return audit.Entry{Principal: a.Username, AuthMethod: a.Method, Role: string(a.Role), SrcIP: a.IP,
		Action: action, Params: params, Result: audit.ResultOK}
}

// change runs fn in one transaction and records, in that same transaction, the audit
// entry fn returns for what it did.
func (s *Service) change(ctx context.Context, fn func(tx *store.Tx) (audit.Entry, error)) error {
	return s.cfg.DB.WithTx(ctx, func(tx *store.Tx) error {
		e, err := fn(tx)
		if err != nil {
			return err
		}
		_, err = s.cfg.Audit.RecordTx(ctx, tx, e)
		return err
	})
}

// changeOrDeny is change, plus a "denied" audit row (outside the rolled-back
// transaction) when the change was refused or its target does not exist.
func (s *Service) changeOrDeny(ctx context.Context, denied audit.Entry, fn func(tx *store.Tx) (audit.Entry, error)) error {
	err := mapStoreErr(s.change(ctx, fn))
	if errors.Is(err, ErrRefused) || errors.Is(err, ErrNotFound) {
		s.auditDenied(ctx, denied, denialClass(err))
	}
	return err
}

// auditDenied records a refused request.
func (s *Service) auditDenied(ctx context.Context, e audit.Entry, class string) {
	e.Result, e.ErrorClass = audit.ResultDenied, class
	if _, err := s.cfg.Audit.Record(ctx, e); err != nil {
		s.cfg.Logger.Error("admin denial audit failed", "action", e.Action, "err", err)
	}
}

// with returns a copy of p plus the key/value pairs kv (never modifies p).
func with(p map[string]any, kv ...any) map[string]any {
	out := make(map[string]any, len(p)+len(kv)/2)
	for k, v := range p {
		out[k] = v
	}
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			out[k] = kv[i+1]
		}
	}
	return out
}

func denialClass(err error) string {
	if errors.Is(err, ErrRefused) {
		return "refused"
	}
	return "not_found"
}

// mapStoreErr turns store sentinels into this package's errors; others pass through.
func mapStoreErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, store.ErrRefused):
		return ErrRefused
	case errors.Is(err, store.ErrNotFound):
		return ErrNotFound
	default:
		return err
	}
}

func invalidInput(msg string) error { return fmt.Errorf("%w: %s", ErrInvalidInput, msg) }

// randomPassword is an unguessable placeholder for accounts that have not enrolled yet
// (users.pw_hash is NOT NULL). Nobody ever learns it.
func randomPassword() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// newID returns a 128-bit random hex identifier.
func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%x", b)
}
