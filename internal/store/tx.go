package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// querier is what every repository runs its SQL on: *sql.DB, or the *sql.Tx of a
// caller-owned transaction (DB.WithTx).
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// inTx runs fn in a transaction. When q already is a transaction (the repository was
// handed out by a Tx), fn joins it and the caller's WithTx commits or rolls back.
func inTx(ctx context.Context, q querier, op string, fn func(querier) error) (err error) {
	db, ok := q.(*sql.DB)
	if !ok {
		return fn(q)
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return mapErr(op, err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, tx.Rollback())
		}
	}()
	if err = fn(tx); err != nil {
		return err
	}
	return mapErr(op, tx.Commit())
}

// Tx is one caller-owned transaction. Its repositories all run on the transaction, so a
// change and the audit row describing it commit or roll back together. Tx is only valid
// inside the WithTx callback and must not be used from other goroutines.
//
// The store has a single connection: inside the callback, use only the Tx's
// repositories. Calling the DB's own repositories there would wait for the connection
// the transaction holds.
type Tx struct {
	tx    *sql.Tx
	after []func()
}

// WithTx runs fn in one transaction: commit when fn returns nil, rollback otherwise.
// Hooks registered with Tx.AfterCommit run, in order, only after a successful commit.
func (d *DB) WithTx(ctx context.Context, fn func(*Tx) error) (err error) {
	if fn == nil {
		return errors.New("store: WithTx: nil function")
	}
	sqlTx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return mapErr("begin", err)
	}
	t := &Tx{tx: sqlTx}
	if err = fn(t); err != nil {
		return errors.Join(err, sqlTx.Rollback())
	}
	if err = sqlTx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	for _, hook := range t.after {
		hook()
	}
	return nil
}

// AfterCommit registers fn to run once the transaction has committed (for example the
// off-box copy of an audit row). It never runs on rollback.
func (t *Tx) AfterCommit(fn func()) { t.after = append(t.after, fn) }

// Users returns the user repository bound to the transaction.
func (t *Tx) Users() UserRepository { return userRepo{t.tx} }

// Accounts returns the guarded account changes bound to the transaction.
func (t *Tx) Accounts() AccountRepository { return accountRepo{t.tx} }

// Sessions returns the session repository bound to the transaction.
func (t *Tx) Sessions() SessionRepository { return sessionRepo{t.tx} }

// Lockouts returns the login-failure repository inside the transaction.
func (t *Tx) Lockouts() LockoutRepository { return lockoutRepo{t.tx} }

// Tokens returns the API token repository bound to the transaction.
func (t *Tx) Tokens() TokenRepository { return tokenRepo{t.tx} }

// Enrolments returns the enrolment token repository bound to the transaction.
func (t *Tx) Enrolments() EnrolmentRepository { return enrolmentRepo{t.tx} }

// Audit returns the audit repository bound to the transaction.
func (t *Tx) Audit() AuditRepository { return auditRepo{t.tx} }

// Settings returns the settings repository bound to the transaction.
func (t *Tx) Settings() SettingsRepository { return settingsRepo{t.tx} }

// Prefs returns the user preferences repository bound to the transaction.
func (t *Tx) Prefs() PrefsRepository { return prefsRepo{t.tx} }

// Servers returns the server repository bound to the transaction.
func (t *Tx) Servers() ServerRepository { return serverRepo{t.tx} }

// Credentials returns the BMC credential repository bound to the transaction.
func (t *Tx) Credentials() CredentialRepository { return credentialRepo{t.tx} }
