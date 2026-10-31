package store

import (
	"context"
	"time"
)

// Repository interfaces. Other packages depend on these, not on *DB, so they can be
// tested with in-memory fakes. All methods take and return values.

// UserRepository manages local accounts.
type UserRepository interface {
	Create(ctx context.Context, u User) error
	ByID(ctx context.Context, id string) (User, error)
	ByUsername(ctx context.Context, username string) (User, error)
	List(ctx context.Context) ([]User, error)
	// Count supports first-admin bootstrap (0 users ⇒ bootstrap allowed).
	Count(ctx context.Context) (int, error)
	SetPasswordHash(ctx context.Context, id, hash string) error
	// CreateFirst inserts u only when the table is empty (one atomic statement);
	// otherwise ErrConflict. It backs the first-admin bootstrap.
	CreateFirst(ctx context.Context, u User) error
	// SetTOTPSecret stores a new secret, resets the last step and clears TOTPConfirmed
	// (a re-enrollment).
	SetTOTPSecret(ctx context.Context, id string, enc []byte) error
	// SetTOTP stores a sealed secret and its confirmed flag, leaving the last accepted
	// step unchanged so the confirmation code cannot be replayed.
	SetTOTP(ctx context.Context, id string, enc []byte, confirmed bool) error
	// AdvanceTOTPStep atomically records step if it is newer than the last accepted
	// one. false means replay (or an older step) and the code must be rejected.
	AdvanceTOTPStep(ctx context.Context, id string, step int64) (bool, error)
	SetDisabled(ctx context.Context, id string, disabled bool) error
	SetRole(ctx context.Context, id string, role Role) error
}

// SessionRepository manages server-side sessions keyed by cookie hash.
type SessionRepository interface {
	Create(ctx context.Context, s Session) error
	Get(ctx context.Context, idHash []byte) (Session, error)
	Touch(ctx context.Context, idHash []byte, at time.Time) error
	MarkStepUp(ctx context.Context, idHash []byte, at time.Time) error
	// Replace atomically deletes oldIDHash and inserts s (session rotation);
	// ErrNotFound, with nothing inserted, if oldIDHash no longer exists.
	Replace(ctx context.Context, oldIDHash []byte, s Session) error
	Delete(ctx context.Context, idHash []byte) error
	DeleteForUser(ctx context.Context, userID string) (int64, error)
	// DeleteExpired removes sessions idle since before idleBefore or created before
	// createdBefore (absolute lifetime).
	DeleteExpired(ctx context.Context, idleBefore, createdBefore time.Time) (int64, error)
	// ListForUser returns a user's sessions, most recently seen first.
	ListForUser(ctx context.Context, userID string) ([]Session, error)
	// DeleteOwned deletes one session only if it belongs to userID (ErrNotFound otherwise).
	DeleteOwned(ctx context.Context, userID string, idHash []byte) error
	// CountByUser returns the number of sessions per user ID.
	CountByUser(ctx context.Context) (map[string]int, error)
}

// TokenRepository manages read-only API tokens.
type TokenRepository interface {
	Create(ctx context.Context, t APIToken) error
	// ByHash returns revoked tokens too; callers must check Revoked().
	ByHash(ctx context.Context, hash []byte) (APIToken, error)
	List(ctx context.Context) ([]APIToken, error)
	Touch(ctx context.Context, id string, at time.Time) error
	// Revoke fails with ErrNotFound if the token is missing or already revoked.
	Revoke(ctx context.Context, id string, at time.Time) error
}

// AuditBuilder receives the current chain head (ok=false on an empty log) and returns
// the next record. It runs inside the append transaction and must not use the store.
type AuditBuilder func(last AuditRecord, ok bool) (AuditRecord, error)

// MaxAuditPage bounds List page size.
const MaxAuditPage = 1000

// AuditRepository is the append-only audit table.
type AuditRepository interface {
	// Append atomically reads the head, builds the next record and inserts it.
	// The record must have Seq = head+1 and PrevHash = head.RowHash (ErrConflict).
	Append(ctx context.Context, build AuditBuilder) (AuditRecord, error)
	Last(ctx context.Context) (AuditRecord, bool, error)
	// List returns up to limit records with Seq > afterSeq in ascending order.
	List(ctx context.Context, afterSeq int64, limit int) ([]AuditRecord, error)
}

// LeaseRepository persists fan leases for reconciliation.
type LeaseRepository interface {
	// Create fails with ErrConflict if the server already has an active lease.
	Create(ctx context.Context, l FanLease) error
	Get(ctx context.Context, leaseID string) (FanLease, error)
	Active(ctx context.Context, serverID string) (FanLease, error)
	ListByStates(ctx context.Context, states ...LeaseState) ([]FanLease, error)
	ListByServer(ctx context.Context, serverID string, limit int) ([]FanLease, error)
	// Transition is compare-and-set: ErrConflict if the lease is not in from.
	Transition(ctx context.Context, leaseID string, from, to LeaseState, at time.Time) error
}

// LockoutRepository stores login failure counters (migration 0002).
type LockoutRepository interface {
	// Get returns the zero state (and nil) when the key is absent.
	Get(ctx context.Context, key string) (LockoutState, error)
	// RecordFailure atomically increments the counter and returns the new state.
	RecordFailure(ctx context.Context, key string, at time.Time) (LockoutState, error)
	// Reset deletes the key (no-op when absent).
	Reset(ctx context.Context, key string) error
	// Prune deletes counters whose last failure is before the cutoff.
	Prune(ctx context.Context, before time.Time) (int64, error)
}

// CapabilityRepository stores the latest probe per server.
type CapabilityRepository interface {
	Put(ctx context.Context, c Capability) error
	Get(ctx context.Context, serverID string) (Capability, error)
}

// Compile-time checks that the SQLite implementations satisfy the interfaces.
var (
	_ UserRepository       = userRepo{}
	_ SessionRepository    = sessionRepo{}
	_ TokenRepository      = tokenRepo{}
	_ AuditRepository      = auditRepo{}
	_ LeaseRepository      = leaseRepo{}
	_ CapabilityRepository = capabilityRepo{}
	_ LockoutRepository    = lockoutRepo{}
)

// AccountRepository holds the account changes whose invariants are enforced in SQL,
// inside the statement itself, so concurrent admins cannot race past them. Each returns
// ErrNotFound for an unknown user and ErrRefused when the guard blocks the change.
type AccountRepository interface {
	// SetRoleGuarded changes a role, refusing an admin's own demotion and the demotion
	// of the last enabled admin.
	SetRoleGuarded(ctx context.Context, actorID, id string, role Role) error
	// SetDisabledGuarded disables or enables a user, refusing to disable oneself or the
	// last enabled admin.
	SetDisabledGuarded(ctx context.Context, actorID, id string, disabled bool) error
	// ClearTOTP removes a user's authenticator (secret, confirmed flag, last step), so
	// the account cannot sign in until it enrols again. An admin cannot clear their own.
	ClearTOTP(ctx context.Context, actorID, id string) error
	// EnabledAdmins counts enabled admin accounts.
	EnabledAdmins(ctx context.Context) (int, error)
}

// EnrolmentRepository stores one-time enrolment links (migration 0004).
type EnrolmentRepository interface {
	Create(ctx context.Context, e EnrolmentToken) error
	// ByHash returns used and expired tokens too; callers check UsedAt/ExpiresAt.
	ByHash(ctx context.Context, hash []byte) (EnrolmentToken, error)
	// Consume atomically marks the token used if it is unused and not expired at now,
	// and returns it; otherwise ErrNotFound. This is what makes links single-use.
	Consume(ctx context.Context, hash []byte, now time.Time) (EnrolmentToken, error)
	// InvalidateForUser marks every unused link of a user as used (superseded).
	InvalidateForUser(ctx context.Context, userID string, at time.Time) (int64, error)
	// Pending lists unused links that have not expired at now, newest first.
	Pending(ctx context.Context, now time.Time) ([]EnrolmentToken, error)
	// Prune deletes links that expired before the cutoff.
	Prune(ctx context.Context, before time.Time) (int64, error)
}

// AuditSearcher is the read side of the audit viewer.
type AuditSearcher interface {
	// Search returns up to f.Limit rows (1..MaxAuditPage) matching f, newest first.
	Search(ctx context.Context, f AuditFilter) ([]AuditRecord, error)
	// Actions lists the distinct actions recorded (for the filter control), sorted.
	Actions(ctx context.Context) ([]string, error)
}

var (
	_ AccountRepository   = accountRepo{}
	_ EnrolmentRepository = enrolmentRepo{}
	_ AuditSearcher       = auditRepo{}
)
