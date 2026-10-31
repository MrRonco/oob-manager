package store

import (
	"errors"
	"time"
)

// Sentinel errors. Repositories wrap them; test with errors.Is.
var (
	// ErrNotFound means no row matched.
	ErrNotFound = errors.New("store: not found")
	// ErrConflict means a uniqueness rule or compare-and-set precondition failed.
	ErrConflict = errors.New("store: conflict")
	// ErrInvalid means the value violates a schema rule (CHECK, foreign key, required field).
	ErrInvalid = errors.New("store: invalid value")
)

// Role is an application role (authz decides what each may do).
type Role string

// Roles.
const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r == RoleViewer || r == RoleOperator || r == RoleAdmin }

// User is a local account. TOTPSecretEnc is ciphertext (app key), never plaintext.
type User struct {
	ID            string
	Username      string
	Email         string // optional
	Role          Role
	PwHash        string
	TOTPSecretEnc []byte
	TOTPConfirmed bool // enrollment proven with a valid code (migration 0002)
	TOTPLastStep  int64
	Disabled      bool
	CreatedAt     time.Time
}

// SessionLevel is how far a session got through login (migration 0002).
type SessionLevel int

// Session levels. A zero Level is stored as SessionPending (fail closed).
const (
	SessionPending SessionLevel = 1 // password ok, TOTP outstanding
	SessionFull    SessionLevel = 2 // password + TOTP
)

// Session is a server-side session, keyed by the hash of the cookie value.
type Session struct {
	IDHash    []byte
	UserID    string
	Level     SessionLevel
	CreatedAt time.Time
	LastSeen  time.Time
	StepUpAt  time.Time // zero = never stepped up
	IP        string
	UA        string
}

// TokenScope is an API token scope. Only read exists (security.md S4).
type TokenScope string

// ScopeRead is the only token scope.
const ScopeRead TokenScope = "read"

// APIToken is a read-only bearer token, stored hashed.
type APIToken struct {
	ID         string
	Name       string
	TokenHash  []byte
	Scope      TokenScope
	CreatedBy  string
	CreatedAt  time.Time
	LastUsedAt time.Time // zero = never used
	RevokedAt  time.Time // zero = active
	ExpiresAt  time.Time // zero = never expires (migration 0003)
}

// LockoutState is a login failure counter (migration 0002).
type LockoutState struct {
	Failures    int
	LastFailure time.Time
}

// Revoked reports whether the token has been revoked.
func (t APIToken) Revoked() bool { return !t.RevokedAt.IsZero() }

// ExpiredAt reports whether the token has expired at now (the expiry instant is excluded).
func (t APIToken) ExpiredAt(now time.Time) bool {
	return !t.ExpiresAt.IsZero() && !now.Before(t.ExpiresAt)
}

// AuditRecord is one row of the hash-chained audit log. The audit package computes
// PrevHash/RowHash; the store only enforces sequence continuity and append-only.
type AuditRecord struct {
	Seq           int64
	TS            time.Time
	CorrelationID string
	Principal     string
	AuthMethod    string
	Role          string
	SrcIP         string
	ServerID      string
	Action        string
	ParamsJSON    string
	Result        string
	BMCStatus     string
	ErrorClass    string
	PrevHash      string
	RowHash       string
}

// LeaseMode is how a fan lease relates to the curve.
type LeaseMode string

// Lease modes.
const (
	LeaseBoost LeaseMode = "boost"
	LeasePin   LeaseMode = "pin"
)

// LeaseState is the lease lifecycle state.
type LeaseState string

// Lease states. Pending and Applied are "active"; the rest are terminal.
const (
	LeasePending  LeaseState = "pending"
	LeaseApplied  LeaseState = "applied"
	LeaseEnded    LeaseState = "ended"
	LeaseExpired  LeaseState = "expired"
	LeaseRejected LeaseState = "rejected"
)

// Active reports whether the state is non-terminal.
func (s LeaseState) Active() bool { return s == LeasePending || s == LeaseApplied }

// Valid reports whether s is a known state.
func (s LeaseState) Valid() bool {
	return s.Active() || s == LeaseEnded || s == LeaseExpired || s == LeaseRejected
}

// FanLease is a persisted fan override. OriginalValue (with HasOriginal) is the BMC
// value to restore on expiry (redfish-floor mode).
type FanLease struct {
	LeaseID       string
	ServerID      string
	Mode          LeaseMode
	Pct           int
	IssuedAt      time.Time
	ExpiresAt     time.Time
	RequestedBy   string
	State         LeaseState
	OriginalValue int
	HasOriginal   bool
	UpdatedAt     time.Time
}

// Capability is the latest probe result for a server, as JSON.
type Capability struct {
	ServerID string
	ProbedAt time.Time
	JSON     string
}

// ErrRefused means a guarded change would break an invariant (the last enabled admin,
// or an admin changing their own account); nothing was written.
var ErrRefused = errors.New("store: refused by invariant")

// EnrolPurpose is why an enrolment link was issued.
type EnrolPurpose string

// Enrolment purposes (migration 0004).
const (
	EnrolPurposeEnrol EnrolPurpose = "enrol" // a new account
	EnrolPurposeReset EnrolPurpose = "reset" // an admin-forced authenticator re-enrolment
)

// Valid reports whether p is a known purpose.
func (p EnrolPurpose) Valid() bool { return p == EnrolPurposeEnrol || p == EnrolPurposeReset }

// EnrolmentToken is a one-time link, stored as the SHA-256 of its secret part.
type EnrolmentToken struct {
	ID        string
	UserID    string
	TokenHash []byte
	Purpose   EnrolPurpose
	CreatedBy string
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    time.Time // zero = unused; also set when a newer link supersedes it
}

// AuditFilter selects audit rows for the viewer. Empty strings match anything;
// BeforeSeq 0 means "from the newest row". Results are newest first.
type AuditFilter struct {
	Action    string
	Principal string
	ServerID  string
	Result    string
	BeforeSeq int64
	Limit     int
	// Actions matches any of these actions (at most MaxAuditFilterActions; the history's
	// event overlay); Since keeps rows at or after it (zero: no bound).
	Actions []string
	Since   time.Time
	// Matches keeps only rows equal to one of these action and result pairs (at most
	// MaxAuditFilterMatches; the Activity pages, round-2 slice C).
	Matches []AuditMatch
}

// AuditMatch is one action with one result.
type AuditMatch struct {
	Action, Result string
}
