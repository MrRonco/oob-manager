package ui

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/console"
	"oob-manager/internal/display"
	"oob-manager/internal/secrets"
	"oob-manager/internal/settings"
	"oob-manager/internal/store"
)

// LogKind is a closed enum of the event logs the UI can show.
type LogKind string

// Log kinds.
const (
	LogSEL       LogKind = "sel"       // System Event Log
	LogLifecycle LogKind = "lifecycle" // Dell Lifecycle Controller log
)

func parseLogKind(s string) (LogKind, bool) {
	switch LogKind(s) {
	case "", LogSEL:
		return LogSEL, true
	case LogLifecycle:
		return LogLifecycle, true
	default:
		return "", false
	}
}

// ErrLogUnavailable is returned by Fleet.Events when the server has no such log (for
// example the Lifecycle log on a non-Dell BMC). Any other error is shown as a generic
// "could not be read" message; its text is never rendered.
var ErrLogUnavailable = errors.New("ui: log not available for this server")

// ServerView is what the UI reads about one configured server. It is a value: the Fleet
// adapter builds it from the poller's published (immutable) state, and the UI never
// modifies it. Zero-valued sections are flagged by the Has* fields.
type ServerView struct {
	ID   string // config ID; the only identifier that appears in URLs
	Name string // display name from config
	// Tags are the config tags (for example "critical"); a copy the UI may not modify.
	Tags []string

	Snapshot    bmc.Snapshot
	HasSnapshot bool
	// Previous is the successful snapshot before Snapshot, for the value-change cue on
	// the Sensors tab (plan 04 §11 item 5); HasPrevious is false until the second poll.
	Previous    bmc.Snapshot
	HasPrevious bool
	// LastSuccess is when the snapshot was taken (last successful poll); zero = never.
	LastSuccess time.Time
	// ErrorClass is the class of the most recent failed poll, "" when the last poll
	// succeeded. Only the class is shown, never BMC text.
	ErrorClass bmc.ErrorClass

	Inventory    bmc.Inventory
	HasInventory bool

	Capabilities    bmc.Capabilities
	HasCapabilities bool

	// LastPollDuration is how long the last snapshot read took (0: not polled yet).
	LastPollDuration time.Duration
	// StaleAfter is this server's own stale threshold; 0 uses Deps.StaleAfter.
	StaleAfter time.Duration
	// Slow poll tiers: when the kept value was read and whether its refresh is overdue.
	// The UI flags a section only when it is overdue.
	SELAsOf, LifecycleAsOf, InventoryAsOf          time.Time
	SELOverdue, LifecycleOverdue, InventoryOverdue bool
	// PinMismatch: the BMC's certificate no longer matches the pin, so polling is paused
	// until an admin confirms the new fingerprint (Settings → Servers).
	PinMismatch bool
	// PowerSince is when the host's current power state was first seen (zero: unknown,
	// it was already in that state at the first poll).
	PowerSince time.Time
	// PowerCause is the verified power action that explains the current power state
	// (zero: none). Snapshot.PowerAsOf is then newer than LastSuccess.
	PowerCause PowerCause
	// Restarting: the app waits for the BMC to come back after a restart it requested
	// (tech_doc §37); Restart is that window. Stale keeps its honest value.
	Restarting bool
	Restart    RestartWindow
}

// RestartWindow is an expected BMC restart: requested at Since by By, expected back by
// Until.
type RestartWindow struct {
	Since, Until time.Time
	By           string
}

// PowerCause is a verified power action: its slug (power.Action), the user and when
// the end state was observed.
type PowerCause struct {
	Action, By string
	At         time.Time
}

// Fleet is the read side of internal/fleet as the UI needs it. It must be safe for
// concurrent use and must never block on a BMC: Servers and Server read published
// snapshots; Events may read a cached log or call the driver with ctx's deadline.
type Fleet interface {
	// Servers returns every configured server in config order.
	Servers() []ServerView
	// Server returns one server by config ID.
	Server(id string) (ServerView, bool)
	// Events returns the requested log of server id, entries newest first. It returns
	// ErrLogUnavailable when the server has no such log.
	Events(ctx context.Context, id string, kind LogKind) (bmc.EventLog, error)
}

// Authenticator is the subset of *auth.Authenticator the UI uses.
type Authenticator interface {
	BeginLogin(ctx context.Context, r auth.LoginRequest) (string, error)
	CompleteLogin(ctx context.Context, pendingToken, code, ip, ua string) (string, auth.Session, error)
	Authenticate(ctx context.Context, token string) (auth.Identity, error)
	Logout(ctx context.Context, token string) error
	ConfirmTOTP(ctx context.Context, username, password, code, ip string) error
	StepUp(ctx context.Context, token, code string) (string, auth.Session, error)
	StepUpFresh(s auth.Session) bool
	StepUpExpires(s auth.Session) time.Time
	PendingUsername(ctx context.Context, token string) (string, bool)
	SessionCookieFor(token string, s auth.Session) *http.Cookie
}

// Admin is the settings slice S1 service (*admin.Service). Every change it makes is
// audited in the same transaction; the UI authorizes and step-up-checks before calling.
type Admin interface {
	Users(ctx context.Context) ([]admin.UserRow, error)
	User(ctx context.Context, id string) (admin.UserRow, error)
	Sessions(ctx context.Context, userID string) ([]admin.SessionRow, error)
	CreateUser(ctx context.Context, a admin.Actor, username string, role authz.Role) (admin.Link, error)
	SetRole(ctx context.Context, a admin.Actor, userID string, role authz.Role) error
	SetDisabled(ctx context.Context, a admin.Actor, userID string, disabled bool) error
	ResetEnrolment(ctx context.Context, a admin.Actor, userID string) (admin.Link, error)
	RevokeSession(ctx context.Context, a admin.Actor, userID, sid string) error
	RevokeSessions(ctx context.Context, a admin.Actor, userID string) (int64, error)
	Tokens(ctx context.Context) ([]admin.TokenRow, error)
	CreateToken(ctx context.Context, a admin.Actor, ownerID, name string, ttl time.Duration) (string, auth.APIToken, error)
	RevokeToken(ctx context.Context, a admin.Actor, id string) error
	LookupLink(ctx context.Context, raw string) (admin.LinkInfo, error)
	RedeemLink(ctx context.Context, raw, password, ip string) (auth.TOTPEnrollment, string, error)
}

// Settings is the runtime-managed settings service (*settings.Service, slice S2): the
// General section and each user's display preferences. Every change it makes is
// audited in the same transaction; the UI authorizes (and step-up-checks General)
// before calling.
type Settings interface {
	Current() settings.Effective
	PendingRestart() []string
	UpdateGeneral(ctx context.Context, a admin.Actor, rev int64, form map[string]string) ([]settings.Change, error)
	// ResetGeneral deletes a saved value so the key falls back to its default.
	ResetGeneral(ctx context.Context, a admin.Actor, rev int64, key string) ([]settings.Change, error)
	// View resolves a user's display preferences over the app defaults ("" = signed out).
	View(ctx context.Context, userID string) (display.View, error)
	Prefs(ctx context.Context, userID string) (display.Prefs, error)
	SetPrefs(ctx context.Context, a admin.Actor, p display.Prefs) ([]settings.Change, error)
}

// AuditLog is the read side of the audit chain for the viewer.
type AuditLog interface {
	Search(ctx context.Context, f store.AuditFilter) ([]store.AuditRecord, error)
	Actions(ctx context.Context) ([]string, error)
	// Verify walks the whole chain (audit.Verify).
	Verify(ctx context.Context) (audit.VerifyResult, error)
}

// Build describes the running binary for the About page and the footer. Version and
// RepoURL come from ldflags (main.version, main.repoURL); an empty RepoURL hides links.
type Build struct {
	Version   string
	Commit    string
	GoVersion string
	RepoURL   string
	Modules   []Module
	// SchemaVersion reports the database migration level; nil hides it.
	SchemaVersion func(ctx context.Context) (int, error)
}

// Module is one dependency compiled into the binary.
type Module struct{ Path, Version string }

// Enroller re-displays the TOTP secret of an account whose enrolment is not yet
// confirmed, after checking its password. internal/auth has no such method yet (see
// tech_doc §13); when Deps.Enroller is nil the enrolment page only confirms a secret the
// user got from the bootstrap command.
type Enroller interface {
	RevealEnrollment(ctx context.Context, username, password, ip string) (auth.TOTPEnrollment, error)
}

// Consoles is the graphical console broker (*console.Service).
type Consoles interface {
	Status(serverID string) console.Status
	Issue(g console.Grant) (string, error)
	Serve(ctx context.Context, ticket, serverID string, session [32]byte, conn net.Conn, check console.Watchdog) error
}

// SerialConsoles is the serial console broker (*console.SerialService).
type SerialConsoles interface {
	Status(serverID string) console.SerialStatus
	Issue(g console.Grant) (string, error)
	ServeSerial(ctx context.Context, ticket, serverID string, session [32]byte, peer console.SerialPeer,
		check console.Watchdog) error
}

// KVMLauncher opens a BMC's own HTML5 console with a one-time credential (Dell iDRAC9
// GetKVMSession). Available reports whether a launch is configured for the server (an
// operator credential exists); the BMC capability is checked separately.
type KVMLauncher interface {
	Available(serverID string) bool
	Launch(ctx context.Context, serverID string) (secrets.Secret, error)
}

// Auditor records security events. *audit.Logger satisfies it.
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) (store.AuditRecord, error)
}

// Defaults for Deps.
const (
	DefaultStaleAfter   = 3 * time.Minute // three missed 60 s polls (FR-3, FR-6)
	DefaultCSRFTTL      = 12 * time.Hour  // the session's absolute lifetime
	DefaultPageSize     = 50              // log entries per page
	DefaultAutoRefresh  = time.Minute     // overview and server pages (UI review F-03)
	DefaultStepUpWindow = 5 * time.Minute // auth.DefaultStepUpWindow
	defaultMaxKeys      = 4096            // per rate limiter
	minCSRFKeyLen       = 32
)

// Deps wires the UI. Auth, Fleet and Audit are required; the rest have defaults.
type Deps struct {
	Auth     Authenticator
	Enroller Enroller // optional
	// FirstRun is the first-run setup page and the generated-keys backup notice of a
	// store-style install (plan 09); nil hides both.
	FirstRun FirstRun
	Fleet    Fleet
	Audit    Auditor
	// Admin and AuditLog back the Settings area; when nil those pages answer 404.
	Admin    Admin
	AuditLog AuditLog
	Build    Build
	// PublicURL (config public_url) is the base of enrolment links; "" uses the
	// request's host.
	PublicURL string
	Logger    *slog.Logger
	Now       func() time.Time
	// Authorize is the authz decision; default authz.Authorize. Every handler calls it.
	Authorize func(p authz.Principal, a authz.Action, stepUpFresh bool) error
	// CSRFKey signs form tokens (≥ 32 bytes). Nil means a random per-process key, which
	// only invalidates open forms on restart.
	CSRFKey    []byte
	CSRFTTL    time.Duration
	StaleAfter time.Duration
	// PendingTTL is the lifetime of the cookie between password and TOTP; it should
	// match auth.Config.PendingTTL.
	PendingTTL time.Duration
	Location   *time.Location // for timestamps; default UTC
	PageSize   int
	// LoginPerIP and LoginPerAccount default to security.md §3: 5/min/IP, 10/h/account.
	LoginPerIP      RateLimit
	LoginPerAccount RateLimit
	// ChangesPerUser limits settings changes (default 10/min per user, security.md §3);
	// VerifyLimit the audit chain check (default 1/min, global); LinkPerIP the
	// enrolment-link pages (default 5/min per IP).
	ChangesPerUser RateLimit
	VerifyLimit    RateLimit
	LinkPerIP      RateLimit
	// AutoRefresh is the overview/server page refresh interval (default 60 s); a user
	// can turn it off (WCAG 2.2.1).
	AutoRefresh time.Duration

	// Consoles and KVM back the graphical console (P5); nil hides it.
	Consoles Consoles
	KVM      KVMLauncher
	// Serial backs the serial console (P4); nil hides it.
	Serial SerialConsoles
	// BMCWebURL returns a server's BMC web UI address for the "open the BMC UI" link
	// ("" hides it).
	BMCWebURL func(serverID string) string
	// ConsolePerUser limits console starts and KVM launches (default 10/min per user).
	ConsolePerUser RateLimit
	// CloseConsoleOnStepUpExpiry ends a console when the step-up window lapses.
	CloseConsoleOnStepUpExpiry bool
	// ConsoleIdle and ConsoleMax are the console limits shown on the page (config
	// console.idle_timeout and console.max_session; defaults 15 min and 4 h).
	ConsoleIdle, ConsoleMax time.Duration

	// Power runs host power actions (P2); nil leaves them disabled ("not in this version").
	Power Power
	// Fans is the fan lease service (P3); nil shows fan control as not set up.
	Fans Fans
	// BMCReset restarts a server's BMC (tech_doc §37); nil shows the BMC panel's action
	// as not set up and the confirm page answers 404.
	BMCReset BMCResets

	// InstanceName labels the installation in the header and on the sign-in page; with
	// Settings the live General value is used instead.
	InstanceName string
	// StepUpWindow is how long a step-up stays fresh (config auth.stepup_window), shown
	// on the step-up and confirm pages; default 5 minutes. With Settings it is read live.
	StepUpWindow time.Duration

	// Settings backs Settings → General and the per-user Display page; nil hides both
	// and renders every page in Location with the built-in display defaults.
	Settings Settings

	// Servers, Prober and Proofs back Settings → Servers (slice S3); without Servers the
	// pages answer 404. FingerprintPerUser and TestPerUser limit fingerprint fetches and
	// connection tests (default 6/min per user, security.md §3).
	Servers            ServerAdmin
	Prober             ServerProber
	Proofs             ProofSigner
	FingerprintPerUser RateLimit
	TestPerUser        RateLimit
	// Notifications backs Settings → Notifications and the Overview "notifications
	// failing" banner (tech_doc §26); nil hides both.
	Notifications Notifications
	// Maintenance backs maintenance mode, server notes and event acknowledgements
	// (tech_doc §28); nil hides all three.
	Maintenance Maintenance
	// Integrations backs Settings → Integrations (GELF audit shipping, tech_doc §34) and
	// the Overview "audit shipping paused" banner; it needs Settings too. nil hides both.
	// Hints are the file-only facts its dashboard snippets show.
	Integrations Integrations
	Hints        Hints
	// Security backs the BMC security check panel (tech_doc §31): the server Security tab
	// and the fleet table's Security column; nil hides both.
	Security Security
	// Firmware backs the read-only firmware view (tech_doc §38): /firmware, its sidebar
	// entry and the Inventory tab's Firmware section; nil hides them (the Inventory tab then
	// lists the poller's firmware items as before).
	Firmware Firmware
	// FirmwareUpdates backs the vendor update check's admin actions (plan 08): skipping one
	// component's newest release; nil hides the controls.
	FirmwareUpdates FirmwareUpdates
	// FirmwareCatalog backs the update check's Check now, upload and held-catalog
	// confirmation and the Settings panel; nil hides them.
	FirmwareCatalog FirmwareCatalog
	// History backs the sensor history (tech_doc §39): the History tab, the Hardware tab's
	// sparklines, the CSV export and the size line in Settings → General; nil hides them.
	History History
}

func (d Deps) withDefaults() Deps {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Authorize == nil {
		d.Authorize = authz.Authorize
	}
	if d.CSRFKey == nil {
		d.CSRFKey = []byte(randomToken())
	}
	d.CSRFTTL = orDur(d.CSRFTTL, DefaultCSRFTTL)
	d.StaleAfter = orDur(d.StaleAfter, DefaultStaleAfter)
	d.PendingTTL = orDur(d.PendingTTL, auth.DefaultPendingTTL)
	d.StepUpWindow = orDur(d.StepUpWindow, DefaultStepUpWindow)
	if d.Location == nil {
		d.Location = time.UTC
	}
	if d.PageSize <= 0 {
		d.PageSize = DefaultPageSize
	}
	if !d.LoginPerIP.valid() {
		d.LoginPerIP = RateLimit{Events: 5, Per: time.Minute}
	}
	if !d.LoginPerAccount.valid() {
		d.LoginPerAccount = RateLimit{Events: 10, Per: time.Hour}
	}
	d.ChangesPerUser = orRate(d.ChangesPerUser, RateLimit{Events: 10, Per: time.Minute})
	d.VerifyLimit = orRate(d.VerifyLimit, RateLimit{Events: 1, Per: time.Minute})
	d.LinkPerIP = orRate(d.LinkPerIP, RateLimit{Events: 5, Per: time.Minute})
	d.AutoRefresh = orDur(d.AutoRefresh, DefaultAutoRefresh)
	d.ConsolePerUser = orRate(d.ConsolePerUser, RateLimit{Events: 10, Per: time.Minute})
	d.FingerprintPerUser = orRate(d.FingerprintPerUser, RateLimit{Events: 6, Per: time.Minute})
	d.TestPerUser = orRate(d.TestPerUser, RateLimit{Events: 6, Per: time.Minute})
	d.ConsoleIdle = orDur(d.ConsoleIdle, 15*time.Minute)
	d.ConsoleMax = orDur(d.ConsoleMax, 4*time.Hour)
	if d.BMCWebURL == nil {
		d.BMCWebURL = func(string) string { return "" }
	}
	if d.Build.Version == "" {
		d.Build.Version = "dev"
	}
	return d
}

func (d Deps) validate() error {
	switch {
	case d.Auth == nil:
		return errors.New("ui: Deps.Auth is required")
	case d.Fleet == nil:
		return errors.New("ui: Deps.Fleet is required")
	case d.Audit == nil:
		return errors.New("ui: Deps.Audit is required")
	case len(d.CSRFKey) < minCSRFKeyLen:
		return fmt.Errorf("ui: Deps.CSRFKey must be at least %d bytes", minCSRFKeyLen)
	}
	return nil
}

func orRate(v, def RateLimit) RateLimit {
	if v.valid() {
		return v
	}
	return def
}

func orDur(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
