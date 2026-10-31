// Package authz is the single permission matrix of oob-manager: roles (PRD §2) × actions
// (tech_doc §6). Everything not listed is denied. API tokens are read-only by type: no
// code path maps a token to an operator or admin action, whatever role it carries.
//
// The matrix is expressed as switch statements rather than a package-level map so there
// is no mutable package state to tamper with.
package authz

import (
	"errors"
	"fmt"
)

// Role is a user role from PRD §2.
type Role string

// Roles, lowest to highest privilege.
const (
	RoleViewer   Role = "viewer"
	RoleOperator Role = "operator"
	RoleAdmin    Role = "admin"
)

// Kind is how a principal authenticated.
type Kind string

// Principal kinds.
const (
	KindSession Kind = "session" // browser session (password + TOTP)
	KindToken   Kind = "token"   // API bearer token, read-only by type
)

// Principal is who is asking. It is a value type; callers build it from the
// authenticated session or token.
type Principal struct {
	Kind Kind
	Role Role
}

// Action is a closed enum of everything the app can do.
type Action string

// Actions. Names are stable: they are written to the audit log.
const (
	ViewFleet            Action = "fleet.view"
	ViewServer           Action = "server.view"
	ViewLogs             Action = "server.logs.view"
	ViewInventory        Action = "server.inventory.view"
	ViewFan              Action = "server.fan.view"
	ViewOwnAudit         Action = "audit.own.view"
	PowerOn              Action = "power.on"
	PowerGracefulStop    Action = "power.graceful_shutdown"
	PowerGracefulRestart Action = "power.graceful_restart"
	PowerForceOff        Action = "power.force_off"
	PowerForceRestart    Action = "power.force_restart"
	PowerCycle           Action = "power.cycle"
	FanLeaseCreate       Action = "fan.lease.create"
	FanLeaseEnd          Action = "fan.lease.end"
	// ConsoleSerial opens a BMC serial console (text console of the host: BIOS, boot
	// loader, OS login). Like the graphical console it is equivalent to physical access.
	ConsoleSerial Action = "console.serial"
	// ConsoleSerialTakeover ends another user's serial console and starts one.
	ConsoleSerialTakeover Action = "console.serial.takeover"
	ConsoleVNC            Action = "console.vnc"
	// ConsoleVNCTakeover ends another user's graphical console and starts one (it is
	// equivalent to physical access, like ConsoleVNC).
	ConsoleVNCTakeover Action = "console.vnc.takeover"
	ConsoleKVMLaunch   Action = "console.kvm_launch"
	AdminAudit         Action = "admin.audit.view"
	AdminAuditVerify   Action = "admin.audit.verify"
	AdminAuditExport   Action = "admin.audit.export"
	// AdminUsers and AdminTokens are the read-only settings pages (lists). Every change goes
	// through the matching *Manage action, which also needs a fresh step-up.
	AdminUsers        Action = "admin.users"
	AdminTokens       Action = "admin.tokens"
	AdminUsersManage  Action = "admin.users.manage"
	AdminTokensManage Action = "admin.tokens.manage"
	AboutView         Action = "about.view"
	// AdminGeneral is the read-only Settings → General page; AdminGeneralManage changes
	// it (step-up required, settings_design.md §3).
	AdminGeneral       Action = "admin.general.view"
	AdminGeneralManage Action = "admin.general.manage"
	// UserPrefs is a signed-in user changing their own display preferences (time zone,
	// theme, formats). Low risk: no step-up, sessions only, but audited.
	UserPrefs Action = "user.prefs"
	// AdminServers is the read-only Settings → Servers pages; AdminServersManage adds,
	// edits, enables, disables and removes servers, stores credentials, confirms
	// fingerprints and runs Test connection (step-up required, settings_design.md §3).
	AdminServers       Action = "admin.servers.view"
	AdminServersManage Action = "admin.servers.manage"
	// AdminNotifications is the read-only Settings → Notifications page;
	// AdminNotificationsManage adds, edits, deletes and tests targets (step-up required).
	// ServerMaintenance starts, schedules and ends a server's maintenance window
	// (operator, no step-up: it only pauses health-type notifications, never security
	// ones, and is audited). ServerNotes writes notes (add, edit or delete one's own,
	// pin any); ServerNotesModerate deletes anyone's note (admin). EventAck acknowledges
	// and un-acknowledges BMC log entries (operator, audited).
	AdminNotifications       Action = "admin.notifications.view"
	AdminNotificationsManage Action = "admin.notifications.manage"
	// AdminIntegrations is the read-only Settings → Integrations page (GELF state and the
	// dashboard hints); AdminIntegrationsManage changes the GELF target, fetches and
	// confirms its certificate and sends a test frame (step-up required, tech_doc §34).
	AdminIntegrations       Action = "admin.integrations.view"
	AdminIntegrationsManage Action = "admin.integrations.manage"
	ServerMaintenance       Action = "server.maintenance"
	ServerNotes             Action = "server.notes.write"
	ServerNotesModerate     Action = "server.notes.moderate"
	EventAck                Action = "server.event.ack"
	// SecurityView shows the BMC security check findings (a viewer sees only the summary:
	// the findings describe weaknesses of the BMC). SecurityRerun runs the checks now (a BMC
	// read; rate-limited; admin, no step-up). SecurityAccept accepts a finding as a risk or
	// takes that back: it silences a finding and its notifications, so like every other
	// admin change it needs a fresh step-up. Neither writes to a BMC.
	SecurityView   Action = "server.security.view"
	SecurityRerun  Action = "server.security.rerun"
	SecurityAccept Action = "server.security.accept"
	// BMCReset restarts a server's BMC (Manager.Reset, GracefulRestart; tech_doc §37):
	// every console on the server closes and monitoring is blind for minutes, the same
	// class as a forced power action. Admin, fresh step-up, sessions only.
	BMCReset Action = "bmc.reset"
	// ViewFirmware shows the firmware view (/firmware, the Inventory section, the API) and
	// ExportFirmware its CSV: both are reads of versions, like the inventory (viewer;
	// tokens too). FirmwareRescan asks the poller to read the firmware inventory now: a
	// BMC read on demand (operator, sessions only, rate-limited, audited, no step-up).
	// Nothing here updates firmware (CLAUDE.md rule 11; tech_doc §38).
	ViewFirmware   Action = "server.firmware.view"
	ExportFirmware Action = "server.firmware.export"
	FirmwareRescan Action = "server.firmware.rescan"
	// FirmwareSkipUpdate skips one component's newest vendor release, or takes that
	// back (plan 08 §12): it silences an update flag and its notification, so like
	// SecurityAccept it is an admin change with a fresh step-up, sessions only. It writes
	// nothing to a BMC.
	FirmwareSkipUpdate Action = "server.firmware.skip_update"
	// FirmwareCatalogCheck asks for an online check of the vendor catalog now (operator,
	// sessions only, one per 5 minutes globally); FirmwareCatalogUpload imports a catalog
	// file or confirms a held one (admin, fresh step-up). Neither reaches a BMC (plan 08).
	FirmwareCatalogCheck  Action = "firmware.catalog.check"
	FirmwareCatalogUpload Action = "firmware.catalog.upload"
	// ViewHistory shows a server's sensor history (the History tab, its sparklines and
	// the API series) and ExportHistory its CSV of one sensor: the same readings the
	// pages show, over time (viewer; tokens too). ExportHistoryAll exports every sensor
	// of a server at once, the largest export (operator, sessions only: tokens stay
	// viewer-level reads; they export one sensor per request). Nothing here reaches a BMC
	// (tech_doc §39).
	ViewHistory      Action = "server.history.view"
	ExportHistory    Action = "server.history.export"
	ExportHistoryAll Action = "server.history.export_all"
)

// Errors returned by Authorize.
var (
	ErrForbidden      = errors.New("authz: forbidden")
	ErrStepUpRequired = errors.New("authz: step-up required")
)

// Actions returns every known action (a fresh slice each call).
func Actions() []Action {
	return []Action{
		ViewFleet, ViewServer, ViewLogs, ViewInventory, ViewFan, ViewOwnAudit,
		PowerOn, PowerGracefulStop, PowerGracefulRestart,
		PowerForceOff, PowerForceRestart, PowerCycle,
		FanLeaseCreate, FanLeaseEnd,
		ConsoleSerial, ConsoleSerialTakeover, ConsoleVNC, ConsoleVNCTakeover, ConsoleKVMLaunch,
		AdminAudit, AdminAuditVerify, AdminAuditExport, AdminUsers, AdminTokens,
		AdminUsersManage, AdminTokensManage, AboutView, AdminGeneral, AdminGeneralManage, UserPrefs,
		AdminServers, AdminServersManage,
		AdminNotifications, AdminNotificationsManage, AdminIntegrations, AdminIntegrationsManage,
		ServerMaintenance, ServerNotes, ServerNotesModerate, EventAck,
		SecurityView, SecurityRerun, SecurityAccept, BMCReset,
		ViewFirmware, ExportFirmware, FirmwareRescan, FirmwareSkipUpdate, FirmwareCatalogCheck, FirmwareCatalogUpload,
		ViewHistory, ExportHistory, ExportHistoryAll,
	}
}

// ParseRole validates a role string exactly (no case folding, no trimming).
func ParseRole(s string) (Role, error) {
	r := Role(s)
	if rank(r) == 0 {
		return "", fmt.Errorf("authz: unknown role %q", s)
	}
	return r, nil
}

// Allowed reports whether p may perform a. Unknown roles, kinds and actions are denied.
func Allowed(p Principal, a Action) bool {
	need, ok := minRole(a)
	if !ok {
		return false
	}
	have := rank(p.Role)
	if have == 0 || have < rank(need) {
		return false
	}
	switch p.Kind {
	case KindSession:
		return true
	case KindToken:
		return tokenReadable(a)
	default:
		return false
	}
}

// RequiresStepUp reports whether a needs a fresh TOTP (security.md §3). Unknown actions
// return true so a forgotten entry fails closed.
func RequiresStepUp(a Action) bool {
	switch a {
	case PowerOn, PowerGracefulStop, PowerGracefulRestart,
		PowerForceOff, PowerForceRestart, PowerCycle,
		FanLeaseCreate, ConsoleSerial, ConsoleSerialTakeover, ConsoleVNC, ConsoleVNCTakeover, ConsoleKVMLaunch,
		AdminUsersManage, AdminTokensManage, AdminGeneralManage, AdminServersManage,
		AdminNotificationsManage, AdminIntegrationsManage, SecurityAccept, BMCReset, FirmwareSkipUpdate,
		FirmwareCatalogUpload:
		return true
	}
	_, known := minRole(a)
	return !known
}

// Authorize combines Allowed and the step-up rule. stepUpFresh is whether the session
// completed a TOTP step-up inside the configured window.
func Authorize(p Principal, a Action, stepUpFresh bool) error {
	if !Allowed(p, a) {
		return ErrForbidden
	}
	if RequiresStepUp(a) && !stepUpFresh {
		return ErrStepUpRequired
	}
	return nil
}

// rank orders roles; 0 means unknown.
func rank(r Role) int {
	switch r {
	case RoleViewer:
		return 1
	case RoleOperator:
		return 2
	case RoleAdmin:
		return 3
	default:
		return 0
	}
}

// minRole is the matrix: the lowest role allowed to perform a.
func minRole(a Action) (Role, bool) {
	switch a {
	case ViewFleet, ViewServer, ViewLogs, ViewInventory, ViewFan, ViewOwnAudit, AboutView, UserPrefs,
		ViewFirmware, ExportFirmware, ViewHistory, ExportHistory:
		return RoleViewer, true
	case PowerOn, PowerGracefulStop, PowerGracefulRestart,
		FanLeaseCreate, FanLeaseEnd, ServerMaintenance, ServerNotes, EventAck, SecurityView, FirmwareRescan, FirmwareCatalogCheck,
		ExportHistoryAll:
		return RoleOperator, true
	case PowerForceOff, PowerForceRestart, PowerCycle,
		ConsoleSerial, ConsoleSerialTakeover, ConsoleVNC, ConsoleVNCTakeover, ConsoleKVMLaunch,
		AdminAudit, AdminAuditVerify, AdminAuditExport, AdminUsers, AdminTokens,
		AdminUsersManage, AdminTokensManage, AdminGeneral, AdminGeneralManage,
		AdminServers, AdminServersManage, AdminNotifications, AdminNotificationsManage, ServerNotesModerate,
		AdminIntegrations, AdminIntegrationsManage,
		SecurityRerun, SecurityAccept, BMCReset, FirmwareSkipUpdate, FirmwareCatalogUpload:
		return RoleAdmin, true
	default:
		return "", false
	}
}

// tokenReadable lists what an API token may do: fleet and per-server reads only.
// "Own audit" has no meaning for a machine token.
func tokenReadable(a Action) bool {
	switch a {
	case ViewFleet, ViewServer, ViewLogs, ViewInventory, ViewFan, ViewFirmware, ExportFirmware,
		ViewHistory, ExportHistory:
		return true
	default:
		return false
	}
}
