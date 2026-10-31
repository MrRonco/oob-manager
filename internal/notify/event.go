// Package notify turns state changes the app already observes (poller state, audit
// records) into outbound notifications: ntfy, Pushover, Gotify, a generic signed
// webhook and SMTP email (docs/tech_doc.md §26).
//
// Safety properties (docs/security.md §3e):
//   - every destination passes an SSRF policy: https only (http only for an explicitly
//     allowed LAN network), the host is resolved once and the checked IP is the one
//     dialled, redirects are never followed, responses are capped and discarded;
//   - target secrets are sealed at rest (AES-GCM, AAD bound to target id, kind and
//     URL), never rendered, logged or audited;
//   - messages carry the server name, the signal and the severity; BMC-supplied event
//     text is included only for targets that opted in.
package notify

import (
	"fmt"
	"slices"
	"time"
)

// Class is a closed enum of event classes. Subscriptions select classes by name.
type Class string

// Event classes.
const (
	ClassHealth       Class = "health"       // server health verdict changes
	ClassReachability Class = "reachability" // BMC unreachable / data stale, and recovered
	ClassSEL          Class = "sel"          // new warning/critical SEL or Lifecycle entries
	ClassPSU          Class = "psu"          // PSU redundancy lost / restored
	ClassFan          Class = "fan"          // fan lease started / ended / failed
	ClassPower        Class = "power"        // power action requested / succeeded / failed
	ClassBMC          Class = "bmc"          // BMC restart requested / back / failed / timed out (tech_doc §37)
	ClassConsole      Class = "console"      // console session started (graphical, serial)
	ClassAuth         Class = "auth"         // login lockout, repeated failed logins
	ClassAudit        Class = "audit"        // audit chain verification failure
	ClassTrust        Class = "trust"        // certificate / host key mismatch (TOFU)
	ClassNotify       Class = "notify"       // a notification target keeps failing (self-alert)
	ClassMaintenance  Class = "maintenance"  // maintenance mode started or ended (not subscribable, see Target.Wants)
	ClassSecurity     Class = "security"     // new BMC security check findings, certificate expiry (tech_doc §31)
	ClassFirmware     Class = "firmware"     // new vendor firmware updates, a failing update check (plan 08)
	ClassTest         Class = "test"         // "Send test" from Settings
)

// Classes returns every subscribable class in display order (a fresh slice). ClassTest
// is not subscribable: a test goes to the one target it was sent from.
func Classes() []Class {
	return []Class{ClassHealth, ClassReachability, ClassSEL, ClassPSU, ClassFan, ClassPower, ClassBMC,
		ClassConsole, ClassAuth, ClassAudit, ClassTrust, ClassSecurity, ClassFirmware, ClassNotify}
}

// ParseClass validates a class name exactly.
func ParseClass(s string) (Class, error) {
	c := Class(s)
	if slices.Contains(Classes(), c) {
		return c, nil
	}
	return "", fmt.Errorf("notify: unknown event class %q", s)
}

// Label is the class as shown in the UI.
func (c Class) Label() string {
	switch c {
	case ClassHealth:
		return "Server health"
	case ClassReachability:
		return "BMC unreachable or stale"
	case ClassSEL:
		return "New warning or critical log entries"
	case ClassPSU:
		return "Power supply redundancy"
	case ClassFan:
		return "Fan leases"
	case ClassPower:
		return "Power actions"
	case ClassBMC:
		return "BMC restarts"
	case ClassConsole:
		return "Console sessions started"
	case ClassAuth:
		return "Login lockouts and failed logins"
	case ClassAudit:
		return "Audit chain verification failure"
	case ClassTrust:
		return "Certificate or host key mismatch"
	case ClassNotify:
		return "Another notification target failing"
	case ClassMaintenance:
		return "Maintenance mode started or ended"
	case ClassSecurity:
		return "BMC security check findings"
	case ClassFirmware:
		return "New firmware updates"
	case ClassTest:
		return "Test"
	default:
		return string(c)
	}
}

// Mutable reports whether a server's maintenance window suppresses the class.
// Security-relevant classes (power, BMC restarts, console, fan, auth, audit, trust) are never
// suppressed: maintenance is planned work, and planned work must still leave a trail.
func (c Class) Mutable() bool {
	switch c {
	case ClassHealth, ClassReachability, ClassSEL, ClassPSU:
		return true
	default:
		return false
	}
}

// Severity orders events. Recovery messages carry the severity of the problem they
// resolve, so a target that received the problem also receives its recovery.
type Severity int

// Severities, lowest first.
const (
	SeverityInfo Severity = iota + 1
	SeverityWarning
	SeverityCritical
)

// Severities returns every severity, lowest first.
func Severities() []Severity { return []Severity{SeverityInfo, SeverityWarning, SeverityCritical} }

// ParseSeverity validates a severity name exactly.
func ParseSeverity(s string) (Severity, error) {
	for _, v := range Severities() {
		if v.String() == s {
			return v, nil
		}
	}
	return 0, fmt.Errorf("notify: unknown severity %q", s)
}

// String is the wire and form name.
func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "info"
	case SeverityWarning:
		return "warning"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Event is one notification-worthy change. It is a value; detectors build it and the
// dispatcher renders it per target. Detail is BMC-supplied text (SEL messages): it is
// untrusted and only sent to targets with IncludeDetail.
type Event struct {
	ID         string // random, unique per event (webhook "id", dedupe in receivers)
	Class      Class
	Severity   Severity
	Recovery   bool
	ServerID   string // "" for app-wide events
	ServerName string
	// Key identifies the signal for deduplication (for example "health/r1").
	Key     string
	Title   string // one line, no BMC text
	Message string // a sentence or two, no BMC text, no addresses or serials
	Detail  []string
	Count   int // for aggregated events (new log entries, failed logins)
	At      time.Time
	// ExcludeTarget skips one target (the self-alert is not sent to the failing target).
	ExcludeTarget string
}

// quiet reports events sent at normal priority whatever their severity: recoveries, tests,
// maintenance start/end messages and security check findings (a weekly-digest kind of
// news: it never pages).
func (e Event) quiet() bool {
	return e.Recovery || e.Class == ClassTest || e.Class == ClassMaintenance || e.Class == ClassSecurity ||
		e.Class == ClassFirmware
}

// withDetail returns e with Detail dropped unless include is set.
func (e Event) withDetail(include bool) Event {
	if !include {
		e.Detail = nil
		return e
	}
	e.Detail = slices.Clone(e.Detail)
	return e
}
