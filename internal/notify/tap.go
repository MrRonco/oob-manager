package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"oob-manager/internal/audit"
)

// Failed-login alerting: this many denied sign-in steps inside the window raise one
// warning; after an alert the class stays quiet for the cooldown.
const (
	FailedLoginThreshold = 5
	FailedLoginWindow    = 10 * time.Minute
	authCooldown         = 15 * time.Minute
)

// Tap turns audit records into events. It implements audit.Sink, so every recorded
// action (power, fan, console, sign-in, chain verification) passes through it after
// it is written; nothing outside the audit trail can raise these events. Enqueue never
// blocks.
type Tap struct {
	emit func(Event)
	name func(serverID string) string
	now  func() time.Time

	mu       sync.Mutex
	failures []time.Time          // denied sign-in steps inside the window
	quiet    map[string]time.Time // auth or trust event key → quiet until
	mismatch map[string]bool      // trust keys with an unresolved mismatch (trust.go)
}

// NewTap returns a tap that hands events to emit; name resolves a server's display name.
func NewTap(emit func(Event), name func(string) string, now func() time.Time) *Tap {
	if now == nil {
		now = time.Now
	}
	if name == nil {
		name = func(id string) string { return id }
	}
	return &Tap{emit: emit, name: name, now: now, quiet: map[string]time.Time{},
		mismatch: map[string]bool{}}
}

var _ audit.Sink = (*Tap)(nil)

// record is the part of an audit message the tap reads.
type record struct {
	action, result, class, server, principal, params string
}

func field(m audit.Message, k string) string {
	s, _ := m.Fields[k].(string)
	return s
}

// Enqueue implements audit.Sink.
func (t *Tap) Enqueue(m audit.Message) bool {
	r := record{action: field(m, "action"), result: field(m, "result"), class: field(m, "error_class"),
		server: field(m, "server_id"), principal: field(m, "principal"), params: field(m, "params")}
	if e, ok := t.translate(r); ok {
		t.emit(e)
	}
	return true
}

func (t *Tap) translate(r record) (Event, bool) {
	if e, ok := t.translateTrust(r); ok {
		return e, true
	}
	switch {
	case strings.HasPrefix(r.action, "power.") && r.action != "power.invalid":
		return t.power(r)
	case strings.HasPrefix(r.action, "fan.lease."):
		return t.fan(r)
	case r.action == "bmc.reset" || r.action == "bmc.reset.verified":
		return t.bmcReset(r)
	case strings.HasPrefix(r.action, "console."):
		return t.console(r)
	case strings.HasPrefix(r.action, "auth.") && r.result == audit.ResultDenied:
		return t.auth(r)
	case r.action == "admin.audit.verify" && r.result == audit.ResultError && r.class == "tampered":
		return AuditChainEvent("found by "+r.principal, t.now()), true
	case strings.HasPrefix(r.action, "server.security.") && r.result == audit.ResultOK:
		return t.security(r)
	case (r.action == "admin.integrations.update" || r.action == "admin.integrations.reset") && r.result == audit.ResultOK:
		return t.integrations(r), true
	}
	return Event{}, false
}

// securityParams is the part of an accept / unaccept audit row the tap reads: catalog
// text (the check ID and title), the admin's comment and the reason an acceptance ended.
type securityParams struct {
	Check   string `json:"check"`
	Title   string `json:"title"`
	Comment string `json:"comment"`
	Reason  string `json:"reason"`
}

// security raises a warning when an admin accepts a finding as a risk (it silences the
// finding and its notifications) and an info event when an acceptance ends, by an admin
// or by the watch pass. Re-runs and refusals raise nothing. The admin's comment is free
// text, so like BMC text it travels in Detail, which only targets that opted in receive.
func (t *Tap) security(r record) (Event, bool) {
	var p securityParams
	_ = json.Unmarshal([]byte(r.params), &p)
	what := orText(p.Title, p.Check)
	e := t.serverEvent(ClassSecurity, r)
	switch r.action {
	case "server.security.accept":
		e.Severity, e.Key = SeverityWarning, "security/accept/"+r.server+"/"+p.Check
		e.Title = "Accepted risk: " + what + " on " + e.ServerName
		e.Message = fmt.Sprintf("%s accepted the finding %q of %s as a risk. It no longer counts and is not notified while it stays the same.",
			r.principal, what, e.ServerName)
		e.Detail = []string{"Comment: " + orText(p.Comment, "none")}
	case "server.security.unaccept":
		e.Severity, e.Key = SeverityInfo, "security/unaccept/"+r.server+"/"+p.Check
		e.Title = "Accepted risk ended: " + what + " on " + e.ServerName
		e.Message = fmt.Sprintf("The acceptance of the finding %q of %s ended (%s, by %s). It counts and is notified again.",
			what, e.ServerName, orText(p.Reason, "removed"), r.principal)
	default:
		return Event{}, false
	}
	return e, true
}

// AuditChainEvent reports a broken audit hash chain (always critical). The startup
// verification calls it too.
func AuditChainEvent(how string, now time.Time) Event {
	return Event{ID: newEventID(), Class: ClassAudit, Severity: SeverityCritical, Key: "audit/chain", At: now,
		Title: "Audit log verification failed",
		Message: "The audit log's hash chain does not verify (" + how + "). Rows may have been changed or " +
			"removed. Open Settings → Audit log and keep a copy of the database before anything else."}
}

func (t *Tap) serverEvent(c Class, r record) Event {
	return Event{ID: newEventID(), Class: c, ServerID: r.server, ServerName: t.name(r.server),
		Key: string(c) + "/" + r.server, At: t.now()}
}

func (t *Tap) power(r record) (Event, bool) {
	what := strings.ReplaceAll(strings.TrimPrefix(r.action, "power."), "_", " ")
	e := t.serverEvent(ClassPower, r)
	switch r.result {
	case audit.ResultStarted:
		e.Severity = SeverityWarning
		e.Title = fmt.Sprintf("%s: power %s requested", e.ServerName, what)
		e.Message = fmt.Sprintf("%s requested power %s of %s.", r.principal, what, e.ServerName)
	case audit.ResultOK:
		e.Severity = SeverityInfo
		e.Title = fmt.Sprintf("%s: power %s done", e.ServerName, what)
		e.Message = fmt.Sprintf("Power %s of %s, requested by %s, completed.", what, e.ServerName, r.principal)
	case audit.ResultError:
		e.Severity = SeverityWarning
		e.Title = fmt.Sprintf("%s: power %s failed", e.ServerName, what)
		e.Message = fmt.Sprintf("Power %s of %s, requested by %s, failed (%s).", what, e.ServerName, r.principal,
			orText(r.class, "unknown"))
	default:
		return Event{}, false
	}
	return e, true
}

func (t *Tap) fan(r record) (Event, bool) {
	e := t.serverEvent(ClassFan, r)
	pct := leasePct(r.params)
	switch {
	case r.result == audit.ResultError:
		e.Severity = SeverityWarning
		e.Title = e.ServerName + ": fan lease action failed"
		e.Message = fmt.Sprintf("A fan lease action on %s failed (%s). The BMC's own fan control stays in charge.",
			e.ServerName, orText(r.class, "unknown"))
	case r.result != audit.ResultOK:
		return Event{}, false
	case r.action == "fan.lease.create":
		e.Severity = SeverityInfo
		e.Title = e.ServerName + ": fan lease started"
		e.Message = fmt.Sprintf("%s started a fan lease on %s%s.", r.principal, e.ServerName, pct)
	case r.action == "fan.lease.end", r.action == "fan.lease.expire":
		e.Severity = SeverityInfo
		e.Title = e.ServerName + ": fan lease ended"
		e.Message = fmt.Sprintf("The fan lease on %s ended%s; automatic fan control is back.", e.ServerName,
			map[bool]string{true: " (expired)", false: ""}[r.action == "fan.lease.expire"])
	default:
		return Event{}, false
	}
	return e, true
}

func leasePct(params string) string {
	var p struct {
		Pct *int `json:"pct"`
	}
	if json.Unmarshal([]byte(params), &p) != nil || p.Pct == nil {
		return ""
	}
	return fmt.Sprintf(" at %d %%", *p.Pct)
}

func (t *Tap) console(r record) (Event, bool) {
	var kind string
	switch {
	case r.action == "console.vnc.start" && r.result == audit.ResultStarted:
		kind = "graphical console session started"
	case r.action == "console.serial.start" && r.result == audit.ResultStarted:
		kind = "serial console session started"
	case r.action == "console.kvm_launch" && r.result == audit.ResultOK:
		kind = "native BMC console opened"
	case strings.HasSuffix(r.action, ".takeover") && r.result == audit.ResultOK:
		kind = "console session taken over"
	default:
		return Event{}, false
	}
	e := t.serverEvent(ClassConsole, r)
	e.Severity = SeverityWarning
	e.Title = e.ServerName + ": " + kind
	e.Message = fmt.Sprintf("%s: %s by %s. A console gives keyboard access to the host.", e.ServerName, kind, r.principal)
	return e, true
}

// auth raises a lockout warning (once per cooldown) and a failed sign-in warning when
// FailedLoginThreshold denials happen inside FailedLoginWindow.
func (t *Tap) auth(r record) (Event, bool) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if strings.HasSuffix(r.class, "_locked_out") {
		return t.quietEvent("auth/lockout", now, "Sign-in lockout",
			"Sign-in attempts are being refused by the lockout (too many failures for an account or address).", 0)
	}
	if r.class != "password" && r.class != "totp" {
		return Event{}, false
	}
	keep := t.failures[:0]
	for _, at := range t.failures {
		if now.Sub(at) < FailedLoginWindow {
			keep = append(keep, at)
		}
	}
	t.failures = append(keep, now)
	if len(t.failures) < FailedLoginThreshold {
		return Event{}, false
	}
	n := len(t.failures)
	t.failures = nil
	return t.quietEvent("auth/failures", now, "Repeated failed sign-ins",
		fmt.Sprintf("%d failed sign-in steps in the last %s.", n, FailedLoginWindow), n)
}

// quietEvent returns an auth event unless key is inside its cooldown; caller holds mu.
func (t *Tap) quietEvent(key string, now time.Time, title, msg string, n int) (Event, bool) {
	if until, ok := t.quiet[key]; ok && now.Before(until) {
		return Event{}, false
	}
	t.quiet[key] = now.Add(authCooldown)
	return Event{ID: newEventID(), Class: ClassAuth, Severity: SeverityWarning, Key: key, At: now,
		Title: title, Message: msg, Count: n}, true
}
