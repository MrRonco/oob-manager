package history

import (
	"slices"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/store"
)

// MarkKind is what an event marker on a chart stands for.
type MarkKind string

// Marker kinds.
const (
	MarkLog   MarkKind = "log"   // a warning or critical SEL / Lifecycle entry
	MarkPower MarkKind = "power" // a power action was requested
	MarkFan   MarkKind = "fan"   // a fan lease started, ended or expired
	MarkBMC   MarkKind = "bmc"   // a BMC restart was requested or came back
)

// MaxMarkers caps the markers of one chart; the rest are counted ("N more").
const MaxMarkers = 200

// Marker is one event drawn over a chart and repeated as text under it. Text of a log
// marker is BMC text: untrusted, rendered escaped.
type Marker struct {
	At       time.Time
	Kind     MarkKind
	Critical bool // a critical log entry (else a warning, or an app action)
	Text     string
	Log      string // the log name of a MarkLog ("System Event Log", "Lifecycle log")
	Acked    bool   // a log entry someone acknowledged
}

// Span is a maintenance window drawn as a shaded band.
type Span struct {
	From, To time.Time
	// Open: the window had not ended at the end of the range.
	Open bool
}

// Markers are the events of one chart.
type Markers struct {
	Marks []Marker
	Spans []Span
	// More counts markers beyond MaxMarkers (the oldest are dropped).
	More int
}

// Audit actions drawn as markers (fixed strings: maintenance and BMC restart actions
// are named by their services).
const (
	actionFanExpire   = "fan.lease.expire"
	actionBMCVerified = "bmc.reset.verified"
	actionMaintStart  = "server.maintenance.start"
	actionMaintEnd    = "server.maintenance.end"
)

// AuditActions are the audit actions of the overlay (a fresh slice, well under
// store.MaxAuditFilterActions).
func AuditActions() []string {
	return []string{string(authz.PowerOn), string(authz.PowerGracefulStop), string(authz.PowerGracefulRestart),
		string(authz.PowerForceOff), string(authz.PowerForceRestart), string(authz.PowerCycle),
		string(authz.FanLeaseCreate), string(authz.FanLeaseEnd), actionFanExpire,
		string(authz.BMCReset), actionBMCVerified, actionMaintStart, actionMaintEnd}
}

// LogEntry is a log entry offered to the overlay: the event, which log it came from and
// whether it was acknowledged.
type LogEntry struct {
	Event bmc.Event
	Log   string
	Acked bool
}

// FromLogs keeps warning and critical entries with a timestamp inside [from, to).
func FromLogs(entries []LogEntry, from, to time.Time) []Marker {
	var out []Marker
	for _, e := range entries {
		sev := e.Event.Severity
		if (sev != bmc.SeverityWarning && sev != bmc.SeverityCritical) || !inRange(e.Event.Created, from, to) {
			continue
		}
		out = append(out, Marker{At: e.Event.Created, Kind: MarkLog, Critical: sev == bmc.SeverityCritical,
			Text: e.Event.Message, Log: e.Log, Acked: e.Acked})
	}
	return out
}

func inRange(t, from, to time.Time) bool { return !t.IsZero() && !t.Before(from) && t.Before(to) }

// FromAudit turns the overlay's audit rows (any order) into markers and maintenance
// spans: power requests (started), fan lease starts, ends and expiries (ok), BMC restart
// requests (started) and their verification, and maintenance windows from their start
// and end rows. A window that started before the range starts at from; one still open
// at the end runs to to.
func FromAudit(recs []store.AuditRecord, from, to time.Time) ([]Marker, []Span) {
	sorted := slices.Clone(recs)
	slices.SortStableFunc(sorted, func(a, b store.AuditRecord) int { return a.TS.Compare(b.TS) })
	var (
		marks []Marker
		spans []Span
		open  *time.Time
	)
	for _, r := range sorted {
		switch {
		case r.Action == actionMaintStart && r.Result == string(audit.ResultOK):
			if open == nil {
				start := maxTime(r.TS, from)
				open = &start
			}
		case r.Action == actionMaintEnd && r.Result == string(audit.ResultOK):
			start := from
			if open != nil {
				start = *open
			}
			if end := minTime(r.TS, to); start.Before(end) {
				spans = append(spans, Span{From: start, To: end})
			}
			open = nil
		default:
			if m, ok := auditMarker(r); ok && inRange(r.TS, from, to) {
				marks = append(marks, m)
			}
		}
	}
	if open != nil && open.Before(to) {
		spans = append(spans, Span{From: *open, To: to, Open: true})
	}
	return marks, spans
}

// auditMarker is the marker of one overlay row, if it is one.
func auditMarker(r store.AuditRecord) (Marker, bool) {
	by := ""
	if r.Principal != "" && r.Principal != "system" {
		by = " by " + r.Principal
	}
	m := Marker{At: r.TS}
	switch {
	case r.Result == string(audit.ResultStarted) && isPower(r.Action):
		m.Kind, m.Text = MarkPower, powerLabel(r.Action)+" requested"+by
	case r.Action == string(authz.FanLeaseCreate) && r.Result == string(audit.ResultOK):
		m.Kind, m.Text = MarkFan, "Fan lease started"+by
	case r.Action == string(authz.FanLeaseEnd) && r.Result == string(audit.ResultOK):
		m.Kind, m.Text = MarkFan, "Fan lease ended"+by
	case r.Action == actionFanExpire:
		m.Kind, m.Text = MarkFan, "Fan lease expired"
	case r.Action == string(authz.BMCReset) && r.Result == string(audit.ResultStarted):
		m.Kind, m.Text = MarkBMC, "BMC restart requested"+by
	case r.Action == actionBMCVerified && r.Result == string(audit.ResultOK):
		m.Kind, m.Text = MarkBMC, "BMC back after its restart"
	case r.Action == actionBMCVerified:
		m.Kind, m.Text = MarkBMC, "BMC did not come back in time"
	default:
		return Marker{}, false
	}
	return m, true
}

func isPower(action string) bool { return powerLabel(action) != "" }

func powerLabel(action string) string {
	switch authz.Action(action) {
	case authz.PowerOn:
		return "Power on"
	case authz.PowerGracefulStop:
		return "Graceful shutdown"
	case authz.PowerGracefulRestart:
		return "Graceful restart"
	case authz.PowerForceOff:
		return "Force off"
	case authz.PowerForceRestart:
		return "Force restart"
	case authz.PowerCycle:
		return "Power cycle"
	default:
		return ""
	}
}

// Collect orders the markers oldest first and keeps the newest MaxMarkers.
func Collect(spans []Span, parts ...[]Marker) Markers {
	var all []Marker
	for _, p := range parts {
		all = append(all, p...)
	}
	slices.SortStableFunc(all, func(a, b Marker) int { return a.At.Compare(b.At) })
	more := 0
	if len(all) > MaxMarkers {
		more = len(all) - MaxMarkers
		all = all[more:]
	}
	return Markers{Marks: all, Spans: spans, More: more}
}
