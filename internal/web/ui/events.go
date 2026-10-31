package ui

import (
	"cmp"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"oob-manager/internal/bmc"
)

type option struct {
	Value, Label string
	Selected     bool
}

type countChip struct {
	Class, Label, Href string
	N                  int
}

type eventsView struct {
	Rows     []eventRow
	Pager    pagerView
	Total    string
	Counts   []countChip
	Hidden   string // "1 info entry hidden by the severity filter"
	AllHref  string
	Servers  []option
	Logs     []option
	Severity []option
	Ranges   []option
	Query    string
	Notes    []string // logs that could not be read, by server
	Zone     string
	// Ack offers Acknowledge on the rows (nil: not allowed). With one server selected,
	// AckAll lists the refs of its unacknowledged warning and critical rows shown.
	Ack    *ackForm
	AckAll *ackAllView
}

// eventFilter is the validated query of /events: closed enums, a configured server ID
// and a short printable search text. Defaults: warning and worse, last 7 days (UX-05).
type eventFilter struct {
	server, log, severity, rng, q string
	page                          int
}

var (
	eventLogs       = []string{"all", "sel", "lifecycle"}
	eventSeverities = []string{"warning", "all", "critical"}
	eventRanges     = map[string]time.Duration{"24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour, "all": 0}
)

const maxEventQuery = 64

func (s *server) parseEventFilter(q url.Values) (eventFilter, bool) {
	f := eventFilter{server: q.Get("server"), log: cmp.Or(q.Get("log"), "all"),
		severity: cmp.Or(q.Get("severity"), "warning"), rng: cmp.Or(q.Get("range"), "7d"), q: strings.TrimSpace(q.Get("q"))}
	page, ok := parsePage(q.Get("page"))
	f.page = page
	_, rangeOK := eventRanges[f.rng]
	switch {
	case !ok, !rangeOK, !slices.Contains(eventLogs, f.log), !slices.Contains(eventSeverities, f.severity),
		len(f.q) > maxEventQuery, strings.ContainsFunc(f.q, func(r rune) bool { return !unicode.IsPrint(r) }):
		return eventFilter{}, false
	}
	if f.server != "" {
		if _, known := s.d.Fleet.Server(f.server); !serverIDPattern.MatchString(f.server) || !known {
			return eventFilter{}, false
		}
	}
	return f, true
}

// href keeps every non-default value, so links and the pager preserve the filter.
func (f eventFilter) href(page int) string {
	q := url.Values{}
	for k, v := range map[string][2]string{"server": {f.server, ""}, "log": {f.log, "all"},
		"severity": {f.severity, "warning"}, "range": {f.rng, "7d"}, "q": {f.q, ""}} {
		if v[0] != v[1] {
			q.Set(k, v[0])
		}
	}
	if page > 1 {
		q.Set("page", strconv.Itoa(page))
	}
	if len(q) == 0 {
		return "/events"
	}
	return "/events?" + q.Encode()
}

func (f eventFilter) kinds() []LogKind {
	switch f.log {
	case "sel":
		return []LogKind{LogSEL}
	case "lifecycle":
		return []LogKind{LogLifecycle}
	default:
		return []LogKind{LogSEL, LogLifecycle}
	}
}

func (f eventFilter) keepSeverity(sev bmc.Severity) bool {
	switch f.severity {
	case "critical":
		return sev == bmc.SeverityCritical
	case "warning":
		return isProblem(sev)
	default:
		return true
	}
}

// keepScope applies range and text, everything but severity (the count chips use it).
func (f eventFilter) keepScope(e fleetEvent, now time.Time) bool {
	if d := eventRanges[f.rng]; d > 0 && (e.Event.Created.IsZero() || e.Event.Created.Before(now.Add(-d))) {
		return false
	}
	return f.q == "" || strings.Contains(strings.ToLower(e.Event.Message+" "+e.Event.MessageID), strings.ToLower(f.q))
}

// eventsPage is the fleet-wide event stream: the cached SEL and Lifecycle logs of every
// server merged, repeats folded, newest first by BMC timestamp. It never causes BMC traffic.
func (s *server) eventsPage(w http.ResponseWriter, r *http.Request, sess session) {
	f, ok := s.parseEventFilter(r.URL.Query())
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "Unknown server, log, severity, range, search text or page number.")
		return
	}
	views := s.d.Fleet.Servers()
	if f.server != "" {
		v, _ := s.d.Fleet.Server(f.server)
		views = []ServerView{v}
	}
	all, notes := s.fleetEvents(r.Context(), views, f.kinds())
	scoped, shown := s.filterEvents(all, f)
	p, pages, lo, hi := pageBounds(f.page, s.d.PageSize, len(shown))
	if p != f.page {
		redirectLocal(w, r, f.href(p))
		return
	}
	v := s.eventsViewOf(f, scoped, shown, sess.tf())
	v.Rows, v.Notes, v.Pager = s.fleetRows(shown[lo:hi], true, sess.tf()), notes, pagerOf("Event pages", p, pages, f.href)
	if v.Ack = s.ackFormFor(sess, r.URL.RequestURI()); v.Ack != nil {
		if f.server != "" {
			v.AckAll = ackAllOf(v.Rows, f.server, v.Ack)
		}
		v.Rows = withAckForm(v.Rows, v.Ack)
	}
	d := s.layoutFor(sess, "Events", navEvents, v)
	d.Crumbs = []crumb{{"Overview", "/"}, {Label: "Events"}}
	s.render(w, r, http.StatusOK, pageEvents, d)
}

func (s *server) filterEvents(all []fleetEvent, f eventFilter) (scoped, shown []fleetEvent) {
	now := s.d.Now()
	for _, e := range all {
		if !f.keepScope(e, now) {
			continue
		}
		scoped = append(scoped, e)
		if f.keepSeverity(e.Event.Severity) {
			shown = append(shown, e)
		}
	}
	return scoped, shown
}

func (s *server) eventsViewOf(f eventFilter, scoped, shown []fleetEvent, tf timeFmt) eventsView {
	v := eventsView{Total: plural(len(shown), "entry", "entries"), Query: f.q, Zone: zoneLabel(s.d.Now(), tf.loc)}
	var crit, warn, info int
	for _, e := range scoped {
		switch e.Event.Severity {
		case bmc.SeverityCritical:
			crit++
		case bmc.SeverityWarning:
			warn++
		default:
			info++
		}
	}
	with := func(sev string) string { g := f; g.severity, g.page = sev, 1; return g.href(1) }
	v.Counts = []countChip{{"crit", "critical", with("critical"), crit}, {"warn", "warning", with("warning"), warn},
		{"info", "info or unknown", with("all"), info}}
	if hidden := len(scoped) - len(shown); hidden > 0 {
		v.Hidden = plural(hidden, "info entry", "info entries") + " hidden by the severity filter"
		if f.severity == "critical" {
			v.Hidden = plural(hidden, "entry", "entries") + " below critical hidden by the severity filter"
		}
		v.AllHref = with("all")
	}
	v.Servers = s.serverOptions(f.server)
	v.Logs = options(f.log, [][2]string{{"all", "Both logs"}, {"sel", "System Event Log"}, {"lifecycle", "Lifecycle log"}})
	v.Severity = options(f.severity, [][2]string{{"warning", "Warning and worse"}, {"all", "All, including info"}, {"critical", "Critical only"}})
	v.Ranges = options(f.rng, [][2]string{{"24h", "Last 24 hours"}, {"7d", "Last 7 days"}, {"30d", "Last 30 days"}, {"all", "Everything kept"}})
	return v
}

func options(selected string, values [][2]string) []option {
	out := make([]option, 0, len(values))
	for _, v := range values {
		out = append(out, option{Value: v[0], Label: v[1], Selected: v[0] == selected})
	}
	return out
}

func (s *server) serverOptions(selected string) []option {
	out := []option{{Value: "", Label: "All servers", Selected: selected == ""}}
	for _, v := range s.d.Fleet.Servers() {
		out = append(out, option{Value: v.ID, Label: v.Name, Selected: v.ID == selected})
	}
	return out
}

// zoneLabel names the display time zone with its offset: "UTC", "EDT (UTC−4)".
func zoneLabel(now time.Time, loc *time.Location) string {
	name, off := now.In(loc).Zone()
	if off == 0 {
		return name
	}
	sign, h, m := "+", off/3600, (off%3600)/60
	if off < 0 {
		sign, h, m = "−", -h, -m
	}
	label := name + " (UTC" + sign + strconv.Itoa(h)
	if m != 0 {
		label += ":" + strconv.Itoa(m)
	}
	return label + ")"
}
