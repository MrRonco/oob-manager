package ui

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/display"
)

// maxAttentionPerServer bounds the sensor part of "Needs attention" per server;
// maxAttentionEvents and maxFeed bound the event parts.
const (
	maxAttentionPerServer = 5
	maxAttentionEvents    = 5
	maxFeed               = 6
)

type overviewView struct {
	Servers   []summaryRow // severity first
	Counts    fleetCounts
	Draw      string
	DataAge   string
	DataAt    string
	DataISO   string
	TempUnit  string // "°C" or "°F", for the fleet table headers
	Attention []attentionItem
	EventWarn int // warning events in the last 24 h
	EventCrit int
	Feed      []eventRow // newest entries of the last 24 h, any severity
	Healthy   bool       // every server OK and current, nothing in the last 24 h needs attention
	FirstRun  *firstRun  // no servers configured
	Refresh   refreshView
	// NotifyFailing names notification targets that keep failing (banner); NotifyAdmin
	// links the banner to Settings → Notifications.
	NotifyFailing []string
	NotifyAdmin   bool
	// GELFPaused: audit shipping is paused because the log server's certificate does not
	// match the pin (banner; tech_doc §34). GELFAdmin links it to Settings → Integrations.
	GELFPaused bool
	GELFAdmin  bool
	// GELFExpired: the pause is an expired certificate, not a mismatch.
	GELFExpired bool
	// GELFNote: saved GELF settings are not in force (admins only).
	GELFNote string
	// InMaint lists servers in a maintenance window with what is not OK on them: shown,
	// but not counted in the verdict or Needs attention (tech_doc §28).
	InMaint []maintGroup
	// OpenEnded lists "until I end it" windows that have lasted over 24 h (warning
	// banner; design decision, tech_doc §30).
	OpenEnded []openEndedItem
	// SecurityColumn adds the fleet table's Security column (tech_doc §31).
	SecurityColumn bool
	// Hero is the verdict-first head of the Overview; Recorder its desktop fleet view
	// (nil: no history, or the viewer may not see it). Round-2 slice C.
	Hero     heroView
	Recorder *recorderView
}

// openEndedItem is one server of the "Open-ended maintenance" warning.
type openEndedItem struct {
	Server, Href, Since, SinceISO, By, Reason string
}

// maintGroup is one server of the "In maintenance" panel.
type maintGroup struct {
	Server, Href string
	Badge        *maintBadge
	Items        []attentionItem
}

// attentionItem is one non-OK fact (a sensor or a recent event), linked to where it is.
type attentionItem struct {
	Server, Href, Text, Jump, JumpHref string
	Health                             healthView
	Time, TimeISO                      string // events only
}

func (s *server) overview(w http.ResponseWriter, r *http.Request, sess session) {
	v := s.overviewOf(r.Context(), s.d.Fleet.Servers(), sess.view)
	v.Refresh = s.refreshFor(r, sess)
	v.NotifyFailing, v.NotifyAdmin = s.notifyFailing(sess)
	v.GELFPaused = s.gelfPaused()
	v.GELFExpired = v.GELFPaused && s.d.Integrations.Stats().PauseReason == audit.ClassTLSExpired
	isIntAdmin := s.d.Authorize(sess.id.Principal(), authz.AdminIntegrations, true) == nil
	v.GELFAdmin = v.GELFPaused && isIntAdmin
	if isIntAdmin {
		v.GELFNote = s.gelfNote()
	}
	if v.Counts.Total == 0 {
		v.FirstRun = s.firstRunFor(sess)
	}
	v.Hero = heroOf(v)
	v.Recorder = s.recorderFor(r.Context(), v.Servers, sess)
	d := s.withRefresh(r, s.layoutFor(sess, "Overview", navOverview, v))
	s.render(w, r, http.StatusOK, pageOverview, d)
}

func (s *server) overviewOf(ctx context.Context, views []ServerView, vw display.View) overviewView {
	rows := make([]summaryRow, 0, len(views))
	var v overviewView
	var watts float64
	reporting := 0
	for _, sv := range views {
		row := s.summarize(sv, vw)
		rows = append(rows, row)
		if row.Maint != nil {
			v.InMaint = append(v.InMaint, maintGroup{Server: row.Name, Href: "/servers/" + row.ID, Badge: row.Maint,
				Items: attentionFor(row)})
		} else {
			v.Attention = append(v.Attention, attentionFor(row)...)
		}
		if d := sv.Snapshot.Power().ConsumedWatts; !row.Fresh.Stale && validReading(d) {
			watts += d.Value
			reporting++
		}
	}
	v.Servers, v.Counts = bySeverity(rows), countFleet(rows)
	v.SecurityColumn = s.d.Security != nil
	if reporting > 0 {
		v.Draw = fmt.Sprintf("%.0f", watts)
	}
	_, _, v.DataAge = s.chrome(views, vw)
	v.DataAt, v.DataISO = fmtFor(vw).clockOf(s.d.Now()), s.d.Now().UTC().Format("2006-01-02T15:04:05Z")
	v.TempUnit = unitOf(vw.Temp).Symbol
	v = s.withRecentEvents(ctx, v, views, fmtFor(vw))
	v.OpenEnded = s.openEndedOf(views, fmtFor(vw))
	v.Healthy = len(views) > v.Counts.Maintenance && v.Counts.OK == len(views)-v.Counts.Maintenance && len(v.Attention) == 0
	return v
}

// withRecentEvents adds the unacknowledged warning and critical events of the last 24
// hours to the attention list (UX-04), or to the server's "In maintenance" group, and
// the newest entries of any severity to the feed. Acknowledged entries are not counted.
func (s *server) withRecentEvents(ctx context.Context, v overviewView, views []ServerView, tf timeFmt) overviewView {
	all, _ := s.fleetEvents(ctx, views, []LogKind{LogSEL, LogLifecycle})
	since := s.d.Now().Add(-recentWindow)
	groups := map[string]int{}
	for i, g := range v.InMaint {
		groups[g.Href] = i
	}
	shown := 0
	for _, e := range s.unackedProblems(all, since) {
		item := s.eventAttention(e, tf)
		if i, ok := groups[item.Href]; ok {
			v.InMaint[i].Items = append(v.InMaint[i].Items, item)
			continue
		}
		if e.Event.Severity == bmc.SeverityCritical {
			v.EventCrit++
		} else {
			v.EventWarn++
		}
		if shown < maxAttentionEvents {
			v.Attention = append(v.Attention, item)
			shown++
		}
	}
	var recent []fleetEvent
	for _, e := range all {
		if e.Event.Created.After(since) && len(recent) < maxFeed {
			recent = append(recent, e)
		}
	}
	v.Feed = s.fleetRows(recent, false, tf)
	return v
}

// unackedProblems are the warning and critical entries newer than since that nobody
// acknowledged.
func (s *server) unackedProblems(all []fleetEvent, since time.Time) []fleetEvent {
	var out []fleetEvent
	for _, e := range recentProblems(all, since) {
		if _, ok := s.acked(e.ServerID, e.Kind, e.Event); !ok {
			out = append(out, e)
		}
	}
	return out
}

func (s *server) eventAttention(e fleetEvent, tf timeFmt) attentionItem {
	row := s.eventRow(e.Event, e.Repeat, tf)
	text := e.Event.Message
	if e.Repeat > 1 {
		text += fmt.Sprintf(" ×%d", e.Repeat)
	}
	return attentionItem{Server: e.ServerName, Href: "/servers/" + e.ServerID, Text: text,
		Health: row.Severity, Time: row.Short, TimeISO: row.ISO, Jump: "event",
		JumpHref: "/events?range=24h&server=" + e.ServerID}
}

// attentionFor lists what is not OK on one server: missing or stale data first, then
// PSUs, fans and temperatures at or above warning or close to it, then overall health
// when nothing more specific explains it.
func attentionFor(row summaryRow) []attentionItem {
	href := "/servers/" + row.ID
	item := func(text, anchor string, h healthView) attentionItem {
		return attentionItem{Server: row.Name, Href: href, Text: text, Health: h, Jump: "sensor", JumpHref: href + anchor}
	}
	if row.Fresh.Restarting {
		return []attentionItem{item("BMC restarting: "+row.Fresh.Restart+". Readings resume when it answers.", "", row.Health)}
	}
	if row.Fresh.NoData {
		return []attentionItem{item("No data: never polled successfully"+lastError(row.Fresh)+". Check the BMC address and credentials.", "", row.Health)}
	}
	if row.Fresh.Stale {
		return []attentionItem{item("No answer from the BMC for "+row.Fresh.Age+lastError(row.Fresh)+". Last known state: "+
			lastKnown(row.Health)+".", "", row.Health)}
	}
	snap := row.raw.Snapshot
	var out []attentionItem
	if row.PowerItem != nil && row.HostDown {
		out = append(out, *row.PowerItem) // the host is down: lead with it
	}
	for _, p := range snap.PSUs() {
		if p.Health == bmc.HealthCritical || p.Health == bmc.HealthWarning {
			out = append(out, item("Power supply "+p.Name+" reports "+healthOf(p.Health).Label+". Check its input and redundancy.", "/sensors#psu-h", healthOf(p.Health)))
		}
	}
	for _, f := range snap.Fans() {
		if f.Health == bmc.HealthCritical || f.Health == bmc.HealthWarning {
			out = append(out, item("Fan "+displayName(f.Name)+" reports "+healthOf(f.Health).Label+".", "/sensors#fans-h", healthOf(f.Health)))
		}
	}
	for _, t := range tempRows(row.unit.convert(snap.Temperatures()), row.unit) {
		switch {
		case t.Alert || t.Meter.Class == "crit":
			out = append(out, item(t.Name+" "+t.Reading+": "+t.Meter.Text+".", "/sensors#temps-h", healthOf(bmc.HealthWarning)))
		case t.Meter.Close:
			out = append(out, item(t.Name+" "+t.Reading+", "+lowerFirst(t.Meter.Text)+".", "/sensors#temps-h",
				healthView{Label: "Close", Class: "info"}))
		}
	}
	if h := snap.Health(); len(out) == 0 && (h == bmc.HealthCritical || h == bmc.HealthWarning) {
		out = append(out, item("The BMC reports overall health "+healthOf(h).Label+".", "#problems", healthOf(h)))
	}
	if row.PowerItem != nil && !row.HostDown {
		out = append(out, *row.PowerItem) // powering on or not reported: after any sensor problem
	}
	return out[:min(len(out), maxAttentionPerServer)]
}

func lastKnown(h healthView) string {
	if h.Class == "stale" && len(h.Label) > len("Stale (last: )") {
		return h.Label[len("Stale (last: ") : len(h.Label)-1]
	}
	return h.Label
}

func lowerFirst(s string) string {
	if s == "" || s[0] < 'A' || s[0] > 'Z' {
		return s
	}
	return string(s[0]+'a'-'A') + s[1:]
}

// firstRun is the checklist shown when no servers are configured (UX-21).
type firstRun struct {
	Admin bool
}

func (s *server) firstRunFor(sess session) *firstRun {
	return &firstRun{Admin: s.d.Authorize(sess.id.Principal(), authz.AdminUsers, true) == nil}
}

// serversPage is the server index (/servers): the fleet table with links to each
// server's sections.
func (s *server) serversPage(w http.ResponseWriter, r *http.Request, sess session) {
	v := s.overviewOf(r.Context(), s.d.Fleet.Servers(), sess.view)
	v.Refresh = s.refreshFor(r, sess)
	d := s.withRefresh(r, s.layoutFor(sess, "Servers", navServers, v))
	d.Crumbs = []crumb{{"Overview", "/"}, {Label: "Servers"}}
	s.render(w, r, http.StatusOK, pageServers, d)
}

func lastError(f freshness) string {
	if f.Error == "" {
		return ""
	}
	return " (last error: " + f.Error + ")"
}

// openEndedOf lists the servers whose "until ended" window has lasted over
// maint.OpenEndedAfter, oldest first (servers no longer in the fleet are left out).
func (s *server) openEndedOf(views []ServerView, tf timeFmt) []openEndedItem {
	if s.d.Maintenance == nil {
		return nil
	}
	names := make(map[string]string, len(views))
	for _, v := range views {
		names[v.ID] = v.Name
	}
	var out []openEndedItem
	for _, w := range s.d.Maintenance.OpenEnded() {
		name, ok := names[w.ServerID]
		if !ok {
			continue
		}
		out = append(out, openEndedItem{Server: name, Href: "/servers/" + w.ServerID, Since: tf.full(w.StartsAt),
			SinceISO: isoUTC(w.StartsAt), By: w.By, Reason: w.Reason})
	}
	return out
}
