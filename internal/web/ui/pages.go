package ui

import (
	"errors"
	"net/http"
	"strconv"

	"oob-manager/internal/bmc"
)

// maxPageParam bounds ?page= (a log never has more than a few thousand entries).
const maxPageParam = 10000

// lookup resolves the {id} path value to a configured server, or writes a 404. IDs that
// do not match the config ID pattern never reach Fleet.
func (s *server) lookup(w http.ResponseWriter, r *http.Request) (ServerView, bool) {
	id := r.PathValue("id")
	if serverIDPattern.MatchString(id) {
		if v, ok := s.d.Fleet.Server(id); ok {
			return v, true
		}
	}
	s.serverNotFound(w, r)
	return ServerView{}, false
}

// serverLayout is the chrome of a server's pages: breadcrumb and the current server
// marked in the Servers menu.
func (s *server) serverLayout(sess session, v ServerView, title, tab string, body any) layoutData {
	d := s.layoutFor(sess, title, navServers, body)
	d.ServerID, d.Crumbs = v.ID, serverCrumbs(v.ID, v.Name, tab)
	// The phone's sticky bottom bar holds the same three menus as the header (plan 04
	// §11 item 9); a viewer, who has no actions, gets no bar.
	var m *serverMenus
	if hc, ok := body.(headCarrier); ok {
		m = hc.serverHeadOf().Menus
	} else {
		m = s.headFor(v, sess).Menus
	}
	if m != nil && m.Note == "" {
		d.ServerMenus, d.BodyClass = m, "has-bottombar"
	}
	return d
}

type logTab struct {
	Label, Href string
	Active      bool
}

// pagerView is the shared First / Newer / Page N of M / Older / Last control. It is
// rendered above and below a long table; the two are navigation landmarks, so the
// second carries its own label (Bottom; axe landmark-unique, audit R2-25).
type pagerView struct {
	Label                                   string
	Page, Pages                             int
	FirstHref, PrevHref, NextHref, LastHref string
}

// Bottom is the same pager labeled for the end of the table.
func (p pagerView) Bottom() pagerView {
	if p.Label != "" {
		p.Label += ", bottom"
	}
	return p
}

type logsView struct {
	Head       serverHead
	Nav        serverNav
	Kind       string
	Tabs       []logTab
	Rows       []eventRow
	Pager      pagerView
	Total      string // "15 entries"
	Incomplete bool
	Notice     string
	Overdue    string // set only when this log's refresh is overdue
	// Ack offers Acknowledge on the rows (nil: not allowed); AckAll lists the refs of the
	// unacknowledged warning and critical rows shown ("Acknowledge all shown").
	Ack    *ackForm
	AckAll *ackAllView
}

func (s *server) logsPage(w http.ResponseWriter, r *http.Request, sess session) {
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	kind, okKind := parseLogKind(q.Get("log"))
	page, okPage := parsePage(q.Get("page"))
	if !okKind || !okPage {
		s.errorPage(w, r, http.StatusBadRequest, "Unknown log or page number.")
		return
	}
	lv := logsView{Head: s.headFor(v, sess).tab("events"), Nav: s.navFor(v, sess, "events"), Kind: string(kind),
		Tabs: logTabs(v.ID, kind), Overdue: s.logOverdueNote(v, kind, sess.tf())}
	log, err := s.d.Fleet.Events(r.Context(), v.ID, kind)
	switch {
	case errors.Is(err, ErrLogUnavailable):
		lv.Notice = "This server does not provide this log."
	case err != nil:
		s.d.Logger.Warn("ui event log read failed", "server", v.ID, "log", kind, "class", bmc.Classify(err))
		lv.Notice = "The log could not be read from the BMC (" + errorText(bmc.Classify(err)) + "). Try again later."
	default:
		var redirect string
		lv, redirect = s.fillLog(lv, v.ID, kind, page, log, sess.tf())
		if redirect != "" {
			http.Redirect(w, r, redirect, http.StatusSeeOther) //nolint:gosec // G710: pageHref of a configured ID, a closed log kind and an int (out-of-range page, UI review F-06)
			return
		}
		if lv.Ack = s.ackFormFor(sess, r.URL.RequestURI()); lv.Ack != nil {
			lv.AckAll, lv.Rows = ackAllOf(lv.Rows, v.ID, lv.Ack), withAckForm(lv.Rows, lv.Ack)
		}
	}
	d := s.serverLayout(sess, v, v.Name+": events", "Events", lv)
	s.render(w, r, http.StatusOK, pageLogs, d)
}

// fillLog returns lv with one page of the log, or a redirect to the last page when
// page is past the end.
func (s *server) fillLog(lv logsView, id string, kind LogKind, page int, log bmc.EventLog, tf timeFmt) (logsView, string) {
	entries := foldRepeats(log.Entries())
	p, pages, lo, hi := pageBounds(page, s.d.PageSize, len(entries))
	if p != page {
		return lv, pageHref(id, kind, p)
	}
	href := func(n int) string { return pageHref(id, kind, n) }
	lv.Rows, lv.Total, lv.Incomplete = s.logRows(id, kind, entries[lo:hi], tf), plural(len(entries), "entry", "entries"), !log.Complete()
	lv.Pager = pagerOf("Log pages", p, pages, href)
	if len(entries) == 0 {
		lv.Notice = "The log is empty."
	}
	return lv, ""
}

func pagerOf(label string, p, pages int, href func(int) string) pagerView {
	v := pagerView{Label: label, Page: p, Pages: pages}
	if p > 1 {
		v.FirstHref, v.PrevHref = href(1), href(p-1)
	}
	if p < pages {
		v.NextHref, v.LastHref = href(p+1), href(pages)
	}
	return v
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

func parsePage(s string) (int, bool) {
	if s == "" {
		return 1, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > maxPageParam {
		return 0, false
	}
	return n, true
}

func logTabs(id string, active LogKind) []logTab {
	return []logTab{
		{Label: "System Event Log", Href: pageHref(id, LogSEL, 1), Active: active == LogSEL},
		{Label: "Lifecycle log", Href: pageHref(id, LogLifecycle, 1), Active: active == LogLifecycle},
	}
}

// logRows renders one page of a server log (record order, no day separators: the BMC
// clock can jump).
func (s *server) logRows(id string, kind LogKind, es []foldedEvent, tf timeFmt) []eventRow {
	out := make([]eventRow, 0, len(es))
	for _, e := range es {
		out = append(out, s.withAck(s.eventRow(e.Event, e.Repeat, tf), id, kind, e.Event, tf))
	}
	return out
}
