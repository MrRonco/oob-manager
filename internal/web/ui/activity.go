package ui

import (
	"context"
	"net/http"
	"slices"
	"strconv"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/store"
)

// activityPageSize is the number of actions per Activity page.
const activityPageSize = 50

// Activity (plan 04 §11 item 8, round-2 slice C) is what people and the app did to the
// servers: power requests, fan leases, BMC restarts and maintenance windows. Every role
// sees it, so the privacy rule is enforced here, in the query and the view model, not in
// the template:
//   - only the action and result pairs of activityMatches() are read, in SQL, so a page
//     of 50 is 50 shown rows: never sign-ins, step-ups, tokens, user or settings changes,
//     and never refusals (denied rows);
//   - a row keeps only the time, the person, the server and a sentence built from the
//     action: never the source IP, the role, the authentication method or parameters.
//
// One row per thing done, as the history overlay draws them: a power action or a BMC
// restart is shown when it was requested (started) and again only if it failed; its
// final "ok" row (which also covers an unconfirmed outcome) is not repeated. Fan leases
// and maintenance are shown when they took effect (ok) or failed.

// activityMatches are the audit rows the Activity pages may show.
func activityMatches() []store.AuditMatch {
	var out []store.AuditMatch
	for _, a := range []authz.Action{authz.PowerOn, authz.PowerGracefulStop, authz.PowerGracefulRestart,
		authz.PowerForceOff, authz.PowerForceRestart, authz.PowerCycle, authz.BMCReset} {
		out = append(out, store.AuditMatch{Action: string(a), Result: audit.ResultStarted},
			store.AuditMatch{Action: string(a), Result: audit.ResultError})
	}
	for _, a := range []string{string(authz.FanLeaseCreate), string(authz.FanLeaseEnd), actionFanExpire,
		actionBMCVerified, actionMaintStart, actionMaintEnd} {
		out = append(out, store.AuditMatch{Action: a, Result: audit.ResultOK},
			store.AuditMatch{Action: a, Result: audit.ResultError})
	}
	return out
}

// Audit actions of other services shown on the Activity pages (fixed strings, as the
// history overlay names them).
const (
	actionFanExpire   = "fan.lease.expire"
	actionBMCVerified = "bmc.reset.verified"
	actionMaintStart  = "server.maintenance.start"
	actionMaintEnd    = "server.maintenance.end"
)

// activityRow is one action. It has no field for an address or a parameter on purpose.
type activityRow struct {
	Time, ISO  string
	Who        string
	ServerID   string
	ServerName string
	Text       string
	Result     healthView
}

// activityList is one page of actions, newest first.
type activityList struct {
	Rows        []activityRow
	OlderHref   string
	Unavailable string
	Server      bool // the list of one server (no server column)
}

// activityView is the global Activity page.
type activityView struct {
	List activityList
}

// serverActivityView is a server's Activity tab: its maintenance window, its notes and
// the actions on it.
type serverActivityView struct {
	Head  serverHead
	Nav   serverNav
	Maint *maintCard
	Notes *notesCard
	List  activityList
}

func (s *server) activityPage(w http.ResponseWriter, r *http.Request, sess session) {
	before, ok := parseBefore(r.URL.Query().Get("before"))
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "Unknown page of the activity list.")
		return
	}
	list := s.activityOf(r.Context(), "", before, sess)
	d := s.layoutFor(sess, "Activity", navActivity, activityView{List: list})
	s.render(w, r, http.StatusOK, pageActivity, d)
}

func (s *server) serverActivityPage(w http.ResponseWriter, r *http.Request, sess session) {
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	before, ok := parseBefore(r.URL.Query().Get("before"))
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "Unknown page of the activity list.")
		return
	}
	av := serverActivityView{Head: s.headFor(v, sess).tab("activity"), Nav: s.navFor(v, sess, "activity"),
		Maint: s.maintCardFor(v, sess), List: s.activityOf(r.Context(), v.ID, before, sess)}
	av.Notes, _ = s.notesFor(v, sess)
	d := s.serverLayout(sess, v, v.Name+": activity", "Activity", av)
	s.render(w, r, http.StatusOK, pageSrvActivity, d)
}

// parseBefore reads ?before= (an audit sequence number; empty is the newest page).
func parseBefore(v string) (int64, bool) {
	if v == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	return n, err == nil && n > 0
}

// activityOf reads one page of actions, of one server when serverID is set.
func (s *server) activityOf(ctx context.Context, serverID string, before int64, sess session) activityList {
	list := activityList{Server: serverID != ""}
	if s.d.AuditLog == nil {
		list.Unavailable = "The activity list is not available in this installation."
		return list
	}
	recs, err := s.d.AuditLog.Search(ctx, store.AuditFilter{Matches: activityMatches(), ServerID: serverID,
		BeforeSeq: before, Limit: activityPageSize})
	if err != nil {
		s.d.Logger.Error("ui activity read failed", "err", err)
		list.Unavailable = "The activity list could not be read. Try again."
		return list
	}
	names := s.serverNames()
	tf := sess.tf()
	for _, rec := range recs {
		if row, ok := activityRowOf(rec, names, tf); ok {
			list.Rows = append(list.Rows, row)
		}
	}
	if len(recs) == activityPageSize {
		base := "/activity"
		if serverID != "" {
			base = "/servers/" + serverID + "/activity"
		}
		list.OlderHref = base + "?before=" + strconv.FormatInt(recs[len(recs)-1].Seq, 10)
	}
	return list
}

// serverNames maps configured server IDs to their names.
func (s *server) serverNames() map[string]string {
	out := map[string]string{}
	for _, v := range s.d.Fleet.Servers() {
		out[v.ID] = v.Name
	}
	return out
}

// activityRowOf is the public form of one audit row; ok is false for a row that must not
// be shown (another action or result; the query already keeps only activityMatches).
func activityRowOf(rec store.AuditRecord, names map[string]string, tf timeFmt) (activityRow, bool) {
	text, ok := activityText(rec.Action, rec.Result)
	if !ok {
		return activityRow{}, false
	}
	row := activityRow{Time: tf.full(rec.TS), ISO: isoUTC(rec.TS), Who: principalName(rec.Principal),
		ServerID: rec.ServerID, ServerName: names[rec.ServerID], Text: text, Result: activityResult(rec.Result)}
	if row.ServerName == "" {
		row.ServerName = rec.ServerID
	}
	return row, true
}

func activityResult(result string) healthView {
	switch result {
	case audit.ResultOK:
		return healthView{Label: "Done", Class: "ok"}
	case audit.ResultError:
		return healthView{Label: "Failed", Class: "crit"}
	default:
		return healthView{Label: "Requested", Class: "info"}
	}
}

// activityText is the sentence of an action and result pair of activityMatches (the
// subject is shown beside it); anything else is not shown.
func activityText(action, result string) (string, bool) {
	if !slices.Contains(activityMatches(), store.AuditMatch{Action: action, Result: result}) {
		return "", false
	}
	switch a := authz.Action(action); a {
	case authz.PowerOn, authz.PowerGracefulStop, authz.PowerGracefulRestart, authz.PowerForceOff,
		authz.PowerForceRestart, authz.PowerCycle:
		return powerVerb(a), true
	case authz.FanLeaseCreate:
		return "started a fan lease", true
	case authz.FanLeaseEnd:
		return "ended the fan lease", true
	case authz.BMCReset:
		return "asked for a BMC restart", true
	}
	switch {
	case action == actionFanExpire:
		return "fan lease expired", true
	case action == actionBMCVerified && result == audit.ResultOK:
		return "BMC answered again after a restart request", true
	case action == actionBMCVerified:
		return "BMC did not answer in time after its restart", true
	case action == actionMaintStart:
		return "started or scheduled maintenance", true
	default:
		return "ended maintenance", true
	}
}

func powerVerb(a authz.Action) string {
	switch a {
	case authz.PowerOn:
		return "asked to power on"
	case authz.PowerGracefulStop:
		return "asked for a graceful shutdown"
	case authz.PowerGracefulRestart:
		return "asked for a graceful restart"
	case authz.PowerForceOff:
		return "forced the power off"
	case authz.PowerForceRestart:
		return "forced a restart"
	default:
		return "power cycled the server"
	}
}

// fanPage is More ▾ → Fan boost…: the fan lease card on its own page (it was on the
// retired Operations tab). Starting and ending a lease post to the unchanged routes.
func (s *server) fanPage(w http.ResponseWriter, r *http.Request, sess session) {
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	fv := fanPageView{Head: s.headFor(v, sess).tab("fan boost"), Nav: s.navFor(v, sess, ""), Fan: s.fanCardFor(r, sess, v)}
	d := s.serverLayout(sess, v, v.Name+": fan boost", "Fan boost", fv)
	s.render(w, r, http.StatusOK, pageFan, d)
}

type fanPageView struct {
	Head serverHead
	Nav  serverNav
	Fan  fanCard
}
