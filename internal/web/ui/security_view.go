package ui

import (
	"cmp"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
	"oob-manager/internal/bmcsec"
)

// securityView is the Security tab (tech_doc §31): a summary every role sees and, for
// operators and admins, the findings grouped with what to do about them.
type securityView struct {
	Head  serverHead
	Nav   serverNav
	Flash string
	// Notice says why a change was refused (the finding changed since the page was
	// loaded); the tab is re-rendered with it.
	Notice      string
	Enabled     bool
	HasReport   bool
	Pending     string
	Summary     secSummary
	Run         secRun
	Details     bool
	DetailsNote string
	Groups      []secGroup
}

type secCount struct {
	Label, Class string
	N            int
}

type secSummary struct {
	Badge   healthView
	Verdict string
	Panel   string
	Counts  []secCount
}

type secRun struct {
	At, ISO, Took, Next, NextISO string
	Running, Requested, Overdue  bool
	Error                        string
	Rerun                        secRerun
}

// secRerun is the Re-run control: a form when CSRF is set, else disabled with Why.
// secRerun is the Re-run control: a form (CSRF set), a disabled button with its reason
// (Why), or for a viewer only a role note (Note): status, not a dead control (R2-11).
type secRerun struct {
	ServerID, CSRF, Why, Note string
}

// secGroup is one check group. Findings are what needs reading (problems, unreadable,
// unknown, accepted risks and "Not checked" infos); Quiet are the passes and other
// infos, folded into "N more checks" (round-2 slice C, plan 04 §11). Cells, Tone and
// Problems draw the group in the posture map, which doubles as the jump list.
type secGroup struct {
	ID, Title, Summary string
	Findings           []secFinding
	Quiet              []secFinding
	QuietSummary       string
	Cells              []string // one posture class per check, worst first
	Tone               string   // the worst cell's class
	Problems           string   // the group's non-pass counts ("1 fail · 2 warning"), "" when clear
}

type secFinding struct {
	ID, Anchor, Title    string
	Badge                healthView
	Evidence             []string
	Why, Fix, Dell, Docs string
	Accepted             *secAccepted
	Accept, Remove       bool
	CSRF, ServerID       string
	// Seen is the finding as shown (result and subject hash); the accept form carries
	// it so the service accepts only what the admin looked at.
	Seen string
}

type secAccepted struct {
	Badge                healthView
	By, At, ISO, Comment string
}

func (s *server) securityPage(w http.ResponseWriter, r *http.Request, sess session) {
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if s.d.Security == nil {
		s.errorPage(w, r, http.StatusNotFound, "There is no page at this address.")
		return
	}
	s.renderSecurity(w, r, sess, v, http.StatusOK, "")
}

// renderSecurity renders the Security tab of v, with a notice when a change was refused.
func (s *server) renderSecurity(w http.ResponseWriter, r *http.Request, sess session, v ServerView, status int, notice string) {
	sv := s.securityViewFor(v, sess)
	sv.Flash, sv.Notice = secDone(r.URL.Query().Get("done")), notice
	d := s.serverLayout(sess, v, v.Name+": security", "Security", sv)
	s.render(w, r, status, pageSecurity, d)
}

func (s *server) allowed(sess session, a authz.Action) bool {
	return s.d.Authorize(sess.id.Principal(), a, true) == nil
}

func (s *server) securityViewFor(v ServerView, sess session) securityView {
	st := s.d.Security.Status(v.ID)
	sv := securityView{Head: s.headFor(v, sess).tab("security"), Nav: s.navFor(v, sess, "security"), Enabled: st.Enabled,
		Run: s.secRunOf(v.ID, st, sess)}
	rep, ok := s.d.Security.Report(v.ID)
	if !ok {
		sv.Pending = "Not checked yet: the checks run after the first good poll of the BMC, then every " +
			fmtEvery(cmp.Or(st.Every, 6*time.Hour)) + "."
		return sv
	}
	sv.HasReport, sv.Summary = true, secSummaryOf(rep.Counts())
	if !s.allowed(sess, authz.SecurityView) {
		sv.DetailsNote = "The findings describe weaknesses of this BMC, so they need the operator role."
		return sv
	}
	sv.Details = true
	var csrf string
	accept := s.allowed(sess, authz.SecurityAccept) && s.d.Security.Available()
	if accept {
		csrf = s.csrf.issue(formSettings, sessionBinding(sess.token))
	}
	sv.Groups = secGroups(rep, v.ID, accept, csrf, sess.tf())
	return sv
}

func (s *server) secRunOf(id string, st bmcsec.RunStatus, sess session) secRun {
	tf := sess.tf()
	run := secRun{Running: st.Running, Requested: st.Requested, Overdue: st.Overdue, Error: secErrorText(st.Error)}
	if st.HasReport {
		run.At, run.ISO, run.Took = tf.full(st.AsOf), isoUTC(st.AsOf), fmtPollDuration(st.Took)
		run.Next, run.NextISO = tf.full(st.NextAround), isoUTC(st.NextAround)
	}
	run.Rerun = secRerun{ServerID: id}
	switch {
	case !st.Enabled:
		run.Rerun.Why = "the checks are off for this server"
	case !s.allowed(sess, authz.SecurityView):
		run.Rerun.Note = "Re-running the checks needs the admin role."
	case !s.allowed(sess, authz.SecurityRerun):
		run.Rerun.Why = "needs the admin role"
	case st.Running || st.Requested:
		run.Rerun.Why = "a run is already on its way"
	case st.CooldownLeft > 0:
		run.Rerun.Why = "available again in " + plural(int((st.CooldownLeft+time.Minute-1)/time.Minute), "minute", "minutes")
	default:
		run.Rerun.CSRF = s.csrf.issue(formSettings, sessionBinding(sess.token))
	}
	return run
}

func fmtEvery(d time.Duration) string {
	if d%time.Hour == 0 {
		return plural(int(d/time.Hour), "hour", "hours")
	}
	return d.String()
}

// secErrorText names a failed run's error class ("" when the last run worked).
func secErrorText(c bmc.ErrorClass) string {
	switch c {
	case bmc.ClassNone:
		return ""
	case bmc.ClassTimeout:
		return "timed out"
	case bmc.ClassUnreachable:
		return "not reachable"
	case bmc.ClassTLS:
		return "certificate mismatch"
	case bmc.ClassAuth:
		return "login refused"
	case bmc.ClassProtocol:
		return "unexpected answer"
	case bmc.ClassUnsupported:
		return "not supported by this BMC"
	default:
		return string(c)
	}
}

func secDone(key string) string {
	switch key {
	case "rerun":
		return "Re-run requested. The checks run now; reload this page in a minute for the results."
	case "accepted":
		return "Finding accepted as a risk. It no longer counts and is not notified while it stays the same."
	case "unaccepted":
		return "Acceptance removed. The finding counts again."
	default:
		return ""
	}
}

// resultBadge is a result as a status badge (glyph and word).
func resultBadge(r bmcsec.Result) healthView {
	switch r {
	case bmcsec.Fail:
		return healthView{Label: r.Label(), Class: "crit"}
	case bmcsec.Warn:
		return healthView{Label: r.Label(), Class: "warn"}
	case bmcsec.CantRead, bmcsec.Unknown:
		return healthView{Label: r.Label(), Class: "unknown"}
	case bmcsec.Info:
		return healthView{Label: r.Label(), Class: "info"}
	default:
		return healthView{Label: r.Label(), Class: "ok"}
	}
}

func acceptedBadge() healthView { return healthView{Label: "Accepted risk", Class: "info"} }

// mostlyUnknown: nothing failed or warned, but more than half of the checks could not be
// evaluated (unknown or refused), so there is no reassurance to show either.
func mostlyUnknown(c bmcsec.Counts) bool {
	return c.Problems() == 0 && 2*(c.Unknown+c.CantRead) > c.Total()
}

func secSummaryOf(c bmcsec.Counts) secSummary {
	sum := secSummary{Counts: secCounts(c)}
	switch {
	case mostlyUnknown(c):
		sum.Badge = resultBadge(bmcsec.Unknown)
		sum.Verdict = "Most checks could not be evaluated; nothing failed or warned among those that were."
	case c.Fail > 0:
		sum.Badge, sum.Panel = resultBadge(bmcsec.Fail), "p-crit"
		sum.Verdict = plural(c.Fail, "check fails", "checks fail")
		if c.Warn > 0 {
			sum.Verdict += " and " + plural(c.Warn, "warns", "warn")
		}
		sum.Verdict += "."
	case c.Warn > 0:
		sum.Badge, sum.Panel = resultBadge(bmcsec.Warn), "p-warn"
		sum.Verdict = plural(c.Warn, "check needs", "checks need") + " attention."
	default:
		sum.Badge, sum.Panel = resultBadge(bmcsec.Pass), "p-ok"
		sum.Verdict = "No failing checks and no warnings."
	}
	if c.CantRead > 0 {
		sum.Verdict += " " + plural(c.CantRead, "check", "checks") + " could not be read with the read-only account."
	}
	return sum
}

func secCounts(c bmcsec.Counts) []secCount {
	all := []secCount{{"Fail", "k-crit", c.Fail}, {"Warning", "k-warn", c.Warn}, {"Can't read", "k-stale", c.CantRead},
		{"Unknown", "", c.Unknown}, {"Info", "k-info", c.Info}, {"Pass", "k-ok", c.Pass}, {"Accepted risk", "k-info", c.Accepted}}
	return slices.DeleteFunc(all, func(x secCount) bool { return x.N == 0 })
}

// secRank orders findings in a group: open failures and warnings, then unreadable and
// unknown, then accepted risks, then info and passes; catalog order within a rank.
func secRank(f bmcsec.Finding) int {
	if f.Accepted != nil {
		return 15
	}
	return f.Result.Rank() * 10
}

func secGroups(rep bmcsec.Report, serverID string, accept bool, csrf string, tf timeFmt) []secGroup {
	byGroup := map[bmcsec.Group][]bmcsec.Finding{}
	for _, f := range rep.Findings {
		byGroup[f.Check.Group] = append(byGroup[f.Check.Group], f)
	}
	var out []secGroup
	for _, g := range bmcsec.Groups() {
		fs := byGroup[g]
		if len(fs) == 0 {
			continue
		}
		slices.SortStableFunc(fs, func(a, b bmcsec.Finding) int { return cmp.Compare(secRank(b), secRank(a)) })
		grp := secGroup{ID: string(g), Title: g.Title(), Summary: groupSummary(fs)}
		var quiet []bmcsec.Finding
		for _, f := range fs {
			grp.Cells = append(grp.Cells, postureClass(f))
			if secQuiet(f) {
				quiet = append(quiet, f)
				grp.Quiet = append(grp.Quiet, secFindingOf(f, serverID, accept, csrf, tf))
				continue
			}
			grp.Findings = append(grp.Findings, secFindingOf(f, serverID, accept, csrf, tf))
		}
		grp.Tone, grp.QuietSummary, grp.Problems = grp.Cells[0], groupSummary(quiet), problemSummary(fs)
		out = append(out, grp)
	}
	return out
}

// secQuiet: a pass, or an info that is not a limit of what was checked ("Not checked …"
// stays visible), and not an accepted risk.
func secQuiet(f bmcsec.Finding) bool {
	if f.Accepted != nil || (f.Result != bmcsec.Pass && f.Result != bmcsec.Info) {
		return false
	}
	return f.Result == bmcsec.Pass || len(f.Evidence) == 0 || !strings.HasPrefix(f.Evidence[0], "Not checked")
}

// postureClass is a check's cell in the posture map: fill weight carries the result
// (fail solid, warning tinted, unreadable dashed, accepted outlined, info a dot, pass a
// low bar), so the map reads in greyscale too.
func postureClass(f bmcsec.Finding) string {
	switch {
	case f.Accepted != nil:
		return "acc"
	case f.Result == bmcsec.Fail:
		return "fail"
	case f.Result == bmcsec.Warn:
		return "warn"
	case f.Result == bmcsec.CantRead || f.Result == bmcsec.Unknown:
		return "unk"
	case f.Result == bmcsec.Info:
		return "info"
	default:
		return "pass"
	}
}

// problemSummary is a group's counts without passes and infos ("" when all clear).
func problemSummary(fs []bmcsec.Finding) string {
	var parts []string
	for _, x := range secCounts(bmcsec.Report{Findings: fs}.Counts()) {
		if x.Label != "Pass" && x.Label != "Info" {
			parts = append(parts, strconv.Itoa(x.N)+" "+strings.ToLower(x.Label))
		}
	}
	return strings.Join(parts, " · ")
}

func groupSummary(fs []bmcsec.Finding) string {
	var parts []string
	for _, x := range secCounts(bmcsec.Report{Findings: fs}.Counts()) {
		parts = append(parts, strconv.Itoa(x.N)+" "+strings.ToLower(x.Label))
	}
	return strings.Join(parts, " · ")
}

func secFindingOf(f bmcsec.Finding, serverID string, accept bool, csrf string, tf timeFmt) secFinding {
	out := secFinding{ID: f.Check.ID, Anchor: checkAnchor(f.Check.ID), Title: f.Check.Title, Badge: resultBadge(f.Result),
		Evidence: f.Evidence, Why: f.Check.Why, Fix: f.Check.Fix, Dell: f.Check.Dell, Docs: f.Check.Docs,
		CSRF: csrf, ServerID: serverID, Seen: f.Seen()}
	if a := f.Accepted; a != nil {
		out.Badge = acceptedBadge()
		out.Accepted = &secAccepted{Badge: acceptedBadge(), By: a.By, At: tf.full(a.At), ISO: isoUTC(a.At), Comment: a.Comment}
	}
	out.Accept = accept && f.Result.Problem() && f.Accepted == nil
	out.Remove = accept && f.Accepted != nil
	return out
}

// secCell is a server's Security column on the fleet table.
type secCell struct {
	Text, Href, Title string
	Badge             *healthView
}

func (s *server) secCellFor(id string, tf timeFmt) *secCell {
	if s.d.Security == nil {
		return nil
	}
	st := s.d.Security.Status(id)
	href := "/servers/" + id + "/security"
	rep, ok := s.d.Security.Report(id)
	switch {
	case !st.Enabled:
		return &secCell{Text: "Disabled"} // checks off; "Off" reads as powered off
	case !ok && st.Running:
		return &secCell{Text: "Checking now", Href: href}
	case !ok:
		return &secCell{Text: "Not checked yet", Href: href}
	}
	c := rep.Counts()
	cell := &secCell{Href: href, Title: "Security checks of " + tf.full(st.AsOf)}
	var parts []string
	if c.Fail > 0 {
		parts = append(parts, strconv.Itoa(c.Fail)+" fail")
	}
	if c.Warn > 0 {
		parts = append(parts, strconv.Itoa(c.Warn)+" warn")
	}
	b := resultBadge(bmcsec.Pass)
	switch {
	case c.Fail > 0:
		b = resultBadge(bmcsec.Fail)
	case c.Warn > 0:
		b = resultBadge(bmcsec.Warn)
	case mostlyUnknown(c):
		b, parts = resultBadge(bmcsec.Unknown), []string{"Unknown"}
	default:
		parts = []string{"OK"}
	}
	b.Label = strings.Join(parts, " · ")
	cell.Text, cell.Badge = b.Label, &b
	return cell
}
