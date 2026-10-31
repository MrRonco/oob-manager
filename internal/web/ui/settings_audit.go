package ui

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"

	"oob-manager/internal/audit"
	"oob-manager/internal/store"
)

// auditPageSize is the number of audit rows per page.
const auditPageSize = 50

var (
	auditActionPattern    = regexp.MustCompile(`^[a-z0-9_.]{1,64}$`)
	auditPrincipalPattern = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	auditResults          = []string{audit.ResultStarted, audit.ResultOK, audit.ResultDenied, audit.ResultError}
)

type auditRowView struct {
	Seq, Time, Principal, Role, Method, IP, Action, Server, Result, Error string
	ResultClass, Sentence                                                 string
	Details                                                               []kv
}

type actionOption struct {
	Value    string
	Selected bool
}

type verifyView struct {
	Done     bool
	OK       bool
	Rows     string
	Head     string
	BadSeq   string
	Reason   string
	Verified string
}

type auditView struct {
	CSRF      string
	Filter    store.AuditFilter
	Actions   []actionOption
	Results   []actionOption
	Rows      []auditRowView
	OlderHref string
	NewestRef string
	Verify    verifyView
}

// parseAuditFilter validates the viewer query; anything malformed is a 400.
func parseAuditFilter(q url.Values) (store.AuditFilter, bool) {
	f := store.AuditFilter{Action: q.Get("action"), Principal: q.Get("principal"), ServerID: q.Get("server"),
		Result: q.Get("result"), Limit: auditPageSize}
	switch {
	case f.Action != "" && !auditActionPattern.MatchString(f.Action),
		f.Principal != "" && !auditPrincipalPattern.MatchString(f.Principal),
		f.ServerID != "" && !serverIDPattern.MatchString(f.ServerID),
		f.Result != "" && !slices.Contains(auditResults, f.Result):
		return store.AuditFilter{}, false
	}
	if b := q.Get("before"); b != "" {
		n, err := strconv.ParseInt(b, 10, 64)
		if err != nil || n < 1 {
			return store.AuditFilter{}, false
		}
		f.BeforeSeq = n
	}
	return f, true
}

func filterQuery(f store.AuditFilter, before int64) string {
	q := url.Values{}
	for k, v := range map[string]string{"action": f.Action, "principal": f.Principal, "server": f.ServerID,
		"result": f.Result} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if before > 0 {
		q.Set("before", strconv.FormatInt(before, 10))
	}
	return "/settings/audit?" + q.Encode()
}

func (s *server) auditPage(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderAudit(w, r, sess, verifyView{})
}

func (s *server) renderAudit(w http.ResponseWriter, r *http.Request, sess session, vr verifyView) {
	f, ok := parseAuditFilter(r.URL.Query())
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "Unknown audit filter.")
		return
	}
	rows, err := s.d.AuditLog.Search(r.Context(), f)
	if err == nil {
		var actions []string
		if actions, err = s.d.AuditLog.Actions(r.Context()); err == nil {
			v := s.auditViewOf(sess, f, rows, actions, s.userNames(r))
			v.Verify = vr
			s.render(w, r, http.StatusOK, pageSettingsAudit, s.settingsLayout(r, sess, "Audit log", v))
			return
		}
	}
	s.d.Logger.Error("ui audit view failed", "err", err)
	s.errorPage(w, r, http.StatusInternalServerError, "The audit log could not be read.")
}

func (s *server) auditViewOf(sess session, f store.AuditFilter, rows []store.AuditRecord, actions []string, names map[string]string) auditView {
	v := auditView{CSRF: s.csrf.issue(formSettings, sessionBinding(sess.token)), Filter: f,
		NewestRef: filterQuery(f, 0)}
	for _, a := range actions {
		v.Actions = append(v.Actions, actionOption{Value: a, Selected: a == f.Action})
	}
	for _, res := range auditResults {
		v.Results = append(v.Results, actionOption{Value: res, Selected: res == f.Result})
	}
	for _, rec := range rows {
		v.Rows = append(v.Rows, s.auditRow(rec, names, sess.tf()))
	}
	if len(rows) == f.Limit {
		v.OlderHref = filterQuery(f, rows[len(rows)-1].Seq)
	}
	return v
}

func (s *server) auditRow(rec store.AuditRecord, names map[string]string, tf timeFmt) auditRowView {
	class := map[string]string{audit.ResultOK: "ok", audit.ResultDenied: "warn", audit.ResultError: "crit"}[rec.Result]
	return auditRowView{Seq: strconv.FormatInt(rec.Seq, 10), Time: tf.full(rec.TS),
		Principal: principalName(rec.Principal), Role: rec.Role, Method: rec.AuthMethod, IP: rec.SrcIP, Action: rec.Action,
		Server: rec.ServerID, Result: rec.Result, Error: rec.ErrorClass, ResultClass: orStr(class, "unknown"),
		Sentence: auditSentence(rec, names), Details: auditDetails(rec.ParamsJSON)}
}

// userNames maps user IDs to usernames for the audit sentences; on error IDs stay unnamed.
func (s *server) userNames(r *http.Request) map[string]string {
	out := map[string]string{}
	if list, err := s.d.Admin.Users(r.Context()); err == nil {
		for _, u := range list {
			out[u.ID] = u.Username
		}
	}
	return out
}

func orStr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// verifyAudit walks the whole chain (security.md T3) and shows the result on the audit
// page. It is rate-limited globally (default once a minute) and audited.
func (s *server) verifyAudit(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	if ok, wait := s.verifyLimit.allow("verify"); !ok {
		s.deny(r, sess, "admin.audit.verify", "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "The chain was verified less than a minute ago. "+tryAgainIn(wait))
		return
	}
	res, err := s.d.AuditLog.Verify(r.Context())
	vr := verifyView{Done: true, Verified: sess.tf().full(s.d.Now())}
	e := audit.Entry{Principal: sess.id.User.Username, Role: string(sess.id.User.Role), Action: "admin.audit.verify"}
	var te *audit.TamperError
	switch {
	case err == nil:
		vr.OK, vr.Rows, vr.Head = true, strconv.FormatInt(res.Count, 10), res.Head
		e.Result, e.Params = audit.ResultOK, map[string]any{"rows": res.Count, "head": res.Head}
	case errors.As(err, &te):
		vr.BadSeq, vr.Reason = strconv.FormatInt(te.Seq, 10), te.Reason
		e.Result, e.ErrorClass, e.Params = audit.ResultError, "tampered", map[string]any{"first_bad_seq": te.Seq}
	default:
		s.d.Logger.Error("ui audit verify failed", "err", err)
		vr.Reason = "The audit log could not be read."
		e.Result, e.ErrorClass = audit.ResultError, "store"
	}
	_ = s.record(r, e)
	s.renderAudit(w, r, sess, vr)
}

func backToAudit(*http.Request) string { return "/settings/audit" }
