package ui

import (
	"errors"
	"net/http"
	"net/url"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
)

// formConfirm values: the confirm page's form carries confirm=yes; a POST without it
// (an old form, a hand-made request) is sent to the confirm page instead (UX-06).
const confirmYes = "yes"

// Confirm tiers (audit R2-15); the zero value is neutral.
const (
	tierCaution = "caution"
	tierDanger  = "danger"
)

// confirmView is the confirm interstitial (brief C-11): verb + target in the title,
// what happens, Cancel as the default focus, a button that names the action, a typed
// name for irreversible actions, and the step-up code when the window is not fresh
// (C-12, naming the action it authorizes).
type confirmView struct {
	Title string
	Badge healthView // "Reversible" (info) or "Cannot be undone" (crit)
	// Tier picks the treatment (audit R2-15): "" neutral (reversible, safe: accent
	// button, info panel), tierCaution (service impact, recoverable: warning panel,
	// outlined warning button), tierDanger (forced or irreversible: the red treatment).
	Tier         string
	Heading      string // "What happens"
	Consequences []string
	Facts        []kv
	Note         string
	Action       string // POST target
	Button       string // "Disable victor"
	CancelHref   string
	Typed        string // the exact text to type; "" = no typed confirmation
	TypedWhy     string
	ActionLabel  string // "Disable account · victor" (step-up context)
	StepUp       stepUpNote
	User         string
	CSRF         string
	Error        string
	TypedInvalid bool
	CodeInvalid  bool
	// Warnings are shown above the consequences (critical server, self-host); Impact is
	// the "What goes down" list from config.
	Warnings []string
	Impact   []string
	// Lease carries the editable fan lease fields (floor, duration); EmptyNote replaces the
	// consequences while they cannot be computed (invalid input).
	Lease     *leaseFields
	EmptyNote string

	// form is the CSRF form name ("" = Settings) and chrome the page layout (nil =
	// Settings), so server-scoped confirms (power, fan lease) reuse the template and step-up.
	form     string
	chrome   func(sess session, title string, body any) layoutData
	serverID string // audited with step-up refusals ("" = none)
}

// confirmSpec builds the confirm view for a request: the target is looked up from the
// path (never from the form), so the page and the POST always agree on what is changed.
type confirmSpec func(r *http.Request, sess session) (confirmView, error)

// confirmPage renders the interstitial for GET.
func (s *server) confirmPage(spec confirmSpec) pageHandler {
	return func(w http.ResponseWriter, r *http.Request, sess session) {
		v, err := spec(r, sess)
		if err != nil {
			s.failChange(w, r, err)
			return
		}
		s.renderConfirm(w, r, sess, v, http.StatusOK)
	}
}

func (s *server) renderConfirm(w http.ResponseWriter, r *http.Request, sess session, v confirmView, status int) {
	form := v.form
	if form == "" {
		form = formSettings
	}
	v.Action, v.CSRF, v.User = r.URL.Path, s.csrf.issue(form, sessionBinding(sess.token)), sess.id.User.Username
	v.StepUp = s.stepUpNoteFor(r, sess)
	v.StepUp.Next = r.URL.Path
	noStore(w)
	var d layoutData
	if v.chrome != nil {
		d = v.chrome(sess, v.Title, v)
	} else {
		d = s.settingsLayout(r, sess, v.Title, v)
		d.Crumbs = []crumb{{"Settings", "/settings"}, {Label: "Confirm"}}
	}
	s.render(w, r, status, pageConfirm, d)
}

// confirmed wraps a destructive Settings change. Order: session, CSRF, target lookup,
// the confirm field, the typed name, the step-up (inline code when the window is not
// fresh), role, per-user rate limit, handler. Every refusal is audited.
func (s *server) confirmed(action authz.Action, spec confirmSpec, h changeHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, form, ok := s.changeForm(w, r, action)
		if !ok {
			return
		}
		v, err := spec(r, sess)
		if err != nil {
			s.failChange(w, r, err)
			return
		}
		switch {
		case form.Get("confirm") != confirmYes:
			s.deny(r, sess, action, "unconfirmed")
			redirectLocal(w, r, r.URL.Path)
			return
		case v.Typed != "" && form.Get("typed") != v.Typed:
			s.deny(r, sess, action, "confirm_mismatch")
			v.Error, v.TypedInvalid = "The name you typed does not match. Type it exactly, including case.", true
			s.renderConfirm(w, r, sess, v, http.StatusUnprocessableEntity)
			return
		}
		if sess, ok = s.confirmStepUp(w, r, sess, action, form.Get("code"), v); !ok {
			return
		}
		if s.authorizeChange(w, r, sess, action, r.URL.Path) && s.allowChange(w, r, sess, action) {
			h(w, r, sess, form)
		}
	})
}

// changeForm runs the shared first steps of a change: session, Settings backend, form
// and CSRF.
func (s *server) changeForm(w http.ResponseWriter, r *http.Request, action authz.Action) (session, url.Values, bool) {
	sess, ok := s.requireSession(w, r)
	if !ok {
		return session{}, nil, false
	}
	if s.d.Admin == nil || s.d.AuditLog == nil {
		s.errorPage(w, r, http.StatusNotFound, "Settings are not available in this installation.")
		return session{}, nil, false
	}
	form, ok := parseForm(w, r)
	if !ok || !s.csrf.verify(form.Get(csrfField), formSettings, sessionBinding(sess.token)) {
		s.deny(r, sess, action, "csrf")
		s.errorPage(w, r, http.StatusForbidden, msgFormExpired)
		return session{}, nil, false
	}
	return sess, form, true
}

// allowChange applies the per-user Settings rate limit.
func (s *server) allowChange(w http.ResponseWriter, r *http.Request, sess session, action authz.Action) bool {
	if ok, wait := s.changeLimit.allow("user:" + sess.id.User.ID); !ok {
		s.deny(r, sess, action, "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Too many changes in a short time. "+tryAgainIn(wait))
		return false
	}
	return true
}

// confirmStepUp returns the session to continue with: unchanged when the step-up window
// is fresh, rotated after a valid inline code. On failure it renders the confirm page
// with the error and returns false.
func (s *server) confirmStepUp(w http.ResponseWriter, r *http.Request, sess session, action authz.Action,
	code string, v confirmView) (session, bool) {
	if s.d.Auth.StepUpFresh(sess.id.Session) {
		return sess, true
	}
	fail := func(status int, class, msg string) (session, bool) {
		_ = s.record(r, audit.Entry{Principal: sess.id.User.Username, Role: string(sess.id.User.Role),
			ServerID: v.serverID, Action: string(action), Result: audit.ResultDenied, ErrorClass: class})
		v.Error, v.CodeInvalid = msg, true
		s.renderConfirm(w, r, sess, v, status)
		return session{}, false
	}
	if code == "" {
		return fail(http.StatusUnauthorized, "stepup_required", "Enter the 6-digit code from your authenticator to confirm.")
	}
	if ok, wait := s.ipLimit.allow("stepup:" + clientIP(r)); !ok {
		setRetryAfter(w, wait)
		return fail(http.StatusTooManyRequests, "rate_limited", "Too many attempts. "+tryAgainIn(wait))
	}
	token, next, err := s.d.Auth.StepUp(r.Context(), sess.token, code)
	var locked *auth.LockedOutError
	switch {
	case err == nil:
		http.SetCookie(w, s.d.Auth.SessionCookieFor(token, next))
		s.auditStepUp(r, sess, audit.ResultOK, "")
		id := sess.id
		id.Session = next
		return session{id: id, token: token, view: sess.view}, true
	case errors.Is(err, auth.ErrSessionInvalid):
		http.SetCookie(w, auth.ClearSessionCookie())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return session{}, false
	case errors.As(err, &locked):
		s.auditStepUp(r, sess, audit.ResultDenied, "totp_locked_out")
		setRetryAfter(w, locked.RetryAfter)
		return fail(http.StatusTooManyRequests, "stepup_required", msgLockedOut)
	case errors.Is(err, auth.ErrInvalidCredentials):
		s.auditStepUp(r, sess, audit.ResultDenied, "totp")
		return fail(http.StatusUnauthorized, "stepup_required", msgBadCode)
	default:
		s.d.Logger.Error("ui inline step-up failed", "err", err)
		return fail(http.StatusInternalServerError, "stepup_required", msgUnavailable)
	}
}
