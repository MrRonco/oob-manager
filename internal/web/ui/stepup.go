package ui

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
)

// formStepUp is the CSRF form name of the step-up page.
const formStepUp = "stepup"

type stepUpPage struct {
	CSRF     string
	Next     string
	User     string
	Error    string
	Fresh    bool
	Until    string
	UntilISO string
	Action   string // what the code authorizes, named from next (UX-07)
	Window   string
	After    string // when a code entered now would expire
	// Resume is the id of a form kept for this session, submitted again after the
	// code (resume.go); "" when none is pending.
	Resume string
}

// stepUpNote is the banner partial "stepup" on pages with changes.
type stepUpNote struct {
	Fresh           bool
	Until, UntilISO string
	Next            string
	Window          string
}

func (s *server) stepUpNoteFor(r *http.Request, sess session) stepUpNote {
	until := s.d.Auth.StepUpExpires(sess.id.Session)
	return stepUpNote{Fresh: s.d.Auth.StepUpFresh(sess.id.Session), Until: sess.tf().full(until),
		UntilISO: until.UTC().Format(time.RFC3339), Next: r.URL.Path, Window: humanDuration(s.stepUpWindow())}
}

// stepUpForm shows the "confirm with your authenticator" form (security.md §3 sudo
// mode). A fresh code allows changes for the step-up window (settings_design.md §8).
func (s *server) stepUpForm(w http.ResponseWriter, r *http.Request, sess session) {
	s.renderStepUp(w, r, sess, sess.token, http.StatusOK, "")
}

func (s *server) renderStepUp(w http.ResponseWriter, r *http.Request, sess session, token string, status int, msg string) {
	next := localPath(r.FormValue("next"), "/settings")
	until := s.d.Auth.StepUpExpires(sess.id.Session)
	v := stepUpPage{CSRF: s.csrf.issue(formStepUp, sessionBinding(token)), Next: next, User: sess.id.User.Username,
		Error: msg, Fresh: s.d.Auth.StepUpFresh(sess.id.Session), Until: sess.tf().full(until),
		UntilISO: until.UTC().Format(time.RFC3339), Action: s.describeNext(r, next), Window: humanDuration(s.stepUpWindow()),
		After: sess.tf().clockOf(s.d.Now().Add(s.stepUpWindow()))}
	if id := validResume(r.FormValue("resume")); id != "" {
		if path, ok := s.pending.keptPath(id, sessionBinding(sess.token)); ok {
			v.Resume = id
			if label := keptFormLabel(path, s.fleetName); label != "" {
				v.Action = label // the kept form says exactly what will be replayed
			}
		}
	}
	s.render(w, r, status, pageStepUp, s.layoutFor(session{id: sess.id, token: token, view: sess.view}, "Confirm it is you", "", v))
}

// stepUpSubmit verifies a fresh TOTP, rotates the session (auth.StepUp) and returns to
// the page that asked for it. Codes are single-use; lockout applies as for login.
func (s *server) stepUpSubmit(w http.ResponseWriter, r *http.Request, sess session) {
	form, ok := parseForm(w, r)
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	if ok, wait := s.ipLimit.allow("stepup:" + clientIP(r)); !ok {
		s.auditStepUp(r, sess, audit.ResultDenied, "rate_limited")
		setRetryAfter(w, wait)
		s.renderStepUp(w, r, sess, sess.token, http.StatusTooManyRequests, msgRateLimited+" "+tryAgainIn(wait))
		return
	}
	if !s.csrf.verify(form.Get(csrfField), formStepUp, sessionBinding(sess.token)) {
		s.auditStepUp(r, sess, audit.ResultDenied, "csrf")
		s.renderStepUp(w, r, sess, sess.token, http.StatusForbidden, msgFormExpired)
		return
	}
	token, next, err := s.d.Auth.StepUp(r.Context(), sess.token, form.Get("code"))
	if err != nil {
		s.stepUpFailed(w, r, sess, err)
		return
	}
	http.SetCookie(w, s.d.Auth.SessionCookieFor(token, next))
	s.auditStepUp(r, sess, audit.ResultOK, "")
	if f, ok := s.pending.take(validResume(form.Get("resume")), sessionBinding(sess.token)); ok {
		s.replay(w, r, f, token) // the kept form runs as if it had just been sent
		return
	}
	redirectLocal(w, r, localPath(form.Get("next"), "/settings"))
}

func (s *server) stepUpFailed(w http.ResponseWriter, r *http.Request, sess session, err error) {
	var locked *auth.LockedOutError
	switch {
	case errors.Is(err, auth.ErrSessionInvalid):
		http.SetCookie(w, auth.ClearSessionCookie())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	case errors.As(err, &locked):
		s.auditStepUp(r, sess, audit.ResultDenied, "totp_locked_out")
		setRetryAfter(w, locked.RetryAfter)
		s.renderStepUp(w, r, sess, sess.token, http.StatusTooManyRequests, msgLockedOut)
	case errors.Is(err, auth.ErrInvalidCredentials):
		s.auditStepUp(r, sess, audit.ResultDenied, "totp")
		s.renderStepUp(w, r, sess, sess.token, http.StatusUnauthorized, msgBadCode)
	default:
		s.d.Logger.Error("ui step-up failed", "err", err)
		s.renderStepUp(w, r, sess, sess.token, http.StatusInternalServerError, msgUnavailable)
	}
}

func (s *server) auditStepUp(r *http.Request, sess session, result, class string) {
	_ = s.record(r, audit.Entry{Principal: sess.id.User.Username, Role: string(sess.id.User.Role),
		Action: "auth.stepup", Result: result, ErrorClass: class})
}

// describeNext names the action a step-up authorizes, from the page it returns to. The
// label is chosen from a closed set; only a configured server's name is interpolated.
func (s *server) describeNext(r *http.Request, next string) string {
	switch {
	case strings.HasSuffix(next, "/console"):
		if name := s.serverNameIn(next, "/console"); name != "" {
			return "Open the graphical console · " + name
		}
	case strings.HasSuffix(next, "/security"):
		if name := s.serverNameIn(next, "/security"); name != "" {
			return "Accept or remove security risks · " + name
		}
	case strings.HasSuffix(next, "/serial"):
		if name := s.serverNameIn(next, "/serial"); name != "" {
			return "Open the serial console · " + name
		}
	case strings.HasPrefix(next, "/servers/") && strings.Contains(next, "/power/"):
		if label := s.describePower(next); label != "" {
			return label
		}
	case strings.HasSuffix(next, "/bmc/reset"):
		if label := s.describeBMC(next); label != "" {
			return label
		}
	case strings.HasPrefix(next, "/settings/users/"):
		id := strings.SplitN(strings.TrimPrefix(next, "/settings/users/"), "/", 2)[0]
		if s.d.Admin != nil && validUserID(id) {
			if u, err := s.d.Admin.User(r.Context(), id); err == nil {
				return "Change account · " + u.Username
			}
		}
		return "Change user accounts"
	case strings.HasPrefix(next, "/settings/users"):
		return "Change user accounts"
	case strings.HasPrefix(next, "/settings/tokens"):
		return "Manage API tokens"
	case strings.HasPrefix(next, "/settings/audit"):
		return "Verify the audit chain"
	case next == "/settings/servers/new":
		return "Add server"
	case strings.HasPrefix(next, "/settings/servers/"):
		if name := s.managedServerName(strings.TrimPrefix(next, "/settings/servers/")); name != "" {
			return "Change server · " + name
		}
		return "Change servers"
	case strings.HasPrefix(next, "/settings/servers"):
		return "Change servers"
	case strings.HasPrefix(next, "/settings/general"):
		return "Change general settings"
	case strings.HasPrefix(next, "/settings/notifications"):
		return "Change notifications"
	}
	return "Make changes"
}

// managedServerName is the configured name of a server in Settings → Servers ("" when
// the id has another shape or names no server).
func (s *server) managedServerName(id string) string {
	if s.d.Servers == nil || !serverIDPattern.MatchString(id) {
		return ""
	}
	if x, ok := s.d.Servers.Current().Entry(id); ok {
		return x.Server.Name
	}
	return ""
}

// serverNameIn returns the configured name of the server in a "/servers/{id}<suffix>"
// path, "" when the path has another shape or names no configured server.
func (s *server) serverNameIn(path, suffix string) string {
	id, ok := strings.CutPrefix(strings.TrimSuffix(path, suffix), "/servers/")
	if !ok || !serverIDPattern.MatchString(id) {
		return ""
	}
	if v, found := s.d.Fleet.Server(id); found {
		return v.Name
	}
	return ""
}
