package ui

import (
	"errors"
	"net/http"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
)

// User-facing messages. They never say which part of a login failed (security.md S1).
const (
	msgBadLogin    = "Invalid username or password."
	msgBadCode     = "Invalid or already used code."
	msgRateLimited = "Too many attempts."
	msgLockedOut   = "Too many failed attempts. Try again later."
	msgExpired     = "Your sign-in expired. Start again."
	msgFormExpired = "The form expired. Please try again."
	msgUnavailable = "Sign-in is temporarily unavailable. Try again."
	msgEnrolled    = "Authenticator confirmed. You can sign in now."
)

const anonymous = "anonymous"

// loginView: the error sits inside the form and is tied to the fields
// (aria-describedby), and a well-formed username is kept after a failure (UI review F-13).
type loginView struct {
	CSRF     string
	Username string
	Error    string
	Info     string
	Instance string
	// SetupOpen links to /setup while no account exists (plan 09).
	SetupOpen bool
}

type totpView struct {
	CSRF     string
	Username string // who is signing in, from the pending session
	Error    string
}

func (s *server) loginPage(w http.ResponseWriter, r *http.Request) {
	if s.signedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderLogin(w, r, http.StatusOK, "", "")
}

// signedIn reports whether r carries a valid full session.
func (s *server) signedIn(r *http.Request) bool {
	token, ok := auth.SessionTokenFromRequest(r)
	if !ok {
		return false
	}
	_, err := s.d.Auth.Authenticate(r.Context(), token)
	return err == nil
}

// renderLogin shows the sign-in form; kind "info" shows msg as a confirmation,
// anything else as the form's error.
func (s *server) renderLogin(w http.ResponseWriter, r *http.Request, status int, msg, kind string) {
	pre := preCookie(w, r, s.d.CSRFTTL)
	v := loginView{CSRF: s.csrf.issue(formLogin, "pre:"+pre), Instance: s.instanceName(), SetupOpen: s.setupOpen(r)}
	if kind == "info" {
		v.Info = msg
	} else {
		v.Error = msg
	}
	if r.Method == http.MethodPost && msg != "" && kind != "info" {
		v.Username = safeUsername(r.PostFormValue("username"))
	}
	s.render(w, r, status, pageLogin, s.baseLayout(r, "Sign in", v))
}

// loginSubmit is the password stage. Order: per-IP and per-account rate limit (cheap,
// before argon2), CSRF, then auth. The typed username is never logged or audited: a
// password pasted into the wrong field would otherwise end up in the audit log.
func (s *server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	form, ok := parseForm(w, r)
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	username, password := form.Get("username"), form.Get("password")
	if wait, ok := s.allowLogin(clientIP(r), username); !ok {
		s.loginDenied(w, r, "rate_limited")
		setRetryAfter(w, wait)
		s.renderLogin(w, r, http.StatusTooManyRequests, msgRateLimited+" "+tryAgainIn(wait), "")
		return
	}
	if !s.csrf.verify(form.Get(csrfField), formLogin, preBinding(r)) {
		s.loginDenied(w, r, "csrf")
		s.renderLogin(w, r, http.StatusForbidden, msgFormExpired, "")
		return
	}
	token, err := s.d.Auth.BeginLogin(r.Context(), auth.LoginRequest{
		Username: username, Password: password, IP: clientIP(r), UserAgent: r.UserAgent()})
	if err != nil {
		s.loginError(w, r, "password", err, func(st int, msg string) { s.renderLogin(w, r, st, msg, "") })
		return
	}
	http.SetCookie(w, auth.SessionCookie(token, s.d.PendingTTL))
	http.Redirect(w, r, "/login/totp", http.StatusSeeOther)
}

// allowLogin applies the per-IP limit and, for well-formed usernames, the per-account
// limit (security.md §3). Malformed names never create limiter keys.
func (s *server) allowLogin(ip, username string) (time.Duration, bool) {
	if ok, wait := s.ipLimit.allow("ip:" + ip); !ok {
		return wait, false
	}
	if usernamePattern.MatchString(username) {
		if ok, wait := s.acctLimit.allow("acct:" + username); !ok {
			return wait, false
		}
	}
	return 0, true
}

func (s *server) loginDenied(_ http.ResponseWriter, r *http.Request, class string) {
	s.denied(r, "auth.login", class)
}

// denied audits a refused pre-session request.
func (s *server) denied(r *http.Request, action, class string) {
	_ = s.record(r, audit.Entry{Principal: anonymous, Action: action, Result: audit.ResultDenied, ErrorClass: class})
}

// stageAction is the audit action of each login/enrolment stage.
func stageAction(stage string) string {
	switch stage {
	case "enroll":
		return "auth.totp.enroll"
	case "enroll_reveal":
		return "auth.totp.reveal"
	default:
		return "auth.login"
	}
}

// loginError maps an auth error to a status and message and audits it.
func (s *server) loginError(w http.ResponseWriter, r *http.Request, stage string, err error,
	show func(status int, msg string)) {
	var locked *auth.LockedOutError
	switch {
	case errors.As(err, &locked):
		s.denied(r, stageAction(stage), stage+"_locked_out")
		setRetryAfter(w, locked.RetryAfter)
		show(http.StatusTooManyRequests, msgLockedOut)
	case errors.Is(err, auth.ErrInvalidCredentials):
		s.denied(r, stageAction(stage), stage)
		msg := msgBadLogin
		if stage == "totp" {
			msg = msgBadCode
		}
		show(http.StatusUnauthorized, msg)
	default:
		s.d.Logger.Error("ui login failed", "stage", stage, "err", err)
		show(http.StatusInternalServerError, msgUnavailable)
	}
}

func (s *server) totpPage(w http.ResponseWriter, r *http.Request) {
	token, ok := auth.SessionTokenFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if s.signedIn(r) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderTOTP(w, r, token, http.StatusOK, "")
}

func (s *server) renderTOTP(w http.ResponseWriter, r *http.Request, token string, status int, msg string) {
	user, _ := s.d.Auth.PendingUsername(r.Context(), token)
	s.render(w, r, status, pageTOTP, s.baseLayout(r, "Authenticator code",
		totpView{CSRF: s.csrf.issue(formTOTP, sessionBinding(token)), Username: user, Error: msg}))
}
