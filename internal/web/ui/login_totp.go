package ui

import (
	"errors"
	"net/http"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
)

// totpSubmit is the second login stage. On success the pending session is replaced by
// a full one under a new ID (auth rotates it) and the login is audited; if the audit
// write fails the new session is discarded, so no login goes unrecorded.
func (s *server) totpSubmit(w http.ResponseWriter, r *http.Request) {
	token, ok := auth.SessionTokenFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	form, ok := parseForm(w, r)
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	if ok, wait := s.ipLimit.allow("totp:" + clientIP(r)); !ok {
		s.loginDenied(w, r, "totp_rate_limited")
		setRetryAfter(w, wait)
		s.renderTOTP(w, r, token, http.StatusTooManyRequests, msgRateLimited+" "+tryAgainIn(wait))
		return
	}
	if !s.csrf.verify(form.Get(csrfField), formTOTP, sessionBinding(token)) {
		s.loginDenied(w, r, "csrf")
		s.renderTOTP(w, r, token, http.StatusForbidden, msgFormExpired)
		return
	}
	full, sess, err := s.d.Auth.CompleteLogin(r.Context(), token, form.Get("code"), clientIP(r), r.UserAgent())
	if errors.Is(err, auth.ErrSessionInvalid) {
		s.loginDenied(w, r, "pending_expired")
		http.SetCookie(w, auth.ClearSessionCookie())
		s.renderLogin(w, r, http.StatusUnauthorized, msgExpired, "")
		return
	}
	if err != nil {
		s.loginError(w, r, "totp", err, func(st int, msg string) { s.renderTOTP(w, r, token, st, msg) })
		return
	}
	if !s.auditLogin(r, full) {
		_ = s.d.Auth.Logout(r.Context(), full)
		http.SetCookie(w, auth.ClearSessionCookie())
		s.renderLogin(w, r, http.StatusInternalServerError, msgUnavailable, "")
		return
	}
	http.SetCookie(w, s.d.Auth.SessionCookieFor(full, sess))
	clearPreCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// auditLogin records a completed login with the user's name and role.
func (s *server) auditLogin(r *http.Request, token string) bool {
	id, err := s.d.Auth.Authenticate(r.Context(), token)
	if err != nil {
		s.d.Logger.Error("ui new session unusable", "err", err)
		return false
	}
	return s.record(r, audit.Entry{Principal: id.User.Username, Role: string(id.User.Role),
		Action: "auth.login", Result: audit.ResultOK}) == nil
}

// logout needs the session's CSRF token; without it the request is refused and nothing
// changes (a cross-site page cannot log the user out). Otherwise the server-side session
// is deleted, the cookie cleared and the browser sent to the login page.
func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	token, ok := auth.SessionTokenFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	form, ok := parseForm(w, r)
	if !ok || !s.csrf.verify(form.Get(csrfField), formLogout, sessionBinding(token)) {
		s.errorPage(w, r, http.StatusForbidden, msgFormExpired)
		return
	}
	principal, role := anonymous, ""
	if id, err := s.d.Auth.Authenticate(r.Context(), token); err == nil {
		principal, role = id.User.Username, string(id.User.Role)
	}
	if err := s.d.Auth.Logout(r.Context(), token); err != nil {
		s.d.Logger.Error("ui logout failed", "err", err)
	}
	_ = s.record(r, audit.Entry{Principal: principal, Role: role, Action: "auth.logout", Result: audit.ResultOK})
	http.SetCookie(w, auth.ClearSessionCookie())
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
