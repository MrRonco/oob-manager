package ui

import (
	"errors"
	"net/http"

	"oob-manager/internal/admin"
)

// formEnrolLink is the CSRF form name of the one-time link page.
const formEnrolLink = "enrol-link"

const msgLinkInvalid = "This enrollment link is invalid, already used or expired. Ask your administrator for a new one."

type enrolLinkView struct {
	CSRF      string
	Action    string // the form's own URL (/enroll/<token>)
	Username  string
	Reset     bool
	Expires   string
	FormError string
}

// enrolLinkPage checks a one-time link without using it and asks for a new password.
// The token in the path is the credential (settings_design.md §4); it is never logged.
func (s *server) enrolLinkPage(w http.ResponseWriter, r *http.Request) {
	if !s.linkGate(w, r) {
		return
	}
	token := r.PathValue("token")
	info, err := s.d.Admin.LookupLink(r.Context(), token)
	if err != nil {
		s.linkFailed(w, r, err)
		return
	}
	s.renderEnrolLink(w, r, http.StatusOK, enrolLinkView{Username: info.Username,
		Reset: info.Purpose == "reset", Expires: fmtFor(s.viewFor(r.Context(), "")).full(info.ExpiresAt)})
}

func (s *server) renderEnrolLink(w http.ResponseWriter, r *http.Request, status int, v enrolLinkView) {
	pre := "pre:" + preCookie(w, r, s.d.CSRFTTL)
	v.CSRF, v.Action = s.csrf.issue(formEnrolLink, pre), "/enroll/"+r.PathValue("token")
	noStore(w)
	s.render(w, r, status, pageEnrolLink, s.baseLayout(r, "Set up your account", v))
}

// enrolLinkSubmit redeems the link: new password, fresh authenticator secret shown once,
// then the usual confirmation form (auth.ConfirmTOTP) finishes the enrolment.
func (s *server) enrolLinkSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.linkGate(w, r) {
		return
	}
	form, ok := parseForm(w, r)
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	token := r.PathValue("token")
	info, err := s.d.Admin.LookupLink(r.Context(), token)
	if err != nil {
		s.linkFailed(w, r, err)
		return
	}
	v := enrolLinkView{Username: info.Username, Reset: info.Purpose == "reset", Expires: fmtFor(s.viewFor(r.Context(), "")).full(info.ExpiresAt)}
	if !s.csrf.verify(form.Get(csrfField), formEnrolLink, preBinding(r)) {
		s.denied(r, "auth.enrol", "csrf")
		v.FormError = msgFormExpired
		s.renderEnrolLink(w, r, http.StatusForbidden, v)
		return
	}
	if form.Get("password") != form.Get("confirm") {
		v.FormError = "The two passwords do not match."
		s.renderEnrolLink(w, r, http.StatusBadRequest, v)
		return
	}
	enr, user, err := s.d.Admin.RedeemLink(r.Context(), token, form.Get("password"), clientIP(r))
	switch {
	case errors.Is(err, admin.ErrInvalidInput):
		v.FormError = "The password must be 12 to 256 characters."
		s.renderEnrolLink(w, r, http.StatusBadRequest, v)
		return
	case err != nil:
		s.linkFailed(w, r, err)
		return
	}
	pre := "pre:" + preCookie(w, r, s.d.CSRFTTL)
	rv := revealView{enrollView: enrollView{CSRF: s.csrf.issue(formEnroll, pre), Username: safeUsername(user)},
		Secret: enr.Secret, URI: enr.URL, QR: qrDataURL(enr.URL)}
	noStore(w)
	s.render(w, r, http.StatusOK, pageEnrollReveal, s.baseLayout(r, "Scan your authenticator", rv))
}

// linkGate applies the per-IP limit of the link pages (default 5/min).
func (s *server) linkGate(w http.ResponseWriter, r *http.Request) bool {
	if s.d.Admin == nil {
		s.errorPage(w, r, http.StatusNotFound, "Page not found.")
		return false
	}
	if ok, wait := s.linkLimit.allow("ip:" + clientIP(r)); !ok {
		s.denied(r, "auth.enrol", "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, msgRateLimited+" "+tryAgainIn(wait))
		return false
	}
	return true
}

func (s *server) linkFailed(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, admin.ErrLinkInvalid) {
		s.denied(r, "auth.enrol", "invalid_link")
		s.errorPage(w, r, http.StatusNotFound, msgLinkInvalid)
		return
	}
	s.d.Logger.Error("ui enrollment link failed", "err", err)
	s.errorPage(w, r, http.StatusInternalServerError, msgUnavailable)
}
