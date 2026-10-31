package ui

import (
	"bytes"
	"encoding/base64"
	"html/template"
	"image/png"
	"net/http"
	"strings"

	"github.com/pquerna/otp"

	"oob-manager/internal/audit"
)

// qrSize is the enrolment QR code edge in pixels.
const qrSize = 200

type enrollView struct {
	CSRF       string
	RevealCSRF string // "" when no Enroller is wired
	Username   string
	Error      string
}

// revealView is the one place a TOTP secret is ever rendered. The page is no-store
// (web.SecurityHeaders) and nothing here is logged.
type revealView struct {
	enrollView
	Secret string
	URI    string
	QR     template.URL // data:image/png;base64,… generated here, never user input
}

func (s *server) enrollPage(w http.ResponseWriter, r *http.Request) {
	s.renderEnroll(w, r, http.StatusOK, "", "")
}

func (s *server) renderEnroll(w http.ResponseWriter, r *http.Request, status int, msg, username string) {
	pre := "pre:" + preCookie(w, r, s.d.CSRFTTL)
	v := enrollView{CSRF: s.csrf.issue(formEnroll, pre), Username: safeUsername(username), Error: msg}
	if s.d.Enroller != nil {
		v.RevealCSRF = s.csrf.issue(formReveal, pre)
	}
	s.render(w, r, status, pageEnroll, s.baseLayout(r, "Set up your authenticator", v))
}

// safeUsername echoes a username back into a form only if it is well formed.
func safeUsername(u string) string {
	if usernamePattern.MatchString(u) {
		return u
	}
	return ""
}

// enrollGate runs the shared checks of both enrolment POSTs: body, rate limit, CSRF.
func (s *server) enrollGate(w http.ResponseWriter, r *http.Request, form string) (username, password, code string, ok bool) {
	f, ok := parseForm(w, r)
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "The form could not be read.")
		return "", "", "", false
	}
	username, password, code = f.Get("username"), f.Get("password"), f.Get("code")
	if wait, ok := s.allowLogin(clientIP(r), username); !ok {
		s.enrollDenied(r, "rate_limited")
		setRetryAfter(w, wait)
		s.renderEnroll(w, r, http.StatusTooManyRequests, msgRateLimited+" "+tryAgainIn(wait), username)
		return "", "", "", false
	}
	if !s.csrf.verify(f.Get(csrfField), form, preBinding(r)) {
		s.enrollDenied(r, "csrf")
		s.renderEnroll(w, r, http.StatusForbidden, msgFormExpired, username)
		return "", "", "", false
	}
	return username, password, code, true
}

func (s *server) enrollDenied(r *http.Request, class string) {
	s.denied(r, "auth.totp.enroll", class)
}

// enrollSubmit confirms the authenticator: password + a current code (auth.ConfirmTOTP).
func (s *server) enrollSubmit(w http.ResponseWriter, r *http.Request) {
	username, password, code, ok := s.enrollGate(w, r, formEnroll)
	if !ok {
		return
	}
	err := s.d.Auth.ConfirmTOTP(r.Context(), username, password, code, clientIP(r))
	if err != nil {
		s.loginError(w, r, "enroll", err, func(st int, _ string) {
			s.renderEnroll(w, r, st, enrollMessage(st), username)
		})
		return
	}
	_ = s.record(r, audit.Entry{Principal: username, Action: "auth.totp.enroll", Result: audit.ResultOK})
	s.renderLogin(w, r, http.StatusOK, msgEnrolled, "info")
}

func enrollMessage(status int) string {
	switch status {
	case http.StatusTooManyRequests:
		return msgLockedOut
	case http.StatusUnauthorized:
		return "Invalid username, password or code."
	default:
		return msgUnavailable
	}
}

// enrollReveal shows the pending secret again (Enroller wired only).
func (s *server) enrollReveal(w http.ResponseWriter, r *http.Request) {
	if s.d.Enroller == nil {
		s.errorPage(w, r, http.StatusNotFound, "Page not found.")
		return
	}
	username, password, _, ok := s.enrollGate(w, r, formReveal)
	if !ok {
		return
	}
	enr, err := s.d.Enroller.RevealEnrollment(r.Context(), username, password, clientIP(r))
	if err != nil {
		s.loginError(w, r, "enroll_reveal", err, func(st int, _ string) {
			s.renderEnroll(w, r, st, enrollMessage(st), username)
		})
		return
	}
	_ = s.record(r, audit.Entry{Principal: username, Action: "auth.totp.reveal", Result: audit.ResultOK})
	pre := "pre:" + preCookie(w, r, s.d.CSRFTTL)
	v := revealView{enrollView: enrollView{CSRF: s.csrf.issue(formEnroll, pre), Username: safeUsername(username)},
		Secret: enr.Secret, URI: enr.URL, QR: qrDataURL(enr.URL)}
	noStore(w)
	s.render(w, r, http.StatusOK, pageEnrollReveal, s.baseLayout(r, "Scan your authenticator", v))
}

// qrDataURL renders the otpauth URI as an inline PNG (CSP allows img-src data:). It
// returns "" if the URI cannot be encoded; the page then shows only the text secret.
func qrDataURL(uri string) template.URL {
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		return ""
	}
	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		return ""
	}
	img, err := key.Image(qrSize, qrSize)
	if err != nil {
		return ""
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return ""
	}
	// #nosec G203 -- the data URL is generated here from PNG bytes, not from input.
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes()))
}

// Grouped is the secret in blocks of four for typing (UX-13): authenticator apps ignore
// the spaces.
func (v revealView) Grouped() string {
	var b strings.Builder
	for i, r := range v.Secret {
		if i > 0 && i%4 == 0 {
			b.WriteByte(' ')
		}
		b.WriteRune(r)
	}
	return b.String()
}
