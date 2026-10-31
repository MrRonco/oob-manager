package ui

import (
	"context"
	"errors"
	"net/http"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/firstrun"
)

// FirstRun is the browser setup of the first admin on any install with no account yet
// (a store install, or a configured one whose admin was never bootstrapped), and the
// backup notice of generated keys (docs/plans/09-store-ready-install.md). Nil hides both;
// *firstrun.Service implements it.
type FirstRun interface {
	SetupOpen(ctx context.Context) bool
	Claim(ctx context.Context, code, username, password string) (auth.TOTPEnrollment, error)
	BackupPending() (identity string, pending bool)
	DismissBackup() error
}

// Form names of the first-run pages.
const (
	formSetup     = "setup"
	formKeyNotice = "key-notice"
)

// setupRate bounds /setup submissions per client address. setupDenyRate audits one
// rate-limited refusal per address a window: behind a userland proxy every client can
// share one address, and a flood must not write an audit row per request (plan 09 N1).
var (
	setupRate     = RateLimit{Events: 5, Per: time.Minute}
	setupDenyRate = RateLimit{Events: 1, Per: setupRate.Per}
)

const (
	msgSetupCode = "That setup code is not valid. Copy it again from the container log (`docker logs`); " +
		"if it has expired or was used, restart the container for a new one."
	msgSetupInput = "Choose a username of lowercase letters, digits, dots, dashes or underscores, and a password " +
		"of 12 to 256 characters."
)

type setupView struct {
	CSRF      string
	Username  string
	FormError string
}

// keyNoticeView is the admin banner while generated keys await a backup.
type keyNoticeView struct {
	Path string
	CSRF string
}

// setupOpen reports whether the first-run setup page is available.
func (s *server) setupOpen(r *http.Request) bool {
	return s.d.FirstRun != nil && s.d.FirstRun.SetupOpen(r.Context())
}

// setupPage asks for the setup code from the log, a username and a password. It exists
// only while no account exists (404 afterwards, like any unknown page).
func (s *server) setupPage(w http.ResponseWriter, r *http.Request) {
	if !s.setupOpen(r) {
		s.errorPage(w, r, http.StatusNotFound, "Page not found.")
		return
	}
	s.renderSetup(w, r, http.StatusOK, setupView{})
}

func (s *server) renderSetup(w http.ResponseWriter, r *http.Request, status int, v setupView) {
	v.CSRF = s.csrf.issue(formSetup, "pre:"+preCookie(w, r, s.d.CSRFTTL))
	v.Username = safeUsername(v.Username)
	noStore(w)
	s.render(w, r, status, pageSetup, s.baseLayout(r, "Set up oob-manager", v))
}

// setupSubmit creates the first admin: rate limit, CSRF, code, then the same bootstrap
// as the CLI. The code is a credential: it is never logged, audited or echoed back.
func (s *server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.setupOpen(r) {
		s.errorPage(w, r, http.StatusNotFound, "Page not found.")
		return
	}
	f, ok := parseForm(w, r)
	if !ok {
		s.errorPage(w, r, http.StatusBadRequest, "The form could not be read.")
		return
	}
	username := f.Get("username")
	v := setupView{Username: username}
	// Its own per-address bucket: setup traffic never charges the sign-in buckets (an
	// unauthenticated flood for "admin" must not lock out sign-in), and failed sign-ins
	// never block the administrator's claim. The 160-bit code is what keeps guessing out.
	if ok, wait := s.setupLimit.allow("setup:" + clientIP(r)); !ok {
		s.setupRateLimited(r)
		setRetryAfter(w, wait)
		v.FormError = msgRateLimited + " " + tryAgainIn(wait)
		s.renderSetup(w, r, http.StatusTooManyRequests, v)
		return
	}
	if !s.csrf.verify(f.Get(csrfField), formSetup, preBinding(r)) {
		s.denied(r, "setup.claim", "csrf")
		v.FormError = msgFormExpired
		s.renderSetup(w, r, http.StatusForbidden, v)
		return
	}
	if f.Get("password") != f.Get("confirm") {
		v.FormError = "The two passwords do not match."
		s.renderSetup(w, r, http.StatusBadRequest, v)
		return
	}
	enr, err := s.d.FirstRun.Claim(r.Context(), f.Get("code"), username, f.Get("password"))
	if err != nil {
		s.setupFailed(w, r, v, err)
		return
	}
	_ = s.record(r, audit.Entry{Principal: safeUsername(username), Action: "setup.claim", Result: audit.ResultOK,
		AuthMethod: "setup-code"})
	pre := "pre:" + preCookie(w, r, s.d.CSRFTTL)
	rv := revealView{enrollView: enrollView{CSRF: s.csrf.issue(formEnroll, pre), Username: safeUsername(username)},
		Secret: enr.Secret, URI: enr.URL, QR: qrDataURL(enr.URL)}
	noStore(w)
	s.render(w, r, http.StatusOK, pageEnrollReveal, s.baseLayout(r, "Scan your authenticator", rv))
}

// setupRateLimited audits a rate-limited claim unless the same address had one audited
// in this window (the response is the same either way).
func (s *server) setupRateLimited(r *http.Request) {
	if ok, _ := s.setupDenyLimit.allow("setup:" + clientIP(r)); ok {
		s.denied(r, "setup.claim", "rate_limited")
	}
}

func (s *server) setupFailed(w http.ResponseWriter, r *http.Request, v setupView, err error) {
	switch {
	case errors.Is(err, firstrun.ErrSetupCode):
		s.denied(r, "setup.claim", "bad_code")
		v.FormError = msgSetupCode
		s.renderSetup(w, r, http.StatusUnauthorized, v)
	case errors.Is(err, firstrun.ErrInvalidInput):
		v.FormError = msgSetupInput
		s.renderSetup(w, r, http.StatusBadRequest, v)
	case errors.Is(err, firstrun.ErrSetupClosed):
		s.denied(r, "setup.claim", "closed")
		s.renderLogin(w, r, http.StatusConflict, "An account already exists. Sign in instead.", "")
	default:
		s.d.Logger.Error("ui first-run setup failed", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, msgUnavailable)
	}
}

// keyNotice returns the backup banner for an admin session, or nil.
func (s *server) keyNotice(sess session) *keyNoticeView {
	if s.d.FirstRun == nil {
		return nil
	}
	path, pending := s.d.FirstRun.BackupPending()
	if !pending {
		return nil
	}
	return &keyNoticeView{Path: path, CSRF: s.csrf.issue(formKeyNotice, sessionBinding(sess.token))}
}

// keyNoticeDismiss acknowledges the backup of the generated identity (admin only).
func (s *server) keyNoticeDismiss(w http.ResponseWriter, r *http.Request, sess session) {
	p := sess.id.Principal()
	if err := s.d.Authorize(p, authz.AdminUsers, true); err != nil || s.d.FirstRun == nil {
		s.errorPage(w, r, http.StatusForbidden, "You do not have permission to do that.")
		return
	}
	form, ok := parseForm(w, r)
	if !ok || !s.csrf.verify(form.Get(csrfField), formKeyNotice, sessionBinding(sess.token)) {
		s.errorPage(w, r, http.StatusForbidden, msgFormExpired)
		return
	}
	// Each dismissal writes an audit row: the change limit bounds a replayed form.
	if !s.allowChange(w, r, sess, authz.AdminUsers) {
		return
	}
	// Audited first: an acknowledgement that cannot be recorded is not done (record logs
	// the failure), so the notice never disappears without its audit row.
	if err := s.record(r, audit.Entry{Principal: sess.id.User.Username, Action: "keys.backup_acknowledged",
		Result: audit.ResultOK}); err != nil {
		s.errorPage(w, r, http.StatusInternalServerError, msgUnavailable)
		return
	}
	if err := s.d.FirstRun.DismissBackup(); err != nil {
		s.d.Logger.Error("ui key backup notice dismiss failed after it was audited", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, msgUnavailable)
		return
	}
	redirectLocal(w, r, form.Get("next"))
}
