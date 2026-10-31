package ui

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
)

// formSettings is the CSRF form name of every Settings change form. Tokens are bound to
// the session, and the session ID rotates on step-up, so a token is only valid for the
// session (and step-up) it was rendered in.
const formSettings = "settings"

// changeHandler handles an authorized, CSRF-checked, rate-limited Settings change.
type changeHandler func(w http.ResponseWriter, r *http.Request, sess session, form url.Values)

// settingsView is a read-only Settings page: authenticated, authorized for a view
// action, and only when the Settings backend is wired.
func (s *server) settingsView(action authz.Action, h pageHandler) http.Handler {
	return s.page(action, func(w http.ResponseWriter, r *http.Request, sess session) {
		if s.d.Admin == nil || s.d.AuditLog == nil {
			s.errorPage(w, r, http.StatusNotFound, "Settings are not available in this installation.")
			return
		}
		h(w, r, sess)
	})
}

// change wraps every mutating Settings route. Order: session, CSRF, authz (role and a
// fresh step-up: settings_design.md §8 decision 1), per-user rate limit, handler.
// Every refusal is audited. back is where to return after a step-up.
func (s *server) change(action authz.Action, back func(*http.Request) string, h changeHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, form, ok := s.changeForm(w, r, action)
		if ok && s.authorizeChange(w, r, sess, action, back(r)) && s.allowChange(w, r, sess, action) {
			h(w, r, sess, form)
		}
	})
}

// probe is change() for requests that reach a BMC without changing anything
// (fingerprint fetch, Test connection): the handler applies its own per-user limit
// (security.md §3) instead of the change limit.
func (s *server) probe(action authz.Action, back func(*http.Request) string, h changeHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, form, ok := s.changeForm(w, r, action)
		if ok && s.authorizeChange(w, r, sess, action, back(r)) {
			h(w, r, sess, form)
		}
	})
}

// authorizeChange applies authz; a missing step-up redirects to the step-up page, keeping
// a posted form for replay.
func (s *server) authorizeChange(w http.ResponseWriter, r *http.Request, sess session, action authz.Action, back string) bool {
	err := s.d.Authorize(sess.id.Principal(), action, s.d.Auth.StepUpFresh(sess.id.Session))
	switch {
	case err == nil:
		return true
	case errors.Is(err, authz.ErrStepUpRequired):
		s.deny(r, sess, action, "stepup_required")
		// The posted form is kept and resumed after the code (resume.go, audit R2-03).
		http.Redirect(w, r, s.stepUpURL(r, sess, back), http.StatusSeeOther) //nolint:gosec // G710: a fixed path with url.Values-encoded parameters

	default:
		s.deny(r, sess, action, "forbidden")
		s.errorPage(w, r, http.StatusForbidden, "You do not have permission to change settings.")
	}
	return false
}

func (s *server) deny(r *http.Request, sess session, action authz.Action, class string) {
	_ = s.record(r, audit.Entry{Principal: sess.id.User.Username, Role: string(sess.id.User.Role),
		ServerID: s.auditServerID(r), Action: string(action), Result: audit.ResultDenied, ErrorClass: class})
}

// auditServerID is the configured server a "/servers/{id}/..." request is about, so a
// refusal of any server-scoped action (power, fan, consoles) names it; "" otherwise.
func (s *server) auditServerID(r *http.Request) string {
	if !strings.HasPrefix(r.URL.Path, "/servers/") {
		return ""
	}
	id := r.PathValue("id")
	if !serverIDPattern.MatchString(id) {
		return ""
	}
	if _, ok := s.d.Fleet.Server(id); !ok {
		return ""
	}
	return id
}

// actor is the audit identity of a browser change.
func actor(r *http.Request, sess session) admin.Actor {
	return admin.Actor{UserID: sess.id.User.ID, Username: sess.id.User.Username, Role: sess.id.User.Role,
		IP: clientIP(r), Method: "local"}
}

// adminError maps a service error to a status and an admin-safe message.
func (s *server) adminError(err error) (int, string) {
	switch {
	case errors.Is(err, admin.ErrInvalidInput):
		return http.StatusBadRequest, err.Error()
	case errors.Is(err, admin.ErrUsernameTaken), errors.Is(err, admin.ErrRefused):
		return http.StatusConflict, err.Error()
	case errors.Is(err, admin.ErrNotFound):
		return http.StatusNotFound, "It no longer exists."
	default:
		s.d.Logger.Error("ui settings change failed", "err", err)
		return http.StatusInternalServerError, "The change could not be saved. Nothing was changed."
	}
}

func (s *server) failChange(w http.ResponseWriter, r *http.Request, err error) {
	status, msg := s.adminError(err)
	s.errorPage(w, r, status, msg)
}

// doneMessage is the confirmation after a change (?done=<key>): a closed set, so
// nothing from the URL is ever echoed.
func doneMessage(key string) string {
	switch key {
	case "role":
		return "Role changed."
	case "role-unchanged":
		return "Role unchanged."
	case "disabled":
		return "User disabled. Their sessions and unused links have ended."
	case "enabled":
		return "User enabled."
	case "revoked":
		return "Session ended."
	case "revoked-all":
		return "All sessions of this user ended."
	case "token-revoked":
		return "Token revoked. It stops working immediately."
	case "general":
		return "Settings saved. They apply at once unless marked \"applies after a restart\"."
	case "general-unchanged":
		return "Nothing changed."
	case "catalog-imported":
		return "Catalog imported. The Firmware page shows its updates."
	case "catalog-held":
		return "Catalog imported but held: it lists far fewer components than the one in use. Confirm it below to use it."
	case "catalog-confirmed":
		return "The held catalog is now in use."
	case "general-reset":
		return "Setting reset to its default."
	case "server-created":
		return "Server added, disabled. Store its read-only login next, then enable it."
	case "server-saved":
		return "Saved. A running server picks the change up at once."
	case "server-unchanged":
		return "Nothing changed."
	case "server-moved":
		return "Moved: its credentials were deleted and the other fingerprints cleared, and it is disabled. Enter them again, then enable it."
	case "server-pin":
		return "Fingerprint saved. The stored credentials are kept."
	case "server-credential":
		return "Credential stored. It is never shown again."
	case "server-enabled":
		return "Server enabled. It is polled from now on."
	case "server-disabled":
		return "Server disabled. Polling stopped; its settings and credentials are kept."
	case "server-deleted":
		return "Server removed."
	case "server-test":
		return "Connection test started. This page refreshes until it finishes."
	default:
		return ""
	}
}

// settingsLayout is the chrome of a Settings page.
func (s *server) settingsLayout(r *http.Request, sess session, title string, body any) layoutData {
	d := s.layoutFor(sess, title, navSettings, body)
	d.Crumbs = []crumb{{"Settings", "/settings"}, {Label: title}}
	if msg := doneMessage(r.URL.Query().Get("done")); msg != "" {
		d.Flash, d.FlashKind = msg, "info"
	}
	return d
}

// noStore marks a response that shows a secret once (never cached, never a redirect).
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
