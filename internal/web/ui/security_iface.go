package ui

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"oob-manager/internal/admin"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmcsec"
	"oob-manager/internal/fleet"
)

// Security is the BMC security check panel (*bmcsec.Service, tech_doc §31). Reads are
// lock-free evaluations of the pollers' last posture: a page view never reaches a BMC.
type Security interface {
	Available() bool
	Report(serverID string) (bmcsec.Report, bool)
	Status(serverID string) bmcsec.RunStatus
	// Accept accepts the finding the admin saw: seen is Finding.Seen() as the form
	// carried it; bmcsec.ErrChanged when the finding differs now.
	Accept(ctx context.Context, a admin.Actor, serverID, checkID, comment, seen string) error
	Unaccept(ctx context.Context, a admin.Actor, serverID, checkID string) error
	Rerun(ctx context.Context, a admin.Actor, serverID string) error
}

// checkIDPattern is the shape of a catalog check ID; the service looks it up.
var checkIDPattern = regexp.MustCompile(`^[a-z]+\.[a-z0-9_]{1,40}$`)

// seenPattern is the shape of the accept form's "seen" field: the result that can be
// accepted and the SHA-256 (hex) of the finding's subject.
var seenPattern = regexp.MustCompile(`^(warn|fail)\|[0-9a-f]{64}$`)

// changedNotice is shown when the finding is not the one the page showed.
const changedNotice = "This finding changed since the page was loaded; review it again. Nothing was accepted."

// securityRoutes: the Security tab (viewer: summary; operator: findings) and the admin
// changes, through annotate() (session, CSRF, role, per-user limit, refusals audited).
func (s *server) securityRoutes(mux *http.ServeMux) {
	mux.Handle("GET /servers/{id}/security", s.page(authz.ViewServer, s.securityPage))
	mux.Handle("POST /servers/{id}/security/rerun", s.annotate(authz.SecurityRerun, backToSecurity, s.rerunSecurity))
	mux.Handle("POST /servers/{id}/security/accept", s.annotate(authz.SecurityAccept, backToSecurity, s.acceptFinding))
	mux.Handle("POST /servers/{id}/security/accept/remove", s.annotate(authz.SecurityAccept, backToSecurity, s.unacceptFinding))
}

func backToSecurity(r *http.Request) string { return "/servers/" + r.PathValue("id") + "/security" }

// secServer resolves {id} for a security change: a configured server and a wired
// service, or a 404 page.
func (s *server) secServer(w http.ResponseWriter, r *http.Request) (ServerView, bool) {
	id := r.PathValue("id")
	if s.d.Security != nil && s.d.Security.Available() && serverIDPattern.MatchString(id) {
		if v, ok := s.d.Fleet.Server(id); ok {
			return v, true
		}
	}
	s.errorPage(w, r, http.StatusNotFound, "There is no such server.")
	return ServerView{}, false
}

func (s *server) rerunSecurity(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	v, ok := s.secServer(w, r)
	if !ok {
		return
	}
	if err := s.d.Security.Rerun(r.Context(), actor(r, sess), v.ID); err != nil {
		s.securityFailed(w, r, "re-run the security checks", err)
		return
	}
	http.Redirect(w, r, "/servers/"+v.ID+"/security?done=rerun", http.StatusSeeOther)
}

func (s *server) acceptFinding(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	v, ok := s.secServer(w, r)
	if !ok {
		return
	}
	check, seen := form.Get("check"), form.Get("seen")
	switch {
	case !checkIDPattern.MatchString(check):
		s.errorPage(w, r, http.StatusBadRequest, "Unknown check.")
		return
	case !seenPattern.MatchString(seen):
		s.errorPage(w, r, http.StatusBadRequest, "The form could not be read. Reload the page.")
		return
	}
	err := s.d.Security.Accept(r.Context(), actor(r, sess), v.ID, check, form.Get("comment"), seen)
	switch {
	case errors.Is(err, bmcsec.ErrChanged):
		s.renderSecurity(w, r, sess, v, http.StatusConflict, changedNotice)
	case err != nil:
		s.securityFailed(w, r, "accept a security finding", err)
	default:
		redirectLocal(w, r, "/servers/"+v.ID+"/security?done=accepted#"+checkAnchor(check))
	}
}

func (s *server) unacceptFinding(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
	v, ok := s.secServer(w, r)
	if !ok {
		return
	}
	check := form.Get("check")
	if !checkIDPattern.MatchString(check) {
		s.errorPage(w, r, http.StatusBadRequest, "Unknown check.")
		return
	}
	if err := s.d.Security.Unaccept(r.Context(), actor(r, sess), v.ID, check); err != nil {
		s.securityFailed(w, r, "remove an accepted risk", err)
		return
	}
	redirectLocal(w, r, "/servers/"+v.ID+"/security?done=unaccepted#"+checkAnchor(check))
}

// securityFailed maps a service error to a page. Validation messages are the service's
// own (safe to show); anything else is logged and answered generically.
func (s *server) securityFailed(w http.ResponseWriter, r *http.Request, what string, err error) {
	var cd *bmcsec.CooldownError
	switch {
	case errors.As(err, &cd):
		setRetryAfter(w, cd.Left)
		s.errorPage(w, r, http.StatusTooManyRequests, "The checks of this server ran moments ago. "+tryAgainIn(cd.Left))
	case errors.Is(err, bmcsec.ErrInvalid):
		s.errorPage(w, r, http.StatusUnprocessableEntity, serviceText(err, "bmcsec: invalid input: "))
	case errors.Is(err, bmcsec.ErrNotProblem):
		s.errorPage(w, r, http.StatusConflict, "Only a warning or a failure can be accepted as a risk; this check no longer reports one.")
	case errors.Is(err, fleet.ErrPaused):
		s.errorPage(w, r, http.StatusConflict, "Polling of this server is paused because its certificate no longer matches the "+
			"pinned fingerprint. Confirm the new fingerprint in Settings → Servers first.")
	case errors.Is(err, bmcsec.ErrNotFound), errors.Is(err, bmcsec.ErrUnavailable), errors.Is(err, fleet.ErrNoPosture),
		errors.Is(err, fleet.ErrUnknownServer):
		s.errorPage(w, r, http.StatusNotFound, "It no longer exists.")
	default:
		s.d.Logger.Error("ui failed to "+what, "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "That did not work. Nothing was changed.")
	}
}

// serviceText is the user-facing part of a service validation error.
func serviceText(err error, prefix string) string {
	msg := strings.TrimPrefix(err.Error(), prefix)
	if msg == "" {
		return "Invalid input."
	}
	return upperFirst(msg) + "."
}

// checkAnchor is the fragment of a check on the Security tab ("svc.ipmi" → "chk-svc-ipmi").
func checkAnchor(id string) string { return "chk-" + strings.ReplaceAll(id, ".", "-") }
