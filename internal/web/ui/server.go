package ui

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/display"
)

// Patterns for values taken from requests. Server IDs are only used to look up a
// configured server; usernames only as rate-limit keys (auth validates them itself).
var (
	serverIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	usernamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
)

// maxFormBytes caps login/enrolment bodies well below web.DefaultBodyLimit.
const maxFormBytes = 8 << 10

type server struct {
	d             Deps
	rd            *renderer
	csrf          csrfSigner
	ipLimit       *limiter
	acctLimit     *limiter
	changeLimit   *limiter // settings changes, per user
	verifyLimit   *limiter // audit chain verification, global
	linkLimit     *limiter // one-time enrolment link pages, per IP
	consLimit     *limiter // console starts and KVM launches, per user
	fanLimit      *limiter // fan lease starts and ends, per user
	fpLimit       *limiter // fingerprint fetches (Settings → Servers), per user
	testLimit     *limiter // connection tests (Settings → Servers), per user
	notifyLimit   *limiter // notification test sends, per user
	gelfTestLimit *limiter // GELF Send test, per user
	maintLimit    *limiter // maintenance, note and acknowledgement changes, per user
	rescanLimit   *limiter // firmware re-scans, per user
	skipLimit     *limiter // firmware update skips, per user
	setupLimit    *limiter // first-run /setup submissions, per address
	uploadLimit   *limiter // vendor catalog uploads, per user
	exportLimit   *limiter // firmware CSV exports, per user
	// historyExportLimit is the sensor history's CSV exports, per user.
	historyExportLimit *limiter
	historyDenyLimit   *limiter // one audited history export refusal per user and kind a minute
	setupDenyLimit     *limiter // one audited rate-limited /setup refusal per address a minute
	// pending keeps forms refused for a stale step-up until the code is confirmed
	// (resume.go); mux is the UI router, which replays them.
	pending *pendingStore
	mux     *http.ServeMux
	// recCache keeps the Overview recorder's rows for a minute (reccache.go).
	recCache recorderCache
}

// New returns the UI handler. The caller must wrap it with web.NewHandler (security
// headers, CSP, CrossOriginProtection, body/time limits) and serve it over TLS: the
// session and CSRF cookies are __Host- cookies, which browsers only accept on HTTPS.
func New(deps Deps) (http.Handler, error) {
	d := deps.withDefaults()
	if err := d.validate(); err != nil {
		return nil, err
	}
	rd, err := newRenderer()
	if err != nil {
		return nil, err
	}
	s := &server{
		d: d, rd: rd,
		csrf:          csrfSigner{key: d.CSRFKey, ttl: d.CSRFTTL, now: d.Now},
		changeLimit:   newLimiter(d.ChangesPerUser, defaultMaxKeys, d.Now),
		verifyLimit:   newLimiter(d.VerifyLimit, 1, d.Now),
		linkLimit:     newLimiter(d.LinkPerIP, defaultMaxKeys, d.Now),
		consLimit:     newLimiter(d.ConsolePerUser, defaultMaxKeys, d.Now),
		fanLimit:      newLimiter(d.ChangesPerUser, defaultMaxKeys, d.Now),
		fpLimit:       newLimiter(d.FingerprintPerUser, defaultMaxKeys, d.Now),
		testLimit:     newLimiter(d.TestPerUser, defaultMaxKeys, d.Now),
		notifyLimit:   newLimiter(notifyTestRate, defaultMaxKeys, d.Now),
		gelfTestLimit: newLimiter(gelfTestRate, defaultMaxKeys, d.Now),
		maintLimit:    newLimiter(maintChangeRate, defaultMaxKeys, d.Now),
		rescanLimit:   newLimiter(firmwareRescanRate, defaultMaxKeys, d.Now),
		skipLimit:     newLimiter(firmwareSkipRate, defaultMaxKeys, d.Now),
		setupLimit:    newLimiter(setupRate, defaultMaxKeys, d.Now),
		uploadLimit:   newLimiter(catalogUploadRate, defaultMaxKeys, d.Now),
		exportLimit:   newLimiter(firmwareExportRate, defaultMaxKeys, d.Now),
		// The sensor history's own export bucket (tech_doc §39).
		historyExportLimit: newLimiter(historyExportRate, defaultMaxKeys, d.Now),
		historyDenyLimit:   newLimiter(historyDenyRate, defaultMaxKeys, d.Now),
		setupDenyLimit:     newLimiter(setupDenyRate, defaultMaxKeys, d.Now),
	}
	s.ipLimit = newLiveLimiter(s.loginIPRate, defaultMaxKeys, d.Now)
	s.acctLimit = newLiveLimiter(s.loginAcctRate, defaultMaxKeys, d.Now)
	if s.pending, err = newPendingStore(d.CSRFKey, d.Now); err != nil {
		return nil, err
	}
	return s.routes(), nil
}

// routes is the whole UI surface. Anything not listed is a 404; every page route goes
// through page() (authenticate + authorize) and every Settings change through change()
// (authenticate + CSRF + authorize with step-up + rate limit).
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /static/", staticHandler())
	s.authRoutes(mux)
	mux.Handle("GET /{$}", s.page(authz.ViewFleet, s.overview))
	mux.Handle("GET /servers", s.page(authz.ViewFleet, s.serversPage))
	mux.Handle("GET /servers/{id}", s.page(authz.ViewServer, s.serverPage))
	mux.Handle("GET /servers/{id}/sensors", s.page(authz.ViewServer, s.sensorsPage))
	mux.Handle("GET /servers/{id}/events", s.page(authz.ViewLogs, s.logsPage))
	mux.Handle("GET /servers/{id}/activity", s.page(authz.ViewServer, s.serverActivityPage))
	mux.Handle("GET /servers/{id}/fan", s.page(authz.ViewServer, s.fanPage))
	mux.Handle("GET /activity", s.page(authz.ViewFleet, s.activityPage))
	mux.Handle("GET /servers/{id}/inventory", s.page(authz.ViewInventory, s.inventoryPage))
	mux.Handle("GET /events", s.page(authz.ViewLogs, s.eventsPage))
	mux.Handle("GET /about", s.page(authz.AboutView, s.aboutPage))
	mux.Handle("POST /prefs/refresh", s.withSession(s.prefsRefresh))
	mux.Handle("POST /prefs/theme", s.withSession(s.prefsTheme))
	mux.HandleFunc("GET /help", s.helpPage)
	mux.Handle("GET /go", s.page(authz.ViewFleet, s.goPage))
	// Old GET paths of the round-2 IA step (slice C): redirected (302), query kept.
	mux.Handle("GET /servers/{id}/operations", moved(""))
	mux.Handle("GET /servers/{id}/logs", moved("/events"))
	s.powerRoutes(mux)
	s.bmcResetRoutes(mux)
	s.settingsRoutes(mux)
	s.displayRoutes(mux)
	s.consoleRoutes(mux)
	s.fanRoutes(mux)
	s.serialRoutes(mux)
	s.notifyRoutes(mux)
	s.integrationsRoutes(mux)
	s.maintRoutes(mux)
	s.securityRoutes(mux)
	s.firmwareRoutes(mux)
	s.historyRoutes(mux)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.errorPage(w, r, http.StatusNotFound, "There is no page at this address.")
	})
	s.mux = mux
	return mux
}

func (s *server) authRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("GET /login/totp", s.totpPage)
	mux.HandleFunc("POST /login/totp", s.totpSubmit)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /setup", s.setupPage)
	mux.HandleFunc("POST /setup", s.setupSubmit)
	mux.Handle("POST /keys/backup-notice", s.withSession(s.keyNoticeDismiss))
	mux.HandleFunc("GET /enroll", s.enrollPage)
	mux.HandleFunc("POST /enroll", s.enrollSubmit)
	mux.HandleFunc("POST /enroll/reveal", s.enrollReveal)
	mux.HandleFunc("GET /enroll/{token}", s.enrolLinkPage)
	mux.HandleFunc("POST /enroll/{token}", s.enrolLinkSubmit)
	mux.Handle("GET /stepup", s.withSession(s.stepUpForm))
	mux.Handle("POST /stepup", s.withSession(s.stepUpSubmit))
}

// settingsRoutes is the admin-only Settings area (slices S1 and S2). S3-S4 add Servers
// and Integrations here (settings_design.md §6).
func (s *server) settingsRoutes(mux *http.ServeMux) {
	mux.Handle("GET /settings", s.settingsView(authz.AdminUsers, func(w http.ResponseWriter, r *http.Request, _ session) {
		http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
	}))
	mux.Handle("GET /settings/users", s.settingsView(authz.AdminUsers, s.usersPage))
	mux.Handle("GET /settings/users/{id}", s.settingsView(authz.AdminUsers, s.userPage))
	mux.Handle("POST /settings/users", s.change(authz.AdminUsersManage, backToUsers, s.createUser))
	mux.Handle("POST /settings/users/{id}/role", s.change(authz.AdminUsersManage, backToUser, s.setRole))
	mux.Handle("GET /settings/users/{id}/disable", s.settingsView(authz.AdminUsers, s.confirmPage(s.disableSpec)))
	mux.Handle("POST /settings/users/{id}/disable", s.confirmed(authz.AdminUsersManage, s.disableSpec, s.setDisabled(true)))
	mux.Handle("POST /settings/users/{id}/enable", s.change(authz.AdminUsersManage, backToUser, s.setDisabled(false)))
	mux.Handle("GET /settings/users/{id}/reset-totp", s.settingsView(authz.AdminUsers, s.confirmPage(s.resetSpec)))
	mux.Handle("POST /settings/users/{id}/reset-totp", s.confirmed(authz.AdminUsersManage, s.resetSpec, s.resetTOTP))
	mux.Handle("GET /settings/users/{id}/sessions/revoke-all", s.settingsView(authz.AdminUsers, s.confirmPage(s.revokeAllSpec)))
	mux.Handle("POST /settings/users/{id}/sessions/revoke-all", s.confirmed(authz.AdminUsersManage, s.revokeAllSpec, s.revokeAll))
	mux.Handle("GET /settings/users/{id}/sessions/{sid}/revoke", s.settingsView(authz.AdminUsers, s.confirmPage(s.revokeSessionSpec)))
	mux.Handle("POST /settings/users/{id}/sessions/{sid}/revoke", s.confirmed(authz.AdminUsersManage, s.revokeSessionSpec, s.revokeSession))
	mux.Handle("GET /settings/tokens", s.settingsView(authz.AdminTokens, s.tokensPage))
	mux.Handle("POST /settings/tokens", s.change(authz.AdminTokensManage, backToTokens, s.createToken))
	mux.Handle("GET /settings/tokens/{id}/revoke", s.settingsView(authz.AdminTokens, s.confirmPage(s.revokeTokenSpec)))
	mux.Handle("POST /settings/tokens/{id}/revoke", s.confirmed(authz.AdminTokensManage, s.revokeTokenSpec, s.revokeToken))
	mux.Handle("GET /settings/audit", s.settingsView(authz.AdminAudit, s.auditPage))
	mux.Handle("POST /settings/audit/verify", s.change(authz.AdminAuditVerify, backToAudit, s.verifyAudit))
	mux.Handle("GET /settings/general", s.settingsView(authz.AdminGeneral, s.generalPage))
	mux.Handle("POST /settings/general", s.change(authz.AdminGeneralManage, backToGeneral, s.saveGeneral))
	mux.Handle("POST /settings/general/reset", s.change(authz.AdminGeneralManage, backToGeneral, s.resetGeneral))
	s.serverSettingsRoutes(mux)
}

// moved answers an old server GET path with a 302 to the server's page at suffix,
// keeping the query (re-encoded, so only its parsed keys and values pass). 302, not 301:
// browsers cache a 301 for good, which would defeat a git revert of the IA step. An old
// Operations address carrying a fan lease notice (?fan=) goes to the Fan boost page,
// which shows it. It reveals nothing: the target checks the session and the role itself.
func moved(suffix string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !serverIDPattern.MatchString(id) {
			http.NotFound(w, r)
			return
		}
		q, to := r.URL.Query(), suffix
		if to == "" && q.Has("fan") {
			to = "/fan"
		}
		target := "/servers/" + id + to
		if enc := q.Encode(); enc != "" {
			target += "?" + enc
		}
		http.Redirect(w, r, target, http.StatusFound) //nolint:gosec // G710: a configured-ID pattern, a fixed suffix and a re-encoded query
	}
}

// session is an authenticated request's identity plus its cookie value (the CSRF
// binding for its forms).
type session struct {
	id    auth.Identity
	token string
	// view is how pages are shown to this user (zone, theme, formats, unit, density).
	view display.View
}

type pageHandler func(http.ResponseWriter, *http.Request, session)

// page authenticates the session and asks authz for action before calling h. Denials
// are audited. There is no path to h that skips either check.
func (s *server) page(action authz.Action, h pageHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.requireSession(w, r)
		if !ok {
			return
		}
		fresh := s.d.Auth.StepUpFresh(sess.id.Session)
		if err := s.d.Authorize(sess.id.Principal(), action, fresh); err != nil {
			_ = s.record(r, audit.Entry{Principal: sess.id.User.Username, Role: string(sess.id.User.Role),
				Action: string(action), Result: audit.ResultDenied, ErrorClass: authzClass(err)})
			s.errorPage(w, r, http.StatusForbidden, "You do not have permission to view this page.")
			return
		}
		h(w, r, sess)
	})
}

// withSession requires a signed-in session but no particular permission (step-up,
// preferences).
func (s *server) withSession(h pageHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sess, ok := s.requireSession(w, r); ok {
			h(w, r, sess)
		}
	})
}

func authzClass(err error) string {
	if errors.Is(err, authz.ErrStepUpRequired) {
		return "stepup_required"
	}
	return "forbidden"
}

// requireSession resolves the session cookie. Without a valid full session it redirects
// to the login page (and drops a stale cookie); store failures are a generic 500.
func (s *server) requireSession(w http.ResponseWriter, r *http.Request) (session, bool) {
	token, ok := auth.SessionTokenFromRequest(r)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return session{}, false
	}
	id, err := s.d.Auth.Authenticate(r.Context(), token)
	if errors.Is(err, auth.ErrSessionInvalid) {
		http.SetCookie(w, auth.ClearSessionCookie())
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return session{}, false
	}
	if err != nil {
		s.d.Logger.Error("ui session lookup failed", "err", err)
		s.errorPage(w, r, http.StatusInternalServerError, "Something went wrong. Try again.")
		return session{}, false
	}
	return session{id: id, token: token, view: s.viewFor(r.Context(), id.User.ID)}, true
}

func (s *server) render(w http.ResponseWriter, r *http.Request, status int, page string, data layoutData) {
	data = withTheme(r, data)
	data.Recent = recentOK(r, status, page, data)
	if err := s.rd.render(w, status, page, data); err != nil {
		s.d.Logger.Error("ui render failed", "page", page, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

// record writes an audit entry. Failures are logged; callers decide whether to fail.
func (s *server) record(r *http.Request, e audit.Entry) error {
	e.SrcIP = clientIP(r)
	if e.AuthMethod == "" {
		e.AuthMethod = "local"
	}
	if _, err := s.d.Audit.Record(r.Context(), e); err != nil {
		s.d.Logger.Error("ui audit record failed", "action", e.Action, "err", err)
		return err
	}
	return nil
}

// clientIP is the TCP peer address. Forwarding headers are ignored on purpose: the app
// is LAN-only with no proxy in front (decision 1), so they would only be spoofable.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// parseForm reads a small urlencoded body.
func parseForm(w http.ResponseWriter, r *http.Request) (url.Values, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		return nil, false
	}
	return r.PostForm, true
}

func setRetryAfter(w http.ResponseWriter, d time.Duration) {
	secs := int((d + time.Second - 1) / time.Second)
	w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
}
