package ui

import (
	"errors"
	"net/http"

	"oob-manager/internal/authz"
	"oob-manager/internal/console"
)

// formSerial is the CSRF form name of the serial console start and takeover forms.
const formSerial = "serial"

// serialPage is the serial console page's view model.
type serialPage struct {
	ID, Name string
	Nav      serverNav
	User     string
	Version  string
	// Ticket is set only on the POST response that starts a session (single use, 30 s).
	Ticket   string
	WSPath   string
	CSRF     string
	Card     serialCard
	Error    string
	Takeover bool
	Legacy   bool
	Idle     string
	Max      string
}

// serialRoutes is the serial console (P4). Without Deps.Serial every route answers 404.
func (s *server) serialRoutes(mux *http.ServeMux) {
	mux.Handle("GET /servers/{id}/serial", s.withSession(s.serialPageGet))
	mux.Handle("POST /servers/{id}/serial", s.withSession(s.serialStart))
	mux.Handle("GET /servers/{id}/serial/ws", http.HandlerFunc(s.serialWS))
}

func (s *server) serialPageGet(w http.ResponseWriter, r *http.Request, sess session) {
	if s.d.Serial == nil {
		s.errorPage(w, r, http.StatusNotFound, "There is no page at this address.")
		return
	}
	if !s.authorizeConsole(w, r, sess, authz.ConsoleSerial, r.URL.Path) {
		return
	}
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if !s.d.Serial.Status(v.ID).Configured {
		s.errorPage(w, r, http.StatusNotFound, "No serial console is configured for this server.")
		return
	}
	s.renderSerial(w, r, sess, v, http.StatusOK, "", "")
}

func (s *server) renderSerial(w http.ResponseWriter, r *http.Request, sess session, v ServerView, status int, ticket, msg string) {
	st := s.d.Serial.Status(v.ID)
	p := serialPage{ID: v.ID, Name: v.Name, Nav: s.navFor(v, sess, "serial"), User: sess.id.User.Username,
		Version: s.d.Build.Version, Ticket: ticket, WSPath: "/servers/" + v.ID + "/serial/ws",
		CSRF: s.csrf.issue(formSerial, sessionBinding(sess.token)), Card: s.serialCardFor(v, sess), Error: msg,
		Takeover: st.InUse && ticket == "", Legacy: st.Legacy,
		Idle: humanDuration(s.d.ConsoleIdle), Max: humanDuration(s.d.ConsoleMax)}
	noStore(w)
	d := s.serverLayout(sess, v, "Serial console: "+v.Name, "Serial console", p)
	s.render(w, r, status, pageSerial, d)
}

// serialStart checks CSRF, authz (takeover is its own action), step-up and the shared
// console rate limit, then mints a ticket and renders the page with it.
func (s *server) serialStart(w http.ResponseWriter, r *http.Request, sess session) {
	if s.d.Serial == nil {
		s.errorPage(w, r, http.StatusNotFound, "There is no page at this address.")
		return
	}
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	form, ok := parseForm(w, r)
	takeover := ok && form.Get("takeover") == "1"
	action := authz.ConsoleSerial
	if takeover {
		action = authz.ConsoleSerialTakeover
	}
	if !ok || !s.csrf.verify(form.Get(csrfField), formSerial, sessionBinding(sess.token)) {
		s.deny(r, sess, action, "csrf")
		s.errorPage(w, r, http.StatusForbidden, msgFormExpired)
		return
	}
	if !s.authorizeConsole(w, r, sess, action, "/servers/"+v.ID+"/serial") || !s.consoleRate(w, r, sess, action) {
		return
	}
	g := console.Grant{ServerID: v.ID, UserID: sess.id.User.ID, Username: sess.id.User.Username,
		Role: string(sess.id.User.Role), SrcIP: clientIP(r), Session: console.SessionHash(sess.token), Takeover: takeover}
	ticket, err := s.d.Serial.Issue(g)
	if err != nil {
		status, msg := serialError(err)
		s.deny(r, sess, action, console.SerialErrorClass(err))
		s.renderSerial(w, r, sess, v, status, "", msg)
		return
	}
	s.renderSerial(w, r, sess, v, http.StatusOK, ticket, "")
}

func serialError(err error) (int, string) {
	var inUse *console.InUseError
	switch {
	case errors.As(err, &inUse):
		return http.StatusConflict, "The serial console is in use by " + inUse.Active.Username + ". An admin can take it over."
	case errors.Is(err, console.ErrSerialNoLogin):
		return http.StatusConflict, "No operator login is stored for this server."
	case errors.Is(err, console.ErrSerialNoHostKey):
		return http.StatusConflict, "The BMC's SSH host key is not configured (ssh_host_key)."
	case errors.Is(err, console.ErrSerialUnsupported):
		return http.StatusConflict, "This serial console transport is not implemented yet."
	case errors.Is(err, console.ErrCoolingDown):
		return http.StatusTooManyRequests, "The BMC rejected the operator login a moment ago. Fix the login, then try again in a minute."
	case errors.Is(err, console.ErrSerialNotConfigured):
		return http.StatusNotFound, "No serial console is configured for this server."
	default:
		return http.StatusServiceUnavailable, "The serial console could not be started. Try again."
	}
}
