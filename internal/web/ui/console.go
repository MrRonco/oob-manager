package ui

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/console"
)

// formConsole is the CSRF form name of the console start, takeover and KVM launch forms.
const formConsole = "console"

// consolePage is the graphical console page's view model.
type consolePage struct {
	ID, Name string
	Nav      serverNav
	User     string
	Version  string
	// Ticket is set only on the POST response that starts a session: the page script
	// opens the WebSocket with it. It is single-use and expires in 30 s.
	Ticket   string
	WSPath   string
	CSRF     string
	Card     consoleCard
	Error    string
	TLS      bool
	Takeover bool // offer "take over" (the console is in use)
	Idle     string
	Max      string
}

// consoleRoutes is the graphical console (P5). Without Deps.Consoles every console
// route answers 404 and the server page shows no console card.
func (s *server) consoleRoutes(mux *http.ServeMux) {
	mux.Handle("GET /servers/{id}/console", s.consoleView(s.consolePageGet))
	mux.Handle("POST /servers/{id}/console", s.withSession(s.consoleStart))
	mux.Handle("GET /servers/{id}/console/ws", http.HandlerFunc(s.consoleWS))
	mux.Handle("POST /servers/{id}/console/kvm-launch", s.withSession(s.kvmLaunch))
}

// consoleView authorizes console.vnc with a fresh step-up; a stale one goes to the
// step-up page and comes back here.
func (s *server) consoleView(h pageHandler) http.Handler {
	return s.withSession(func(w http.ResponseWriter, r *http.Request, sess session) {
		if s.d.Consoles == nil {
			s.errorPage(w, r, http.StatusNotFound, "There is no page at this address.")
			return
		}
		if s.authorizeConsole(w, r, sess, authz.ConsoleVNC, r.URL.Path) {
			h(w, r, sess)
		}
	})
}

// authorizeConsole applies authz for a console action; a missing step-up redirects to
// /stepup?next=back. Refusals are audited.
func (s *server) authorizeConsole(w http.ResponseWriter, r *http.Request, sess session, action authz.Action, back string) bool {
	err := s.d.Authorize(sess.id.Principal(), action, s.d.Auth.StepUpFresh(sess.id.Session))
	switch {
	case err == nil:
		return true
	case errors.Is(err, authz.ErrStepUpRequired):
		s.deny(r, sess, action, "stepup_required")
		http.Redirect(w, r, "/stepup?next="+url.QueryEscape(localPath(back, "/")), http.StatusSeeOther)
	default:
		s.deny(r, sess, action, "forbidden")
		msg := "The graphical console needs the admin role."
		if action == authz.ConsoleSerial || action == authz.ConsoleSerialTakeover {
			msg = "The serial console needs the admin role."
		}
		s.errorPage(w, r, http.StatusForbidden, msg)
	}
	return false
}

func (s *server) consolePageGet(w http.ResponseWriter, r *http.Request, sess session) {
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	st := s.d.Consoles.Status(v.ID)
	if !st.Configured {
		s.errorPage(w, r, http.StatusNotFound, "No graphical console is configured for this server.")
		return
	}
	s.renderConsole(w, r, sess, v, http.StatusOK, "", "")
}

func (s *server) renderConsole(w http.ResponseWriter, r *http.Request, sess session, v ServerView, status int, ticket, msg string) {
	st := s.d.Consoles.Status(v.ID)
	p := consolePage{ID: v.ID, Name: v.Name, Nav: s.navFor(v, sess, "console"), User: sess.id.User.Username, Version: s.d.Build.Version, Ticket: ticket,
		WSPath: "/servers/" + v.ID + "/console/ws", CSRF: s.csrf.issue(formConsole, sessionBinding(sess.token)),
		Card: s.consoleCardFor(v, sess), Error: msg, TLS: st.TLS, Takeover: st.InUse && ticket == "",
		Idle: humanDuration(s.d.ConsoleIdle), Max: humanDuration(s.d.ConsoleMax)}
	noStore(w)
	d := s.serverLayout(sess, v, "Graphical console: "+v.Name, "Graphical console", p)
	s.render(w, r, status, pageConsole, d)
}

// consoleStart checks CSRF, authz (takeover is its own action), step-up and the rate
// limit, then mints a ticket and renders the console page with it.
func (s *server) consoleStart(w http.ResponseWriter, r *http.Request, sess session) {
	if s.d.Consoles == nil {
		s.errorPage(w, r, http.StatusNotFound, "There is no page at this address.")
		return
	}
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	form, ok := parseForm(w, r)
	takeover := ok && form.Get("takeover") == "1"
	action := authz.ConsoleVNC
	if takeover {
		action = authz.ConsoleVNCTakeover
	}
	if !ok || !s.csrf.verify(form.Get(csrfField), formConsole, sessionBinding(sess.token)) {
		s.deny(r, sess, action, "csrf")
		s.errorPage(w, r, http.StatusForbidden, msgFormExpired)
		return
	}
	if !s.authorizeConsole(w, r, sess, action, "/servers/"+v.ID+"/console") || !s.consoleRate(w, r, sess, action) {
		return
	}
	g := console.Grant{ServerID: v.ID, UserID: sess.id.User.ID, Username: sess.id.User.Username,
		Role: string(sess.id.User.Role), SrcIP: clientIP(r), Session: console.SessionHash(sess.token), Takeover: takeover}
	ticket, err := s.d.Consoles.Issue(g)
	if err != nil {
		status, msg := consoleError(err)
		s.deny(r, sess, action, consoleErrorClass(err))
		s.renderConsole(w, r, sess, v, status, "", msg)
		return
	}
	s.renderConsole(w, r, sess, v, http.StatusOK, ticket, "")
}

func (s *server) consoleRate(w http.ResponseWriter, r *http.Request, sess session, action authz.Action) bool {
	if ok, wait := s.consLimit.allow("console:" + sess.id.User.ID); !ok {
		s.deny(r, sess, action, "rate_limited")
		setRetryAfter(w, wait)
		s.errorPage(w, r, http.StatusTooManyRequests, "Too many console requests in a short time. "+tryAgainIn(wait))
		return false
	}
	return true
}

func consoleError(err error) (int, string) {
	var inUse *console.InUseError
	switch {
	case errors.As(err, &inUse):
		return http.StatusConflict, "The console is in use by " + inUse.Active.Username + ". An admin can take it over."
	case errors.Is(err, console.ErrNoPassword):
		return http.StatusConflict, "No VNC password is stored for this server."
	case errors.Is(err, console.ErrCoolingDown):
		return http.StatusTooManyRequests, "The BMC rejected the VNC password a moment ago. Fix the password, then try again in a minute."
	case errors.Is(err, console.ErrNotConfigured):
		return http.StatusNotFound, "No graphical console is configured for this server."
	default:
		return http.StatusServiceUnavailable, "The console could not be started. Try again."
	}
}

func consoleErrorClass(err error) string {
	switch {
	case errors.Is(err, console.ErrInUse):
		return "in_use"
	case errors.Is(err, console.ErrNoPassword):
		return "no_credential"
	case errors.Is(err, console.ErrCoolingDown):
		return "cooldown"
	default:
		return "unavailable"
	}
}

// kvmUnavailableNote explains a missing native launch button: GetKVMSession needs the
// operator login, which the VNC console does not.
const kvmUnavailableNote = "The native iDRAC console launch is not offered: it needs an operator login (credentials.operator) for this server."

// consoleCardFor builds the server page card for the signed-in principal.
func (s *server) consoleCardFor(v ServerView, sess session) consoleCard {
	var st console.Status
	if s.d.Consoles != nil {
		st = s.d.Consoles.Status(v.ID)
	}
	capable := v.Capabilities.Flags().KVMLaunch
	kvm := capable && s.d.KVM != nil && s.d.KVM.Available(v.ID)
	c := buildConsoleCard(v, st, cardInput{kvm: kvm, tf: sess.tf()})
	if capable && !kvm {
		c.KVMNote = kvmUnavailableNote
	}
	c.Allowed = s.d.Authorize(sess.id.Principal(), authz.ConsoleVNC, true) == nil
	c.BMCURL, c.Version = s.d.BMCWebURL(v.ID), s.d.Build.Version
	if c.KVM && c.Allowed {
		c.KVMCSRF = s.csrf.issue(formConsole, sessionBinding(sess.token))
	}
	return c
}

// recordConsole audits a console action outside the broker (KVM launch).
func (s *server) recordConsole(r *http.Request, sess session, action authz.Action, serverID, result, class string) {
	_ = s.record(r, audit.Entry{Principal: sess.id.User.Username, Role: string(sess.id.User.Role),
		ServerID: serverID, Action: string(action), Result: result, ErrorClass: class})
}

// humanDuration renders a console limit ("15 minutes", "4 hours", "90 minutes").
func humanDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0 && d >= time.Hour:
		return plural(int(d/time.Hour), "hour", "hours")
	default:
		m := int(d / time.Minute)
		return plural(m, "minute", "minutes")
	}
}
