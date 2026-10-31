package ui

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmc"
)

// kvmLaunchTimeout bounds the Redfish login, GetKVMSession and logout (iDRAC is slow).
const kvmLaunchTimeout = 20 * time.Second

// kvmPage shows the one-time launch link. It is rendered once (no-store), never a
// redirect: CSP form-action 'self' would block a redirect to the BMC, and a link the
// admin clicks keeps the temporary credential out of our server's Location headers.
type kvmPage struct {
	ID, Name string
	URL      string
}

// kvmLaunch asks the BMC for a single-use console login (Dell iDRAC9 GetKVMSession)
// and shows a link that opens the BMC's own HTML5 console in a new tab. It needs the
// admin role, a fresh step-up, the console CSRF token and the console rate limit.
func (s *server) kvmLaunch(w http.ResponseWriter, r *http.Request, sess session) {
	v, ok := s.lookup(w, r)
	if !ok {
		return
	}
	if s.d.KVM == nil || !s.d.KVM.Available(v.ID) || !v.Capabilities.Flags().KVMLaunch {
		s.errorPage(w, r, http.StatusNotFound, "This BMC does not offer a native console launch.")
		return
	}
	form, ok := parseForm(w, r)
	if !ok || !s.csrf.verify(form.Get(csrfField), formConsole, sessionBinding(sess.token)) {
		s.deny(r, sess, authz.ConsoleKVMLaunch, "csrf")
		s.errorPage(w, r, http.StatusForbidden, msgFormExpired)
		return
	}
	if !s.authorizeConsole(w, r, sess, authz.ConsoleKVMLaunch, "/servers/"+v.ID) ||
		!s.consoleRate(w, r, sess, authz.ConsoleKVMLaunch) {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), kvmLaunchTimeout)
	defer cancel()
	link, err := s.d.KVM.Launch(ctx, v.ID)
	if err != nil {
		s.recordConsole(r, sess, authz.ConsoleKVMLaunch, v.ID, audit.ResultError, string(bmc.Classify(err)))
		s.errorPage(w, r, http.StatusBadGateway, "The BMC did not provide a console session. Try again, or open the BMC's own web interface.")
		return
	}
	s.recordConsole(r, sess, authz.ConsoleKVMLaunch, v.ID, audit.ResultOK, "")
	noStore(w)
	d := s.serverLayout(sess, v, "Native console: "+v.Name, "Native console", kvmPage{ID: v.ID, Name: v.Name, URL: link.Reveal()})
	s.render(w, r, http.StatusOK, pageKVMLaunch, d)
}

func audit403(id auth.Identity, err error) audit.Entry {
	return audit.Entry{Principal: id.User.Username, Role: string(id.User.Role), Action: string(authz.ConsoleVNC),
		Result: audit.ResultDenied, ErrorClass: authzClass(err)}
}

// publicHost is the host[:port] of public_url ("" when unset or invalid).
func publicHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Host
}
