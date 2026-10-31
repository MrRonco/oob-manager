package ui

import "net/http"

// errorView is the error page: a friendly heading, the reason, and ways onward (UI
// review F-05). Signed-in users keep the full navigation and Sign out.
type errorView struct {
	Status   int
	Code     string // "404 Not Found"
	Heading  string
	Reason   string
	SignedIn bool
	Servers  []navEntry // for "no such server": the configured ones
}

func errorHeading(status int) string {
	switch status {
	case http.StatusNotFound:
		return "Page not found"
	case http.StatusForbidden:
		return "Access denied"
	case http.StatusBadRequest:
		return "That request could not be used"
	case http.StatusTooManyRequests:
		return "Too many requests"
	default:
		return "Something went wrong"
	}
}

// errorPage renders status with reason inside the normal layout.
func (s *server) errorPage(w http.ResponseWriter, r *http.Request, status int, reason string) {
	s.renderError(w, r, status, errorView{Reason: reason})
}

// serverNotFound is the 404 for an unknown server ID; it lists the configured servers.
func (s *server) serverNotFound(w http.ResponseWriter, r *http.Request) {
	s.renderError(w, r, http.StatusNotFound, errorView{Heading: "Server not found",
		Reason: "No server with that ID is configured.", Servers: s.navServers(s.viewFor(r.Context(), ""))})
}

func (s *server) renderError(w http.ResponseWriter, r *http.Request, status int, v errorView) {
	v.Status, v.Code = status, http.StatusText(status)
	if v.Heading == "" {
		v.Heading = errorHeading(status)
	}
	data := s.baseLayout(r, v.Heading, v)
	if sess, ok := s.optionalSession(r); ok {
		data = s.layoutFor(sess, v.Heading, "", v)
		v.SignedIn = true
		if data.Servers == nil {
			v.Servers = nil
		}
		data.Body = v
	} else {
		v.Servers = nil // never list servers to someone signed out
		data.Body = v
	}
	s.render(w, r, status, pageError, data)
}
