package ui

import (
	"net/http"
	"strings"
)

// helpView is the Help page: setup, glossary, keyboard, accessibility statement and
// how to report a problem (UX-21, UX-22). It is static text, so it is served without
// a session (the sign-in page links to it).
type helpView struct {
	DocsURL, IssuesURL, SecurityURL string
	SignedIn                        bool
}

func (s *server) helpPage(w http.ResponseWriter, r *http.Request) {
	v := helpView{}
	if repo := strings.TrimRight(s.d.Build.RepoURL, "/"); strings.HasPrefix(repo, "https://") {
		v.DocsURL, v.IssuesURL, v.SecurityURL = repo+"/tree/main/docs", repo+"/issues", repo+"/security/policy"
	}
	d := s.baseLayout(r, "Help", v)
	if sess, ok := s.optionalSession(r); ok {
		v.SignedIn = true
		d = s.layoutFor(sess, "Help", navHelp, v)
	}
	s.render(w, r, http.StatusOK, pageHelp, d)
}
