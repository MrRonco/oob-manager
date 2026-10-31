package ui

import (
	"net/http"
	"strconv"
	"strings"
)

type aboutView struct {
	Version     string
	Commit      string
	GoVersion   string
	Schema      string
	RepoURL     string
	DocsURL     string
	IssuesURL   string
	SecurityURL string
	Modules     []Module
}

// aboutPage shows what is running and under which licences (UI review F-14). Links
// appear only when the build sets main.repoURL; nothing installation-specific is shown.
func (s *server) aboutPage(w http.ResponseWriter, r *http.Request, sess session) {
	b := s.d.Build
	v := aboutView{Version: b.Version, Commit: b.Commit, GoVersion: b.GoVersion, Modules: b.Modules}
	if repo := strings.TrimRight(b.RepoURL, "/"); strings.HasPrefix(repo, "https://") {
		v.RepoURL, v.DocsURL, v.IssuesURL, v.SecurityURL = repo, repo+"/tree/main/docs", repo+"/issues", repo+"/security/policy"
	}
	if b.SchemaVersion != nil {
		if n, err := b.SchemaVersion(r.Context()); err == nil {
			v.Schema = strconv.Itoa(n)
		} else {
			s.d.Logger.Warn("ui schema version unavailable", "err", err)
		}
	}
	d := s.layoutFor(sess, "About", navAbout, v)
	d.Crumbs = []crumb{{"Overview", "/"}, {Label: "About"}}
	s.render(w, r, http.StatusOK, pageAbout, d)
}
