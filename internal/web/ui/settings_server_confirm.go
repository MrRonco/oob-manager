package ui

import (
	"net/http"
	"net/url"

	"oob-manager/internal/admin"
	"oob-manager/internal/registry"
)

// serverTarget is the database server named by the path (a shadowed row included, so
// it can be removed), as a confirm-spec error when absent or file-managed.
func (s *server) serverTarget(r *http.Request) (registry.Entry, error) {
	if s.d.Servers == nil {
		return registry.Entry{}, admin.ErrNotFound
	}
	x, ok := s.d.Servers.Current().DBEntry(r.PathValue("id"))
	if !ok {
		return registry.Entry{}, admin.ErrNotFound
	}
	return x, nil
}

func (s *server) disableServerSpec(r *http.Request, _ session) (confirmView, error) {
	x, err := s.serverTarget(r)
	if err != nil {
		return confirmView{}, err
	}
	n := x.Server.Name
	return confirmView{Title: "Disable " + n + "?", Badge: reversible, Tier: tierCaution, Heading: "What happens",
		Consequences: []string{"Polling of " + n + " stops; it leaves the overview and the API.",
			"A running console on " + n + " ends, and an active fan lease is ended first (fans back to the BMC's own curve).",
			"Its settings and stored credentials are kept: enabling it again resumes."},
		Typed: n, TypedWhy: "Disabling takes the server out of monitoring.",
		Button: "Disable " + n, CancelHref: "/settings/servers/" + x.Server.ID, ActionLabel: "Disable server · " + n}, nil
}

func (s *server) deleteServerSpec(r *http.Request, _ session) (confirmView, error) {
	x, err := s.serverTarget(r)
	if err != nil {
		return confirmView{}, err
	}
	n := x.Server.Name
	cons := []string{"Polling of " + n + " stops, a running console ends and an active fan lease is ended first.",
		"Its settings and every stored credential are deleted. Its history (audit log, samples) stays.",
		"To use it again you add it again, fingerprint and credentials included."}
	if x.Shadowed {
		cons = []string{"Only the unused browser copy is deleted; config.yaml keeps defining " + x.Server.ID + "."}
	}
	return confirmView{Title: "Remove " + n + "?", Badge: irreversible, Tier: tierDanger, Heading: "What happens", Consequences: cons,
		Typed: x.Server.ID, TypedWhy: "Removing cannot be undone. Type the server's id.",
		Button: "Remove " + n, CancelHref: "/settings/servers/" + x.Server.ID, ActionLabel: "Remove server · " + n}, nil
}

func (s *server) disableServer(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	x, err := s.serverTarget(r)
	if err != nil {
		s.errorPage(w, r, http.StatusNotFound, "There is no such server.")
		return
	}
	ch, err := s.d.Servers.SetEnabled(r.Context(), actor(r, sess), x.Server.ID, x.Rev, false)
	s.done(w, r, sess, ch, err, "server-disabled", "review")
}

func (s *server) deleteServer(w http.ResponseWriter, r *http.Request, sess session, _ url.Values) {
	x, err := s.serverTarget(r)
	if err != nil {
		s.errorPage(w, r, http.StatusNotFound, "There is no such server.")
		return
	}
	if err = s.d.Servers.Delete(r.Context(), actor(r, sess), x.Server.ID, x.Rev); err != nil {
		status, msg := s.serverError(err)
		s.errorPage(w, r, status, msg)
		return
	}
	redirectLocal(w, r, "/settings/servers?done=server-deleted")
}
