package ui

import (
	"errors"
	"net/http"
	"net/url"
	"strings"

	"oob-manager/internal/authz"
	"oob-manager/internal/registry"
)

// serverSettingsRoutes is Settings → Servers (slice S3, settings_design.md §5). Every
// POST goes through change() or confirmed(): session, CSRF, admin role, the step-up
// window and the per-user change limit; fingerprint fetches and connection tests have
// their own per-user limits too. Pages answer 404 without Deps.Servers.
func (s *server) serverSettingsRoutes(mux *http.ServeMux) {
	view := func(h pageHandler) http.Handler { return s.settingsView(authz.AdminServers, s.withServers(h)) }
	manage := func(back func(*http.Request) string, h changeHandler) http.Handler {
		return s.change(authz.AdminServersManage, back, s.withServersChange(h))
	}
	probe := func(back func(*http.Request) string, h changeHandler) http.Handler {
		return s.probe(authz.AdminServersManage, back, s.withServersChange(h))
	}
	mux.Handle("GET /settings/servers", view(s.serversSettingsPage))
	mux.Handle("GET /settings/servers/new", view(s.newServerPage))
	mux.Handle("POST /settings/servers/fingerprint", probe(backToNewServer, s.newServerFingerprint))
	mux.Handle("POST /settings/servers", manage(backToNewServer, s.createServer))
	mux.Handle("GET /settings/servers/{id}", view(s.serverSettingsPage))
	mux.Handle("POST /settings/servers/{id}/identity", manage(backToServer, s.saveIdentity))
	mux.Handle("POST /settings/servers/{id}/connection/fingerprint", probe(backToServer, s.connectionFingerprint))
	mux.Handle("POST /settings/servers/{id}/connection", manage(backToServer, s.saveConnection))
	mux.Handle("POST /settings/servers/{id}/pin/fetch", probe(backToServer, s.pinFingerprint))
	mux.Handle("POST /settings/servers/{id}/pin", manage(backToServer, s.savePin))
	mux.Handle("POST /settings/servers/{id}/credentials/{slot}", manage(backToServer, s.saveCredential))
	mux.Handle("POST /settings/servers/{id}/features", manage(backToServer, s.saveFeatures))
	mux.Handle("POST /settings/servers/{id}/enable", manage(backToServer, s.enableServer))
	mux.Handle("POST /settings/servers/{id}/test", probe(backToServer, s.testServer))
	mux.Handle("GET /settings/servers/{id}/disable", view(s.confirmPage(s.disableServerSpec)))
	mux.Handle("POST /settings/servers/{id}/disable", s.confirmed(authz.AdminServersManage, s.disableServerSpec, s.withServersChange(s.disableServer)))
	mux.Handle("GET /settings/servers/{id}/delete", view(s.confirmPage(s.deleteServerSpec)))
	mux.Handle("POST /settings/servers/{id}/delete", s.confirmed(authz.AdminServersManage, s.deleteServerSpec, s.withServersChange(s.deleteServer)))
}

func backToNewServer(*http.Request) string { return "/settings/servers/new" }

func backToServer(r *http.Request) string {
	if id := r.PathValue("id"); serverIDPattern.MatchString(id) {
		return "/settings/servers/" + id
	}
	return "/settings/servers"
}

func (s *server) serversMissing(w http.ResponseWriter, r *http.Request) bool {
	if s.d.Servers == nil || s.d.Prober == nil || s.d.Proofs == nil {
		s.errorPage(w, r, http.StatusNotFound, "Server settings are not available in this installation.")
		return true
	}
	return false
}

func (s *server) withServers(h pageHandler) pageHandler {
	return func(w http.ResponseWriter, r *http.Request, sess session) {
		if !s.serversMissing(w, r) {
			h(w, r, sess)
		}
	}
}

func (s *server) withServersChange(h changeHandler) changeHandler {
	return func(w http.ResponseWriter, r *http.Request, sess session, form url.Values) {
		if !s.serversMissing(w, r) {
			h(w, r, sess, form)
		}
	}
}

// serverRow is one line of the Servers list.
type serverRow struct {
	ID, Name, Kind, Address string
	Status                  healthView
	Source                  string // "config.yaml" or "Browser"
	FileManaged             bool
	LastTest                string
	Note                    string
}

type serversListView struct {
	StepUp   stepUpNote
	Rows     []serverRow
	Warnings []string
	Locked   bool
	Networks string
}

func (s *server) serversSettingsPage(w http.ResponseWriter, r *http.Request, sess session) {
	eff := s.d.Servers.Current()
	v := serversListView{StepUp: s.stepUpNoteFor(r, sess), Warnings: eff.Warnings, Locked: eff.Locked}
	v.StepUp.Next = "/settings/servers"
	var nets []string
	for _, p := range s.d.Servers.Policy().Networks {
		nets = append(nets, p.String())
	}
	v.Networks = strings.Join(nets, ", ")
	for _, x := range eff.Entries() {
		v.Rows = append(v.Rows, s.serverRowOf(sess, x))
	}
	s.render(w, r, http.StatusOK, pageSettingsServers, s.settingsLayout(r, sess, "Servers", v))
}

func (s *server) serverRowOf(sess session, x registry.Entry) serverRow {
	row := serverRow{ID: x.Server.ID, Name: x.Server.Name, Kind: string(x.Server.BMC.Kind),
		Address: x.Server.BMC.Endpoint(), Source: "Browser", Status: s.entryStatus(x)}
	row.Address = strings.TrimPrefix(row.Address, "https://")
	if x.Source == registry.SourceFile {
		row.Source, row.FileManaged = "config.yaml", true
	}
	if x.Shadowed {
		row.Note = "Ignored: config.yaml defines this id."
	}
	row.LastTest = "Never"
	if t, ok := s.d.Prober.LastTest(x.Server.ID); ok {
		row.LastTest = testSummary(sess, t)
	}
	return row
}

// testSummary is "Passed 09:01:02 UTC", "Failed …" or "Running".
func testSummary(sess session, t ServerTest) string {
	switch {
	case t.Running:
		return "Running…"
	case t.OK:
		return "Passed " + sess.tf().full(t.FinishedAt)
	default:
		return "Failed " + sess.tf().full(t.FinishedAt)
	}
}

// entryStatus is the registry state combined with the poller's.
func (s *server) entryStatus(x registry.Entry) healthView {
	switch {
	case x.Shadowed:
		return healthView{Label: "Shadowed", Class: "warn"}
	case x.Source == registry.SourceDB && !x.Enabled:
		return healthView{Label: "Disabled", Class: "unknown"}
	case !x.Active():
		return healthView{Label: "Needs setup", Class: "warn"}
	}
	v, ok := s.d.Fleet.Server(x.Server.ID)
	switch {
	case !ok:
		return healthView{Label: "Not polled", Class: "unknown"}
	case v.PinMismatch:
		return healthView{Label: "Certificate changed", Class: "crit"}
	case v.ErrorClass != "":
		return healthView{Label: "Unreachable", Class: "crit"}
	case v.HasSnapshot:
		return healthView{Label: "Polling", Class: "ok"}
	default:
		return healthView{Label: "Waiting for first poll", Class: "info"}
	}
}

// serverError maps a registry error to a status and an admin-safe message.
func (s *server) serverError(err error) (int, string) {
	switch {
	case errors.Is(err, registry.ErrLocked):
		return http.StatusForbidden, "This server is managed by config.yaml or the Servers section is locked. Nothing was changed."
	case errors.Is(err, registry.ErrConflict):
		return http.StatusConflict, registry.ErrConflict.Error()
	case errors.Is(err, registry.ErrNotFound):
		return http.StatusNotFound, "There is no such server."
	case errors.Is(err, registry.ErrExists), errors.Is(err, registry.ErrLeaseActive):
		return http.StatusConflict, err.Error()
	case errors.Is(err, registry.ErrInvalid), errors.Is(err, registry.ErrUnknownPin):
		msg := strings.TrimPrefix(err.Error(), registry.ErrInvalid.Error()+": ")
		if len(msg) > 400 {
			msg = msg[:400] + "…"
		}
		return http.StatusUnprocessableEntity, "Not saved: " + msg
	default:
		s.d.Logger.Error("ui server settings change failed", "err", err)
		return http.StatusInternalServerError, "The change could not be saved. Nothing was changed."
	}
}
