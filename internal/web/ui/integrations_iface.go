package ui

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/config"
	"oob-manager/internal/integrations"
	"oob-manager/internal/settings"
	"oob-manager/internal/tofu"
)

// Integrations is the audit shipping service (*integrations.Service, tech_doc §34).
// Every change it makes is audited (the update row before the swap); the UI authorizes
// and step-up-checks first. Nothing it returns is secret.
type Integrations interface {
	Stats() audit.ShipperStats
	Applied() config.GELF
	Locked() bool
	Networks() []netip.Prefix
	Update(ctx context.Context, a admin.Actor, rev int64, form map[string]string, pin settings.PinOrigin) ([]settings.Change, error)
	Reset(ctx context.Context, a admin.Actor, rev int64, key string) ([]settings.Change, error)
	Fingerprint(ctx context.Context, a admin.Actor, hostport, serverName string) (tofu.CertInfo, error)
	// Note explains saved GELF values that are not in force ("" when none).
	Note() string
	SendTest(ctx context.Context, a admin.Actor) integrations.TestResult
}

// Hints describe the pull-style integrations for the copy-ready snippets: whether
// /metrics is on and who may scrape it (both file-only, config metrics.*).
type Hints struct {
	MetricsEnabled  bool
	MetricsNetworks []string
}

// gelfTestRate limits Send test per user (settings_design.md §3: 3/min); fingerprint
// fetches share the 6/min Servers limit.
var gelfTestRate = RateLimit{Events: 3, Per: time.Minute}

// Paths of Settings → Integrations.
const (
	pathIntegrations = "/settings/integrations"
	pathGELFReset    = "/settings/integrations/reset"
	pathGELFFetch    = "/settings/integrations/gelf/fingerprint"
	pathGELFPin      = "/settings/integrations/gelf/pin"
	pathGELFTest     = "/settings/integrations/gelf/test"
)

// integrationsRoutes is Settings → Integrations. Saves and the pin confirmation are
// changes (10/min); the fingerprint fetch and Send test are probes with their own limits.
func (s *server) integrationsRoutes(mux *http.ServeMux) {
	mux.Handle("GET "+pathIntegrations, s.integrationsView(s.integrationsPage))
	mux.Handle("POST "+pathIntegrations, s.change(authz.AdminIntegrationsManage, backToIntegrations, s.saveIntegrations))
	mux.Handle("POST "+pathGELFReset, s.change(authz.AdminIntegrationsManage, backToIntegrations, s.resetIntegrations))
	mux.Handle("POST "+pathGELFFetch, s.probe(authz.AdminIntegrationsManage, backToIntegrations, s.fetchGELFPin))
	mux.Handle("POST "+pathGELFPin, s.change(authz.AdminIntegrationsManage, backToIntegrations, s.confirmGELFPin))
	mux.Handle("POST "+pathGELFTest, s.probe(authz.AdminIntegrationsManage, backToIntegrations, s.testGELF))
}

func backToIntegrations(*http.Request) string { return pathIntegrations }

// integrationsView is a read-only Integrations page: authenticated, admin, and only
// when the settings and integrations services are wired.
func (s *server) integrationsView(h pageHandler) http.Handler {
	return s.settingsView(authz.AdminIntegrations, func(w http.ResponseWriter, r *http.Request, sess session) {
		if !s.integrationsBackend(w, r) {
			return
		}
		h(w, r, sess)
	})
}

func (s *server) integrationsBackend(w http.ResponseWriter, r *http.Request) bool {
	if s.d.Integrations == nil || s.d.Settings == nil {
		s.errorPage(w, r, http.StatusNotFound, "Integrations are not available in this installation.")
		return false
	}
	return true
}

// gelfPaused reports a pin mismatch for the Overview banner (false without the service).
func (s *server) gelfPaused() bool {
	return s.d.Integrations != nil && s.d.Integrations.Stats().PinMismatch
}

// gelfNote is the Overview note about saved GELF values that are not in force.
func (s *server) gelfNote() string {
	if s.d.Integrations == nil {
		return ""
	}
	return s.d.Integrations.Note()
}
