package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/fleet"
	"oob-manager/internal/web"
)

// TokenVerifier checks a raw bearer token (auth.TokenService implements it).
type TokenVerifier interface {
	Verify(ctx context.Context, rawToken string) (auth.APIToken, authz.Principal, error)
}

// Pinger reports database reachability (store.DB implements it).
type Pinger interface {
	Ping(ctx context.Context) error
}

// ShipperStatus reports the GELF shipper state (audit.Shipper implements it).
type ShipperStatus interface {
	Stats() audit.ShipperStats
}

// Defaults.
const (
	DefaultTokenRatePerMinute = 60 // security.md §3
	readyTimeout              = 2 * time.Second
)

// Deps wires the API. Fleet, Tokens and DB are required; Shipper is nil when GELF
// shipping is disabled.
type Deps struct {
	Fleet   fleet.Reader
	Tokens  TokenVerifier
	DB      Pinger
	Shipper ShipperStatus
	Version string
	Logger  *slog.Logger
	Now     func() time.Time
	// TokenRatePerMinute caps requests per token (default 60).
	TokenRatePerMinute int
	// Maintenance adds maintenance windows and acknowledgements to the server and event
	// resources (nil: null and empty).
	Maintenance MaintenanceReader
	// BMCReset reports a server's last app-requested BMC restart (bmcreset.Service; nil:
	// last_app_reset is null).
	BMCReset func(serverID string) (BMCResetRecord, bool)
	// Firmware is the firmware view (fwinventory.Service; nil: its resources answer 404).
	Firmware FirmwareView
	// History is the sensor history (history.Service; nil: its resources answer 404).
	History HistoryView
	// ExportsPerMinute caps CSV exports per token (default 6), firmware and history alike.
	ExportsPerMinute int
	// Metrics, when set, is served at /metrics (metrics.Collector); nil answers 404.
	Metrics http.Handler
	// MetricsNetworks limits who may scrape (empty: any address; a token is required).
	MetricsNetworks []netip.Prefix
}

// API is the http.Handler for /api/v1/*, /healthz, /readyz and /metrics.
type API struct {
	deps    Deps
	limiter *limiter
	exports *limiter // CSV exports per token
	// readyAnswer caches the /readyz answer for readyCacheFor.
	readyAnswer readyCache
	build       BuildInfo
	mux         *http.ServeMux
}

// New validates deps and builds the handler.
func New(d Deps) (*API, error) {
	if d.Fleet == nil || d.Tokens == nil || d.DB == nil {
		return nil, errors.New("api: fleet, token verifier and database are required")
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.TokenRatePerMinute <= 0 {
		d.TokenRatePerMinute = DefaultTokenRatePerMinute
	}
	if d.ExportsPerMinute <= 0 {
		d.ExportsPerMinute = DefaultExportsPerMinute
	}
	a := &API{deps: d, limiter: newLimiter(d.TokenRatePerMinute, d.Now), exports: newLimiter(d.ExportsPerMinute, d.Now), build: readBuild(d.Version)}
	a.mux = a.routes()
	return a, nil
}

// ServeHTTP implements http.Handler.
func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) { a.mux.ServeHTTP(w, r) }

// Paths this handler owns; the server mounts it on each of them.
const (
	PathPrefix = "/api/"
	PathHealth = "/healthz"
	PathReady  = "/readyz"
)

func (a *API) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle(PathHealth, getOnly(http.HandlerFunc(a.healthz)))
	mux.Handle(PathReady, getOnly(http.HandlerFunc(a.readyz)))
	mux.Handle(PathMetrics, a.metricsRoute())
	mux.Handle("/api/v1/version", a.protected(authz.ViewFleet, a.version))
	mux.Handle("/api/v1/servers", a.protected(authz.ViewFleet, a.listServers))
	mux.Handle("/api/v1/servers/{id}", a.protected(authz.ViewServer, a.serverDetail))
	mux.Handle("/api/v1/servers/{id}/events", a.protected(authz.ViewLogs, a.serverEvents))
	mux.Handle("/api/v1/servers/{id}/firmware", a.protected(authz.ViewFirmware, a.serverFirmware))
	mux.Handle("/api/v1/firmware", a.protected(authz.ViewFirmware, a.firmwareList))
	mux.Handle("/api/v1/firmware.csv", a.protected(authz.ExportFirmware, a.firmwareCSV))
	mux.Handle("/api/v1/firmware/catalog", a.protected(authz.ViewFirmware, a.firmwareCatalog))
	mux.Handle("/api/v1/servers/{id}/history/sensors", a.protected(authz.ViewHistory, a.historySensors))
	mux.Handle("/api/v1/servers/{id}/history", a.protected(authz.ViewHistory, a.historySeries))
	mux.Handle("/api/v1/servers/{id}/history.csv", a.protected(authz.ExportHistory, a.historyCSV))
	mux.Handle(PathPrefix, a.protected(authz.ViewFleet, func(w http.ResponseWriter, r *http.Request) {
		web.WriteProblem(w, r, http.StatusNotFound, "no such API resource")
	}))
	return mux
}

// getOnly answers anything but GET/HEAD with 405 Problem Details.
func getOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			web.WriteProblem(w, r, http.StatusMethodNotAllowed, "the API is read-only")
			return
		}
		h.ServeHTTP(w, r)
	})
}
