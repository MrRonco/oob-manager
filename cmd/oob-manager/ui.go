package main

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
	"oob-manager/internal/bmcsec"
	"oob-manager/internal/config"
	"oob-manager/internal/firstrun"
	"oob-manager/internal/fleet"
	"oob-manager/internal/fleetview"
	"oob-manager/internal/fwcatalog"
	"oob-manager/internal/fwinventory"
	"oob-manager/internal/integrations"
	"oob-manager/internal/maint"
	"oob-manager/internal/notify"
	"oob-manager/internal/settings"
	"oob-manager/internal/web/ui"
)

// staleIntervals is how many missed polls make a server's data stale in the UI.
const staleIntervals = 3

// UIHandler is the browser UI. It is mounted at "/" behind web.NewHandler (security
// headers, CSP, cross-origin protection, body and time limits); /api/, /healthz and
// /readyz are routed to the JSON API before it, so the UI never sees them.
type UIHandler interface{ http.Handler }

// UIDeps is everything the UI may use. Fleet is the read side of the pollers
// (fleet.Reader); handlers never call a BMC directly.
type UIDeps struct {
	Config config.Config
	Fleet  fleet.Reader
	Auth   *auth.Authenticator
	Audit  *audit.Logger
	// Admin and AuditLog back the Settings area (slice S1).
	Admin    ui.Admin
	AuditLog ui.AuditLog
	Build    ui.Build
	// CSRFKey is derived from the app keys (secrets.PurposeCSRF), so form tokens
	// survive restarts. It is required: the UI's random fallback is not used here.
	CSRFKey []byte
	Logger  *slog.Logger
	// Consoles and KVM back the graphical console; nil hides it.
	Consoles ui.Consoles
	KVM      ui.KVMLauncher
	// Power runs power actions; nil keeps them disabled.
	Power ui.Power
	// Fans is the fan lease service; nil shows fan control as not set up.
	Fans ui.Fans
	// Serial backs the serial console; nil hides it.
	Serial ui.SerialConsoles
	// BMCReset restarts BMCs (tech_doc §37); nil keeps the action off.
	BMCReset ui.BMCResets
	// Notifications backs Settings → Notifications; nil hides it.
	Notifications *notify.Service
	// Maintenance backs maintenance mode, notes and acknowledgements; nil hides them.
	Maintenance *maint.Service
	// Settings backs Settings → General and Display preferences (slice S2); nil hides them.
	Settings *settings.Service
	// AutoRefresh is the opt-in page refresh interval (zero: the UI default, 60 s).
	AutoRefresh time.Duration
	// BMCWebURL and Lifecycle are live lookups from the server registry (slice S3); nil
	// derives them from Config.Servers.
	BMCWebURL func(id string) string
	Lifecycle func(id string) bool
	// Servers, Prober and Proofs back Settings → Servers (slice S3); nil hides it.
	Servers ui.ServerAdmin
	Prober  ui.ServerProber
	Proofs  ui.ProofSigner
	// Security backs the BMC security check panel (tech_doc §31); nil hides it.
	Security *bmcsec.Service
	// Integrations backs Settings → Integrations and the "audit shipping paused" banner
	// (tech_doc §34); nil hides both.
	Integrations *integrations.Service
	// Firmware backs the firmware view (tech_doc §38); nil hides it.
	Firmware *fwinventory.Service
	// FirmwareUpdates is the update check's admin side (nil hides it).
	FirmwareUpdates *fwcatalog.Checker
	FirmwareCatalog *fwcatalog.Checker
	// History backs the sensor history (tech_doc §39); nil hides it.
	History ui.History
	// FirstRun is the first-run setup and backup notice (plan 09); nil hides both.
	FirstRun *firstrun.Service
}

// newUIHandler builds internal/web/ui over the fleet adapter. Rate limits keep the
// ui defaults (security.md §3: 5/min/IP, 10/h/account); every page is authorized with
// authz.Authorize. TOTP re-display (ui.Enroller) is deliberately not wired: see
// tech_doc §14.
func newUIHandler(d UIDeps) (UIHandler, error) {
	if len(d.CSRFKey) == 0 {
		return nil, errors.New("ui: CSRF key is required")
	}
	if d.Auth == nil || d.Audit == nil || d.Fleet == nil {
		return nil, errors.New("ui: Auth, Audit and Fleet are required")
	}
	return ui.New(ui.Deps{
		Auth:            d.Auth,
		Fleet:           fleetview.New(d.Fleet, orLifecycle(d)),
		Audit:           d.Audit,
		Logger:          d.Logger,
		Authorize:       authz.Authorize,
		CSRFKey:         d.CSRFKey,
		CSRFTTL:         csrfTTL(d),
		StaleAfter:      uiStaleAfter(d.Config),
		Settings:        uiSettings(d.Settings),
		Notifications:   uiNotifications(d.Notifications),
		Maintenance:     uiMaintenance(d.Maintenance),
		PendingTTL:      auth.DefaultPendingTTL,
		Admin:           d.Admin,
		AuditLog:        d.AuditLog,
		Build:           d.Build,
		PublicURL:       d.Config.PublicURL,
		Consoles:        d.Consoles,
		KVM:             d.KVM,
		Power:           d.Power,
		Fans:            d.Fans,
		Serial:          d.Serial,
		BMCReset:        d.BMCReset,
		Servers:         d.Servers,
		Prober:          d.Prober,
		Proofs:          d.Proofs,
		Security:        uiSecurity(d.Security),
		Firmware:        uiFirmware(d.Firmware),
		FirmwareUpdates: uiFirmwareUpdates(d.FirmwareUpdates),
		FirmwareCatalog: uiFirmwareCatalog(d.FirmwareCatalog),
		History:         d.History,
		FirstRun:        uiFirstRun(d.FirstRun),
		Integrations:    uiIntegrations(d.Integrations),
		Hints:           ui.Hints{MetricsEnabled: d.Config.Metrics.Enabled, MetricsNetworks: d.Config.Metrics.AllowNetworks},
		BMCWebURL:       orWebURL(d),
		InstanceName:    d.Config.UI.InstanceName,
		StepUpWindow:    d.Config.Auth.StepUpWindow,
		AutoRefresh:     d.AutoRefresh,

		CloseConsoleOnStepUpExpiry: d.Config.Console.CloseOnStepUpExpiry,
		ConsoleIdle:                d.Config.Console.IdleTimeout,
		ConsoleMax:                 d.Config.Console.MaxSession,
	})
}

// lifecycleFromConfig reports which servers have a Dell Lifecycle Controller log,
// decided by the configured BMC kind only.
func lifecycleFromConfig(cfg config.Config) func(id string) bool {
	dell := map[string]bool{}
	for _, s := range cfg.Servers {
		dell[s.ID] = s.BMC.Kind == config.KindIDRAC8 || s.BMC.Kind == config.KindIDRAC9
	}
	return func(id string) bool { return dell[id] }
}

func orLifecycle(d UIDeps) func(string) bool {
	if d.Lifecycle != nil {
		return d.Lifecycle
	}
	return lifecycleFromConfig(d.Config)
}

func orWebURL(d UIDeps) func(string) string {
	if d.BMCWebURL != nil {
		return d.BMCWebURL
	}
	return bmcWebURL(d.Config)
}

// uiStaleAfter is three poll intervals (zero lets the ui default apply).
func uiStaleAfter(cfg config.Config) time.Duration {
	return staleIntervals * cfg.Poll.Interval
}

// csrfTTL bounds form tokens by the longest session the settings allow, so a session
// lengthened in Settings → General keeps working forms (tokens stay session-bound).
func csrfTTL(d UIDeps) time.Duration {
	if d.Settings != nil {
		return config.MaxSessionMax
	}
	return d.Config.Auth.SessionMax
}

// uiSettings keeps a nil *settings.Service a nil interface (the UI then hides the
// General and Display pages).
func uiSettings(s *settings.Service) ui.Settings {
	if s == nil {
		return nil
	}
	return s
}

// uiNotifications keeps a nil *notify.Service a nil interface (the UI then hides
// Settings → Notifications and the banner).
func uiNotifications(s *notify.Service) ui.Notifications {
	if s == nil {
		return nil
	}
	return s
}

// uiMaintenance keeps a nil *maint.Service a nil interface (the UI then hides
// maintenance mode, notes and acknowledgements).
func uiMaintenance(m *maint.Service) ui.Maintenance {
	if m == nil {
		return nil
	}
	return m
}

// uiIntegrations keeps a nil *integrations.Service a nil interface (the UI then hides
// Settings → Integrations and the banner).
func uiIntegrations(s *integrations.Service) ui.Integrations {
	if s == nil {
		return nil
	}
	return s
}

// uiFirstRun keeps a nil service a nil interface (the UI hides /setup and the notice).
func uiFirstRun(s *firstrun.Service) ui.FirstRun {
	if s == nil {
		return nil
	}
	return s
}
