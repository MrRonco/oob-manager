// Package config loads and validates config.yaml (docs/tech_doc.md §4). Loading fails
// fast: any unknown key or invalid value aborts startup with every problem listed.
//
// A Config is a value. Callers must treat it as read-only; Server returns deep copies.
package config

import (
	"slices"
	"time"
)

// Defaults applied when a key is absent.
const (
	DefaultListen          = ":8443" // all interfaces inside the container; publish it on one host address (deploy/README.md)
	DefaultSessionIdle     = 30 * time.Minute
	DefaultSessionMax      = 12 * time.Hour
	DefaultStepUpWindow    = 5 * time.Minute
	DefaultPollInterval    = 60 * time.Second
	DefaultPollMinInterval = 30 * time.Second
	DefaultDBPath          = "/data/oob-manager.db"
	// LegacyDBPath is the default before the oob-console -> oob-manager rename (2026-10-22).
	// cmd/oob-manager opens it when db_path is not set, DefaultDBPath does not exist and
	// this file does, so an upgraded install never starts on a silent fresh database.
	LegacyDBPath           = "/data/oob-console.db"
	DefaultLeaseDir        = "/leases"
	DefaultCredentialsFile = "/run/secrets/bmc-credentials.age" //nolint:gosec // G101: a file path, not a credential
	DefaultIdentityFile    = "/run/secrets/age-identity"
	DefaultAppKeysFile     = "/run/secrets/app-keys.age"

	// MaxConfigBytes caps the config file size read by Load.
	MaxConfigBytes = 1 << 20
)

// AuthMode selects the login methods.
type AuthMode string

// Supported auth modes.
const (
	AuthLocal         AuthMode = "local"
	AuthCFAccessLocal AuthMode = "cfaccess+local"
)

// BMCKind identifies the management controller generation / protocol family.
type BMCKind string

// Supported BMC kinds.
const (
	KindIDRAC8  BMCKind = "idrac8"
	KindIDRAC9  BMCKind = "idrac9"
	KindRedfish BMCKind = "redfish"
	KindIPMI    BMCKind = "ipmi"
)

// FanMode selects the fan applier (docs/system_design.md §3).
type FanMode string

// Supported fan modes. Spellings without the hyphen (hostlease, redfishfloor, ipmioem)
// are accepted on input and normalised to these values.
const (
	FanHostLease    FanMode = "host-lease"
	FanRedfishFloor FanMode = "redfish-floor"
	FanIPMIOEM      FanMode = "ipmi-oem"
	FanNone         FanMode = "none"
)

// SerialKind selects the serial console transport.
type SerialKind string

// Supported serial console transports.
const (
	SerialBMCSSH SerialKind = "bmcssh"
	SerialSOL    SerialKind = "sol"
	SerialNone   SerialKind = "none"
)

// GraphicalKind selects the graphical console method.
type GraphicalKind string

// Supported graphical console methods.
const (
	GraphicalVNC       GraphicalKind = "vnc"
	GraphicalKVMLaunch GraphicalKind = "kvm-launch"
	GraphicalLink      GraphicalKind = "link"
	GraphicalNone      GraphicalKind = "none"
)

// Config is the whole validated configuration.
type Config struct {
	Listen    string          `yaml:"listen"`
	TLS       TLSConfig       `yaml:"tls"`
	PublicURL string          `yaml:"public_url"`
	Auth      AuthConfig      `yaml:"auth"`
	Audit     AuditConfig     `yaml:"audit"`
	Poll      PollConfig      `yaml:"poll"`
	Storage   StorageConfig   `yaml:"storage"`
	Secrets   SecretsConfig   `yaml:"secrets"`
	Console   ConsoleSettings `yaml:"console"`
	UI        UIConfig        `yaml:"ui"`
	RateLimit RateLimitConfig `yaml:"ratelimit"`
	Settings  SettingsConfig  `yaml:"settings"`
	Servers   []Server        `yaml:"servers"`
	// Notifications is file-only (notifications.go).
	Notifications NotificationsConfig `yaml:"notifications"`
	// Metrics is file-only (metrics.go).
	Metrics MetricsConfig `yaml:"metrics"`
	// Security is file-only (security.go).
	Security SecurityConfig `yaml:"security"`
	// Firmware is file-only (firmware.go).
	Firmware FirmwareConfig `yaml:"firmware"`
	// History is the sensor history (history.go): runtime-managed, a key here wins.
	History HistoryConfig `yaml:"history"`

	// SHA256 is the hex digest of the raw file, for the startup audit record (T4).
	SHA256 string `yaml:"-"`
	// FileKeys lists the runtime-managed settings keys (GeneralKeys, IntegrationKeys) written in the
	// file, in GeneralKeys order. Those win over the database (settings_design.md §2).
	FileKeys []string `yaml:"-"`
}

// UIConfig holds browser UI presentation settings.
type UIConfig struct {
	// InstanceName labels this installation in the header and on the sign-in page
	// (for example "Lab OOB"); empty shows none.
	InstanceName string `yaml:"instance_name"`
	// TimeZone is the app-wide display time zone (canonical IANA name, default UTC).
	// Display only: storage stays UTC. Users may override it for themselves.
	TimeZone string `yaml:"time_zone"`
	// Theme is the app-wide default color theme (display.Themes, default graphite).
	Theme string `yaml:"theme"`
	// App-wide defaults of the other display preferences (users may override each):
	// clock_format 24h|12h, date_format iso|us, temperature_unit c|f,
	// density compact|comfortable.
	ClockFormat     string `yaml:"clock_format"`
	DateFormat      string `yaml:"date_format"`
	TemperatureUnit string `yaml:"temperature_unit"`
	Density         string `yaml:"density"`
}

// RateLimitConfig holds the login rate limits (security.md §3).
type RateLimitConfig struct {
	LoginIPPerMin    int `yaml:"login_ip_per_min"`
	LoginAcctPerHour int `yaml:"login_acct_per_hour"`
}

// SettingsConfig controls the browser Settings area.
type SettingsConfig struct {
	// Locked lists Settings sections that are read-only in the browser
	// (SectionGeneral, SectionServers, SectionIntegrations).
	Locked []string `yaml:"locked"`
	// BMCNetworks is the CIDR allowlist for BMC addresses entered in the browser
	// (settings_design.md §3); default DefaultBMCNetworks.
	BMCNetworks []string `yaml:"bmc_networks"`
}

// TLSConfig points at the UI certificate and key. Parse accepts both left out, which
// only an install without config.yaml uses (plan 09): the binary then uses a pair in the
// data volume, generated once. serve refuses a config.yaml without them (plan 09 L5).
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// Defaulted is true when config.yaml set neither file.
	Defaulted bool `yaml:"-"`
}

// AuthConfig holds login and session settings.
type AuthConfig struct {
	Mode         AuthMode       `yaml:"mode"`
	CFAccess     CFAccessConfig `yaml:"cfaccess"`
	SessionIdle  time.Duration  `yaml:"session_idle"`
	SessionMax   time.Duration  `yaml:"session_max"`
	StepUpWindow time.Duration  `yaml:"stepup_window"`
}

// CFAccessConfig holds Cloudflare Access JWT verification settings.
type CFAccessConfig struct {
	TeamDomain string `yaml:"team_domain"`
	AUD        string `yaml:"aud"`
}

// AuditConfig configures off-box audit shipping.
type AuditConfig struct {
	GELF GELFConfig `yaml:"gelf"`
}

// GELFConfig is the GELF TCP/TLS input of a log server (Graylog and others). An empty
// Address disables shipping from the file; the browser can then set it (Settings →
// Integrations), unless settings.locked lists integrations. AllowedNetworks is
// file-only: where any GELF address, from the file or the browser, may point.
type GELFConfig struct {
	Address         string   `yaml:"address"`
	Transport       string   `yaml:"transport"`
	ServerName      string   `yaml:"server_name"`
	PinSHA256       string   `yaml:"pin_sha256"`
	AllowedNetworks []string `yaml:"allowed_networks"`
}

// Enabled reports whether GELF shipping is configured.
func (g GELFConfig) Enabled() bool { return g.Address != "" }

// PollConfig controls BMC polling cadence.
type PollConfig struct {
	Interval    time.Duration `yaml:"interval"`
	MinInterval time.Duration `yaml:"min_interval"`
	// StaleMultiplier: data older than this many poll intervals is shown as stale.
	StaleMultiplier int `yaml:"stale_multiplier"`
}

// StorageConfig holds writable paths inside the container.
type StorageConfig struct {
	DBPath   string `yaml:"db_path"`
	LeaseDir string `yaml:"lease_dir"`
	// DBPathDefaulted is true when config.yaml did not set db_path, so DBPath is
	// DefaultDBPath and the binary may fall back to LegacyDBPath.
	DBPathDefaulted bool `yaml:"-"`
}

// SecretsConfig points at the age-encrypted credential and app-key files and their identity.
type SecretsConfig struct {
	CredentialsFile string `yaml:"credentials_file"`
	IdentityFile    string `yaml:"identity_file"`
	// AppKeysFile is the age-encrypted app key document (TOTP sealing key).
	AppKeysFile string `yaml:"app_keys_file"`
	// The *Defaulted flags are true when config.yaml did not set that path, so it holds
	// the mounted default (/run/secrets/...). Only a defaulted path may fall back to the
	// data volume (plan 09); a configured one is used as written or startup fails.
	IdentityDefaulted, AppKeysDefaulted, CredentialsDefaulted bool `yaml:"-"`
}

// Server is one managed machine.
type Server struct {
	ID           string        `yaml:"id"`
	Name         string        `yaml:"name"`
	Tags         []string      `yaml:"tags"`
	BMC          BMCConfig     `yaml:"bmc"`
	TLSPinSHA256 string        `yaml:"tls_pin_sha256"`
	SSHHostKey   string        `yaml:"ssh_host_key"`
	Credentials  CredentialRef `yaml:"credentials"`
	Fan          FanConfig     `yaml:"fan"`
	Console      ConsoleConfig `yaml:"console"`
	Power        PowerConfig   `yaml:"power"`
}

// BMCConfig addresses the controller. Address must be a literal IP (no DNS).
type BMCConfig struct {
	Address string  `yaml:"address"`
	Kind    BMCKind `yaml:"kind"`
	// Port is the Redfish HTTPS port (default 443; ipmi: the RMCP+ port, default 623).
	Port int `yaml:"port"`
	// Auth is how Redfish requests authenticate (default session; basic for BMCs
	// without a SessionService).
	Auth BMCAuth `yaml:"auth"`
	// Timeouts default per kind (bmc.go); zero fields take the kind default.
	Timeouts BMCTimeouts `yaml:"timeouts"`
}

// CredentialRef names entries in the age-encrypted credential file.
type CredentialRef struct {
	ReadOnly string `yaml:"readonly"`
	Operator string `yaml:"operator"`
	VNC      string `yaml:"vnc"`
}

// FanConfig selects the fan applier and its limits.
type FanConfig struct {
	Mode       FanMode       `yaml:"mode"`
	SafeMinPct int           `yaml:"safe_min_pct"`
	MaxLease   time.Duration `yaml:"max_lease"`
}

// BoostOnly reports whether leases may only raise fan speed (no pin below the curve).
func (f FanConfig) BoostOnly() bool { return f.Mode == FanRedfishFloor }

// ConsoleConfig selects console transports.
type ConsoleConfig struct {
	Serial    SerialKind    `yaml:"serial"`
	Graphical GraphicalKind `yaml:"graphical"`
	// VNC applies when Graphical is vnc (defaults are filled for every server).
	VNC VNCConfig `yaml:"vnc"`
	// SSH applies when Serial is bmcssh (defaults are filled for every server).
	SSH SSHConfig `yaml:"ssh"`
}

// Server returns a deep copy of the server with the given ID.
func (c Config) Server(id string) (Server, bool) {
	for _, s := range c.Servers {
		if s.ID == id {
			return s.clone(), true
		}
	}
	return Server{}, false
}

func (s Server) clone() Server {
	out := s
	out.Tags = slices.Clone(s.Tags)
	out.Console.VNC = s.Console.VNC.clone()
	out.Power = s.Power.clone()
	out.Console.SSH = s.Console.SSH.clone()
	return out
}
