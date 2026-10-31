package metrics

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"runtime"
	"sync"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/fleet"
)

// Caps that bound the cardinality of one scrape.
const (
	// MaxSensorsPerServer caps each per-server list (temperatures, fans, PSUs, voltages).
	MaxSensorsPerServer = 64
	// MaxNotifyTargets caps the notification target series.
	MaxNotifyTargets = 64
	// MaxSeriesPerFamily caps any one family across the fleet.
	MaxSeriesPerFamily = 4096
	// DefaultCacheFor is how long a rendered scrape is reused, so concurrent or rapid
	// scrapers cost one render.
	DefaultCacheFor = time.Second
)

// FanState is a server's fan lease picture (fan.Service.Status, which never contacts a BMC).
type FanState struct {
	LeaseActive bool
	LeasePct    int
	Remaining   time.Duration
	AppliedPct  int
	HasApplied  bool
}

// NotifyTarget is one notification target's delivery state.
type NotifyTarget struct {
	ID                  string
	Enabled             bool
	Failing             bool
	ConsecutiveFailures int
	Sent, Dropped       uint64
}

// MaintenanceState is a server's maintenance window as metrics see it.
type MaintenanceState struct {
	Active bool      // a window is active now
	Until  time.Time // its end; zero when it lasts until it is ended
}

// RuntimeStats are the process metrics (runtime.ReadMemStats by default).
type RuntimeStats struct {
	Goroutines            int
	HeapAlloc, Sys, NumGC uint64
}

// BuildInfo labels oob_build_info.
type BuildInfo struct {
	Version, Commit, GoVersion string
}

// ShipperStatus reports the GELF shipper state (audit.Shipper implements it).
type ShipperStatus interface {
	Stats() audit.ShipperStats
}

// Config wires a Collector. Fleet is required; every other source is optional and its
// families are left out (or read 0, for the maintenance families) when it is nil.
type Config struct {
	Fleet fleet.Reader
	// FanStatus returns the lease state of a server with leasable fans (false: none).
	FanStatus func(ctx context.Context, serverID string) (FanState, bool)
	// ConsoleActive reports whether a graphical / serial console is open for a server.
	ConsoleActive func(serverID string) (vnc, serial bool)
	NotifyTargets func() []NotifyTarget
	Shipper       ShipperStatus
	// AuditChainOK is the startup audit chain verification result.
	AuditChainOK func() bool
	Logins       *LoginCounter
	// Maintenance reports a server's maintenance window (maint.Service; nil: never in
	// maintenance).
	Maintenance func(serverID string) MaintenanceState
	// Acked reports whether a log entry is acknowledged (maint.Service; nil: none is).
	Acked func(serverID, log, entryID string, created time.Time) bool
	// Security reports a server's BMC security check counts (bmcsec.Service; nil, or false
	// for a server without a report: oob_security_checks is left out).
	Security func(serverID string) (SecurityCounts, bool)
	// BMCReset reports a server's BMC restart record (bmcreset.Service; nil:
	// oob_bmc_resets_total is left out and the last restart comes from the BMC only).
	BMCReset func(serverID string) BMCResetState
	// Firmware reports a server's firmware view numbers (fwinventory.Service; nil, or false
	// for a server the view does not know: the oob_firmware_* families are left out).
	Firmware func(serverID string) (FirmwareCounts, bool)
	// Catalog reports the firmware update check (fwcatalog.Checker; nil: the
	// oob_firmware_catalog_* families are left out).
	Catalog func() CatalogState
	// History reports the sensor history's size and rollup progress (history.Service;
	// nil: the oob_history_* families are left out).
	History func() HistoryState
	// IncludeInventory adds identifiers (serial, service tag, firmware) to oob_server_info.
	IncludeInventory bool
	Build            BuildInfo
	StartTime        time.Time
	Now              func() time.Time
	Runtime          func() RuntimeStats
	CacheFor         time.Duration
}

// Collector renders scrapes. It is safe for concurrent use; renders are serialised and
// reused for CacheFor.
type Collector struct {
	cfg Config

	mu     sync.Mutex
	at     time.Time
	cached []byte
}

// New validates cfg and fills defaults.
func New(cfg Config) (*Collector, error) {
	if cfg.Fleet == nil {
		return nil, errors.New("metrics: fleet reader is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Runtime == nil {
		cfg.Runtime = readRuntime
	}
	if cfg.CacheFor <= 0 {
		cfg.CacheFor = DefaultCacheFor
	}
	if cfg.Build.GoVersion == "" {
		cfg.Build.GoVersion = runtime.Version()
	}
	return &Collector{cfg: cfg}, nil
}

// Collect builds the families of one scrape from cached state only.
func (c *Collector) Collect(ctx context.Context) []Family {
	b := newBuilder(allSpecs(), MaxSeriesPerFamily)
	now := c.cfg.Now()
	servers := c.cfg.Fleet.Servers()
	c.collectApp(b, servers)
	for _, s := range servers {
		c.collectServer(ctx, b, s, now)
	}
	return b.families()
}

// Render returns the exposition text, reusing a render younger than CacheFor.
func (c *Collector) Render(ctx context.Context) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now()
	if c.cached != nil && now.Sub(c.at) >= 0 && now.Sub(c.at) < c.cfg.CacheFor {
		return c.cached, nil
	}
	var buf bytes.Buffer
	if err := Write(&buf, c.Collect(ctx)); err != nil {
		return nil, err
	}
	c.cached, c.at = buf.Bytes(), now
	return c.cached, nil
}

// ServeHTTP writes the scrape. Authentication, the network allowlist and rate limiting
// are the caller's (internal/api).
func (c *Collector) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := c.Render(r.Context())
	if err != nil {
		http.Error(w, "metrics unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

func readRuntime() RuntimeStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return RuntimeStats{Goroutines: runtime.NumGoroutine(), HeapAlloc: m.HeapAlloc, Sys: m.Sys, NumGC: uint64(m.NumGC)}
}
