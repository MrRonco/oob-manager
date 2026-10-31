package fleet

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/store"
)

// Defaults from docs/system_design.md §2 and tech_doc.md §5.
const (
	DefaultInterval         = 60 * time.Second
	DefaultJitter           = 0.10
	DefaultCycleTimeout     = 30 * time.Second
	DefaultBreakerThreshold = 3
	DefaultBreakerOpenFor   = 2 * time.Minute
	DefaultEventsEvery      = 5 * time.Minute
	DefaultInventoryEvery   = 6 * time.Hour
	DefaultPostureEvery     = 6 * time.Hour // BMC security checks: the slow tier (tech_doc §31)
	maxJitter               = 0.5
)

// LifecycleLogger is the optional Dell Lifecycle Controller log, discovered by type
// assertion (dellredfish.Driver implements it).
type LifecycleLogger interface {
	LifecycleLog(ctx context.Context, since time.Time) (bmc.EventLog, error)
}

// Target is one server to poll. The driver is built by the caller from the validated
// config and the secrets store; nothing here comes from a request.
type Target struct {
	ID     string
	Name   string
	Tags   []string
	Driver bmc.Driver
	// CycleTimeout is the budget of each poll tier for this server (0: Config.CycleTimeout).
	CycleTimeout time.Duration
	// Interval overrides Config.Interval (0: use it). The effective interval is never
	// shorter than the cycle timeout.
	Interval time.Duration
	// Posture, when set, reads the security posture on its own slow tier (every
	// Config.PostureEvery, at start and on RequestPosture) with this poller's driver, so
	// the checks share the poller's BMC session.
	Posture PostureFunc
	// Fingerprint identifies everything that needs a new driver (kind, address, port,
	// pin, credential versions, interval…). Apply keeps a running poller whose
	// fingerprint is unchanged; empty always restarts.
	Fingerprint string
}

// Config wires a Fleet. Zero values take the defaults above; Samples and
// Capabilities may be nil (no persistence).
type Config struct {
	Targets []Target
	// Samples receives each poll's sensor readings (the history store; internal/history
	// rolls them up and prunes them). Sampling, when set, is read at every poll (the
	// General history switches apply without a restart); nil samples every family.
	Samples      store.SampleSink
	Sampling     func() Sampling
	Capabilities store.CapabilityRepository
	Clock        Clock
	Logger       *slog.Logger
	// Rand returns a float in [0,1) for jitter (default math/rand/v2).
	Rand func() float64

	Interval         time.Duration
	Jitter           float64 // fraction of Interval, e.g. 0.1 = ±10 %
	CycleTimeout     time.Duration
	BreakerThreshold int
	BreakerOpenFor   time.Duration
	EventsEvery      time.Duration
	InventoryEvery   time.Duration
	PostureEvery     time.Duration
	FirmwareEvery    time.Duration
	// Firmware records the firmware tier's scans (nil: no firmware tier).
	Firmware   FirmwareSink
	StaleAfter time.Duration // default StaleMultiplier (else 3) × each server's interval
	// StaleMultiplier, when set and StaleAfter is zero, is read on every view (Settings →
	// General poll.stale_multiplier applies without a restart).
	StaleMultiplier func() int
	// RestartQuiet and RestartRetry are the BMC restart window's cadence (restart.go):
	// no poll for RestartQuiet after the request, then one every RestartRetry.
	RestartQuiet time.Duration
	RestartRetry time.Duration
}

func (c Config) withDefaults() Config {
	c.Clock = orValue[Clock](c.Clock, RealClock{})
	c.Logger = orValue(c.Logger, slog.Default())
	if c.Rand == nil {
		c.Rand = rand.Float64
	}
	c.Interval = orValue(c.Interval, DefaultInterval)
	c.Jitter = orValue(c.Jitter, DefaultJitter)
	c.CycleTimeout = orValue(c.CycleTimeout, DefaultCycleTimeout)
	c.BreakerThreshold = orValue(c.BreakerThreshold, DefaultBreakerThreshold)
	c.BreakerOpenFor = orValue(c.BreakerOpenFor, DefaultBreakerOpenFor)
	c.EventsEvery = orValue(c.EventsEvery, DefaultEventsEvery)
	c.InventoryEvery = orValue(c.InventoryEvery, DefaultInventoryEvery)
	c.PostureEvery = orValue(c.PostureEvery, DefaultPostureEvery)
	c.FirmwareEvery = orValue(c.FirmwareEvery, DefaultFirmwareEvery)
	c.RestartQuiet = orValue(c.RestartQuiet, DefaultRestartQuiet)
	c.RestartRetry = orValue(c.RestartRetry, DefaultRestartRetry)
	return c
}

func (c Config) validate() error {
	if err := validateTargets(c.Targets); err != nil {
		return err
	}
	if c.Interval < 0 || c.CycleTimeout < 0 || c.Jitter < 0 || c.Jitter > maxJitter || c.BreakerThreshold < 0 {
		return errors.New("fleet: negative durations, a negative threshold or jitter above 0.5 are invalid")
	}
	return nil
}

func validateTargets(ts []Target) error {
	seen := map[string]bool{}
	for _, t := range ts {
		if t.ID == "" || t.Driver == nil {
			return fmt.Errorf("fleet: target %q needs an ID and a driver", t.ID)
		}
		if seen[t.ID] {
			return fmt.Errorf("fleet: duplicate target %q", t.ID)
		}
		seen[t.ID] = true
	}
	return nil
}

func orValue[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// PostureFunc reads one server's BMC security posture with the driver its poller uses
// (bmcsec.Collect bound to the server's settings). It must only read: Redfish GETs and
// handshake-only probes. A section it could not read is part of the posture; the error
// is for a run that read nothing.
type PostureFunc func(ctx context.Context, d bmc.Driver) (bmc.Posture, error)
