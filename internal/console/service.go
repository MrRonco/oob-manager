package console

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/store"
)

// Defaults for Config.
const (
	DefaultCheckEvery   = 10 * time.Second
	DefaultProbeEvery   = 6 * time.Hour // the slow (inventory) poll tier
	DefaultProbeRetry   = 5 * time.Minute
	DefaultAuthCooldown = time.Minute
	shutdownWait        = 5 * time.Second
	// lowColourName makes noVNC choose an 8-bit pixel format (its Intel AMT special
	// case, noVNC core/rfb.js); the page shows the configured server name instead.
	lowColourName = "Intel(r) AMT KVM"
)

// Errors a session watchdog returns to end a running console with that reason.
var (
	ErrSessionEnded  error = reasonSession
	ErrStepUpExpired error = reasonStepUp
	ErrForbidden     error = reasonForbidden
)

// Errors from Issue and Serve.
var (
	ErrNotConfigured = errors.New("console: no graphical console configured for this server")
	ErrNoPassword    = errors.New("console: the VNC credential is missing")
	ErrCoolingDown   = errors.New("console: the BMC rejected the VNC password; wait before retrying")
)

// Auditor records audit entries (*audit.Logger).
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) (store.AuditRecord, error)
}

// Config wires a Service. Targets, Audit are required.
type Config struct {
	Targets      []Target
	Audit        Auditor
	Logger       *slog.Logger
	Dial         DialFunc
	Now          func() time.Time
	IdleTimeout  time.Duration
	MaxSession   time.Duration
	TicketTTL    time.Duration
	CheckEvery   time.Duration
	ProbeEvery   time.Duration
	ProbeRetry   time.Duration
	AuthCooldown time.Duration
}

func (c Config) withDefaults() Config {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Dial == nil {
		c.Dial = defaultDial
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	c.IdleTimeout = orDur(c.IdleTimeout, 15*time.Minute)
	c.MaxSession = orDur(c.MaxSession, 4*time.Hour)
	c.TicketTTL = orDur(c.TicketTTL, DefaultTicketTTL)
	c.CheckEvery = orDur(c.CheckEvery, DefaultCheckEvery)
	c.ProbeEvery = orDur(c.ProbeEvery, DefaultProbeEvery)
	c.ProbeRetry = orDur(c.ProbeRetry, DefaultProbeRetry)
	c.AuthCooldown = orDur(c.AuthCooldown, DefaultAuthCooldown)
	return c
}

func orDur(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

// Service is the graphical console broker. It is safe for concurrent use.
type Service struct {
	cfg     Config
	targets atomic.Pointer[map[string]Target] // immutable; replaced by SetTargets
	tickets *tickets
	broker  *broker

	mu       sync.Mutex
	probes   map[string]Probe
	rejected map[string]time.Time // last BMC rejection of the VNC password
}

// New validates cfg and builds the service. It does not contact any BMC.
func New(cfg Config) (*Service, error) {
	if cfg.Audit == nil {
		return nil, errors.New("console: Audit is required")
	}
	c := cfg.withDefaults()
	targets, err := targetMap(c.Targets)
	if err != nil {
		return nil, err
	}
	s := &Service{cfg: c, tickets: newTickets(c.Now, c.TicketTTL), broker: newBroker(),
		probes: map[string]Probe{}, rejected: map[string]time.Time{}}
	s.targets.Store(&targets)
	return s, nil
}

func targetMap(ts []Target) (map[string]Target, error) {
	out := make(map[string]Target, len(ts))
	for _, t := range ts {
		if _, dup := out[t.ServerID]; dup || t.ServerID == "" {
			return nil, fmt.Errorf("console: duplicate or empty target %q", t.ServerID)
		}
		out[t.ServerID] = t
	}
	return out, nil
}

// target returns the current target of serverID.
func (s *Service) target(serverID string) (Target, bool) {
	t, ok := (*s.targets.Load())[serverID]
	return t, ok
}

// SetTargets replaces the configured consoles (settings slice S3). A console running on
// a server whose target changed in any way (address, port, TLS, pin, password, quirks)
// or that was removed ends with reason config_changed, and its cached probe and
// password rejection are dropped. Consoles on unchanged servers keep running.
func (s *Service) SetTargets(ts []Target) error {
	next, err := targetMap(ts)
	if err != nil {
		return err
	}
	old := s.targets.Swap(&next)
	for id, o := range *old {
		if n, ok := next[id]; ok && sameTarget(o, n) {
			continue
		}
		s.broker.end(id, reasonConfigChanged, shutdownWait)
		s.mu.Lock()
		delete(s.probes, id)
		delete(s.rejected, id)
		s.mu.Unlock()
	}
	return nil
}

func sameTarget(a, b Target) bool {
	return a.ServerID == b.ServerID && a.Kind == b.Kind && a.Addr == b.Addr && a.TLS == b.TLS &&
		string(a.pin) == string(b.pin) && a.Password.Equal(b.Password) && a.SafeEncodings == b.SafeEncodings &&
		a.LowColour == b.LowColour && a.RSAKeyExchange == b.RSAKeyExchange
}

// Status is what the server page's console card needs.
type Status struct {
	Configured  bool
	HasPassword bool
	TLS         bool
	Probe       Probe
	InUse       bool
	Active      Active
	// RejectedAt is when the BMC last rejected the VNC password (zero: never).
	RejectedAt time.Time
	Warnings   []string
}

// Status reports a server's console state. Unknown servers are "not configured".
func (s *Service) Status(serverID string) Status {
	t, ok := s.target(serverID)
	if !ok {
		return Status{}
	}
	s.mu.Lock()
	st := Status{Configured: true, HasPassword: t.HasPassword(), TLS: t.TLS, Probe: s.probes[serverID],
		RejectedAt: s.rejected[serverID], Warnings: PasswordWarnings(t.Kind, t.Password)}
	s.mu.Unlock()
	st.Active, st.InUse = s.broker.active(serverID)
	return st
}

// Issue mints a one-time ticket for g after checking the server can take a console now.
func (s *Service) Issue(g Grant) (string, error) {
	if err := s.ready(g.ServerID); err != nil {
		return "", err
	}
	if a, held := s.broker.active(g.ServerID); held && !g.Takeover {
		return "", &InUseError{Active: a}
	}
	return s.tickets.issue(g)
}

func (s *Service) ready(serverID string) error {
	t, ok := s.target(serverID)
	switch {
	case !ok:
		return ErrNotConfigured
	case !t.HasPassword():
		return ErrNoPassword
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if at := s.rejected[serverID]; !at.IsZero() && s.cfg.Now().Sub(at) < s.cfg.AuthCooldown {
		return ErrCoolingDown
	}
	return nil
}

// Shutdown ends every console (reason "shutdown") and waits briefly for them.
func (s *Service) Shutdown() { s.broker.endAll(reasonShutdown, shutdownWait) }

func newSessionID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// classify maps a connection failure to an audit error class.
func classify(err error) string {
	switch {
	case errors.Is(err, ErrPinMismatch):
		return "tls_pin"
	case errors.Is(err, ErrTLS):
		return "tls"
	case errors.Is(err, errBMCAuth):
		return "bmc_auth"
	case errors.Is(err, errBMCProtocol):
		return "bmc_protocol"
	case errors.Is(err, errBrowserProtocol):
		return "browser_protocol"
	default:
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return "timeout"
		}
		return "unreachable"
	}
}
