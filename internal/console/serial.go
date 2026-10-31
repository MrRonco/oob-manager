package console

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/bmc/bmcssh"
	"oob-manager/internal/config"
	"oob-manager/internal/secrets"
)

// Errors from SerialService.Issue and ServeSerial.
var (
	ErrSerialNotConfigured = errors.New("console: no serial console configured for this server")
	ErrSerialNoLogin       = errors.New("console: the operator login for the serial console is missing")
	ErrSerialNoHostKey     = errors.New("console: ssh_host_key is not configured")
	ErrSerialUnsupported   = errors.New("console: this serial console transport is not implemented")
)

// TermSize is a terminal size in characters.
type TermSize struct{ Cols, Rows int }

// SerialLink is an open serial console on a BMC: a bmcssh session (an IPMI SOL stream
// would implement the same interface; task 4.3 is deferred, see tech_doc §22).
type SerialLink interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Resize(TermSize) error
	Break() error
	// Quit ends the BMC console cleanly (iDRAC: the Ctrl-\ quit key), then closes.
	Quit() error
	Close() error
}

// SerialOpener opens the serial console of t. Production uses bmcssh.
type SerialOpener func(ctx context.Context, t SerialTarget, size TermSize) (SerialLink, error)

// SerialTarget is one server's serial console endpoint, built from validated config and
// the secrets file only.
type SerialTarget struct {
	ServerID  string
	Transport config.SerialKind
	// SSH is the bmcssh endpoint (Transport bmcssh). Its Password may be zero and its
	// HostKey empty: the card then says what to set up and nothing is dialled.
	SSH bmcssh.Config
}

// HasLogin reports whether the operator login is available.
func (t SerialTarget) HasLogin() bool { return t.SSH.Username != "" && !t.SSH.Password.IsZero() }

// SerialTargetFor builds the target of a server with console.serial bmcssh or sol.
// op may be a zero Credential (missing from the secrets file).
func SerialTargetFor(s config.Server, op secrets.Credential) (SerialTarget, error) {
	switch s.Console.Serial {
	case config.SerialBMCSSH, config.SerialSOL:
	default:
		return SerialTarget{}, fmt.Errorf("console: server %s has no serial console configured", s.ID)
	}
	return SerialTarget{ServerID: s.ID, Transport: s.Console.Serial, SSH: bmcssh.Config{
		ServerID: s.ID, Addr: net.JoinHostPort(s.BMC.Address, strconv.Itoa(s.Console.SSH.Port)),
		HostKey: s.SSHHostKey, Username: op.Username, Password: op.Password,
		Legacy: s.Console.SSH.Has(config.QuirkIDRAC8LegacySSH)}}, nil
}

// SerialConfig wires a SerialService. Targets and Audit are required.
type SerialConfig struct {
	Targets      []SerialTarget
	Audit        Auditor
	Logger       *slog.Logger
	Open         SerialOpener
	Dial         DialFunc // used by the default opener (the e2e harness redirects it)
	Now          func() time.Time
	IdleTimeout  time.Duration
	MaxSession   time.Duration
	TicketTTL    time.Duration
	CheckEvery   time.Duration
	AuthCooldown time.Duration
}

// SerialService is the serial console broker: tickets, one session per server,
// timeouts and audit (the same machinery as the graphical console, with its own
// tickets and slots so a serial ticket never opens a graphical console).
type SerialService struct {
	cfg     SerialConfig
	targets atomic.Pointer[map[string]SerialTarget] // immutable; replaced by SetTargets
	tickets *tickets
	broker  *broker

	mu       sync.Mutex
	rejected map[string]time.Time // last BMC rejection of the operator login
	last     map[string]SerialAttempt
}

// SerialAttempt is the outcome of the last connection attempt to a server.
type SerialAttempt struct {
	At    time.Time
	Class string // "" = connected; else a bmcssh.Classify class
}

// NewSerial validates cfg and builds the service. It does not contact any BMC.
func NewSerial(cfg SerialConfig) (*SerialService, error) {
	if cfg.Audit == nil {
		return nil, errors.New("console: Audit is required")
	}
	c := cfg.withDefaults()
	targets, err := serialTargetMap(c.Targets)
	if err != nil {
		return nil, err
	}
	s := &SerialService{cfg: c, tickets: newTickets(c.Now, c.TicketTTL), broker: newBroker(),
		rejected: map[string]time.Time{}, last: map[string]SerialAttempt{}}
	s.targets.Store(&targets)
	return s, nil
}

func serialTargetMap(ts []SerialTarget) (map[string]SerialTarget, error) {
	out := make(map[string]SerialTarget, len(ts))
	for _, t := range ts {
		if _, dup := out[t.ServerID]; dup || t.ServerID == "" {
			return nil, fmt.Errorf("console: duplicate or empty serial target %q", t.ServerID)
		}
		out[t.ServerID] = t
	}
	return out, nil
}

func (s *SerialService) target(serverID string) (SerialTarget, bool) {
	t, ok := (*s.targets.Load())[serverID]
	return t, ok
}

// SetTargets replaces the configured serial consoles (settings slice S3). A console on
// a server whose target changed (address, port, host key, login, legacy quirk) or that
// was removed ends with reason config_changed, and its rejection and last-attempt
// records are dropped (a confirmed new host key clears "host key changed").
func (s *SerialService) SetTargets(ts []SerialTarget) error {
	next, err := serialTargetMap(ts)
	if err != nil {
		return err
	}
	old := s.targets.Swap(&next)
	for id, o := range *old {
		if n, ok := next[id]; ok && sameSerialTarget(o, n) {
			continue
		}
		s.broker.end(id, reasonConfigChanged, shutdownWait)
		s.mu.Lock()
		delete(s.rejected, id)
		delete(s.last, id)
		s.mu.Unlock()
	}
	return nil
}

func sameSerialTarget(a, b SerialTarget) bool {
	return a.ServerID == b.ServerID && a.Transport == b.Transport && a.SSH.Addr == b.SSH.Addr &&
		a.SSH.HostKey == b.SSH.HostKey && a.SSH.Username == b.SSH.Username && a.SSH.Password.Equal(b.SSH.Password) &&
		a.SSH.Legacy == b.SSH.Legacy
}

func (c SerialConfig) withDefaults() SerialConfig {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Open == nil {
		c.Open = sshOpener(c.Dial)
	}
	c.IdleTimeout = orDur(c.IdleTimeout, config.DefaultConsoleIdle)
	c.MaxSession = orDur(c.MaxSession, config.DefaultConsoleMax)
	c.TicketTTL = orDur(c.TicketTTL, DefaultTicketTTL)
	c.CheckEvery = orDur(c.CheckEvery, DefaultCheckEvery)
	c.AuthCooldown = orDur(c.AuthCooldown, DefaultAuthCooldown)
	return c
}

// SerialStatus is what the server page's serial card needs.
type SerialStatus struct {
	Configured bool
	Transport  config.SerialKind
	Supported  bool // the transport is implemented (bmcssh)
	HasLogin   bool
	HasHostKey bool
	Legacy     bool
	InUse      bool
	Active     Active
	RejectedAt time.Time
	Last       SerialAttempt
}

// Status reports a server's serial console state. Unknown servers are "not configured".
func (s *SerialService) Status(serverID string) SerialStatus {
	t, ok := s.target(serverID)
	if !ok {
		return SerialStatus{}
	}
	s.mu.Lock()
	st := SerialStatus{Configured: true, Transport: t.Transport, Supported: t.Transport == config.SerialBMCSSH,
		HasLogin: t.HasLogin(), HasHostKey: t.SSH.HostKey != "", Legacy: t.SSH.Legacy,
		RejectedAt: s.rejected[serverID], Last: s.last[serverID]}
	s.mu.Unlock()
	st.Active, st.InUse = s.broker.active(serverID)
	return st
}

// Issue mints a one-time ticket for g after checking the server can take a serial
// console now.
func (s *SerialService) Issue(g Grant) (string, error) {
	if err := s.ready(g.ServerID); err != nil {
		return "", err
	}
	if a, held := s.broker.active(g.ServerID); held && !g.Takeover {
		return "", &InUseError{Active: a}
	}
	return s.tickets.issue(g)
}

func (s *SerialService) ready(serverID string) error {
	t, ok := s.target(serverID)
	switch {
	case !ok:
		return ErrSerialNotConfigured
	case t.Transport != config.SerialBMCSSH:
		return ErrSerialUnsupported
	case !t.HasLogin():
		return ErrSerialNoLogin
	case t.SSH.HostKey == "":
		return ErrSerialNoHostKey
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if at := s.rejected[serverID]; !at.IsZero() && s.cfg.Now().Sub(at) < s.cfg.AuthCooldown {
		return ErrCoolingDown
	}
	return nil
}

// Shutdown ends every serial console (reason "shutdown") and waits briefly for them.
func (s *SerialService) Shutdown() { s.broker.endAll(reasonShutdown, shutdownWait) }

// sshOpener opens a bmcssh session; dial (nil: net.Dialer) is the TCP dialer.
func sshOpener(dial DialFunc) SerialOpener {
	return func(ctx context.Context, t SerialTarget, size TermSize) (SerialLink, error) {
		if t.Transport != config.SerialBMCSSH {
			return nil, ErrSerialUnsupported
		}
		c := t.SSH
		c.Dial = bmcssh.DialFunc(dial)
		sess, err := bmcssh.Open(ctx, c, bmcssh.Size{Cols: size.Cols, Rows: size.Rows})
		if err != nil {
			return nil, err
		}
		return sshLink{sess}, nil
	}
}

// sshLink adapts *bmcssh.Session to SerialLink.
type sshLink struct{ *bmcssh.Session }

func (l sshLink) Resize(sz TermSize) error {
	return l.Session.Resize(bmcssh.Size{Cols: sz.Cols, Rows: sz.Rows})
}
