// Package bmcreset restarts a server's BMC (Redfish Manager.Reset, GracefulRestart;
// docs/tech_doc.md §37) with the safety model of a forced power action: the admin role
// and a fresh step-up (checked by the caller), a fail-closed audit row before anything
// happens, a per-server cooldown that survives restarts, and interlocks with power
// actions. While the BMC is away the fleet holds a restart window, so the silence raises
// no "unreachable" alarm; when the BMC answers again the reset is verified, consoles
// re-probe and a BMC-side fan floor is applied again.
//
// Nothing user-supplied reaches a BMC: the server ID is looked up in the targets, the
// target URI comes from the BMC's own Manager document, and the body is a constant.
package bmcreset

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/fleet"
	"oob-manager/internal/power"
	"oob-manager/internal/store"
)

// ResetType is the one value this app sends (redfish.ManagerResetType).
const ResetType = "GracefulRestart"

// Audit actions besides authz.BMCReset ("bmc.reset").
const (
	ActionReset    = "bmc.reset"
	ActionVerified = "bmc.reset.verified"
	systemActor    = "system"
)

// Defaults (constants, not config: tech_doc §37).
const (
	// DefaultCooldown is the wait between two resets of one server (design decision:
	// 10 minutes). A BMC takes minutes to return; repeating achieves nothing.
	DefaultCooldown = 10 * time.Minute
	// DefaultRequestTimeout bounds the operator login, the discovery reads and the POST.
	DefaultRequestTimeout = 60 * time.Second
	// Retention is how long bmc_resets rows are kept (the janitor prunes them).
	Retention = 400 * 24 * time.Hour
	// afterBackTimeout bounds the work after the BMC returned (fan floor re-apply).
	afterBackTimeout = 2 * time.Minute
	// finalAttempts and finalRetryPause: final audit rows and row updates are retried.
	finalAttempts   = 3
	finalRetryPause = 100 * time.Millisecond
)

// Deadline is how long the app waits for a restarted BMC of kind k to answer again
// before it reports a timeout (iDRAC8 5 min, iDRAC9 3 min, others 5 min).
func Deadline(k config.BMCKind) time.Duration {
	if k == config.KindIDRAC9 {
		return 3 * time.Minute
	}
	return 5 * time.Minute
}

// Resetter is one operator session on one BMC (*redfish.ManagerResetter).
type Resetter interface {
	// Reset sends {"ResetType":"GracefulRestart"} to the manager's own Reset action.
	Reset(ctx context.Context) error
	Close(ctx context.Context) error
}

// Opener logs in with the server's operator account and finds the Reset action
// (bmc.ErrUnsupported when the BMC offers none that may be used).
type Opener func(ctx context.Context) (Resetter, error)

// Target is one configured server. A nil Open means no operator login (the action is
// disabled with that reason). Deadline is Deadline(kind).
type Target struct {
	ServerID string
	Open     Opener
	Deadline time.Duration
	SelfHost bool
}

// Fleet opens and cancels the restart window (*fleet.Fleet).
type Fleet interface {
	ExpectRestart(id string, w fleet.RestartWindow, done func(fleet.RestartEnd)) error
	CancelRestart(id string) bool
}

// Power is the power service's latest operation (*power.Service): a reset waits while
// a power action is still being verified.
type Power interface {
	Last(id string) (power.Operation, bool)
}

// Console ends a console on a server before the reset (*console.Service,
// *console.SerialService).
type Console interface {
	EndForBMCReset(serverID string) bool
}

// Auditor records audit entries (*audit.Logger).
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) (store.AuditRecord, error)
}

// Actor is who asked, as the audit log records it.
type Actor struct {
	Username, Role, SrcIP, AuthMethod string
}

// Config wires a Service. Audit, Store and Fleet are required.
type Config struct {
	Targets  []Target
	Audit    Auditor
	Store    store.BMCResetRepository
	Fleet    Fleet
	Power    Power     // optional
	Consoles []Console // ended before the POST
	// AfterBack runs once the BMC answered again (forget console probes, re-apply a fan
	// floor), in the background with a context bounded by afterBackTimeout and cancelled
	// by Shutdown. AfterTimeout runs when the BMC did not come back by the deadline (the
	// fan service then re-applies a BMC-side floor whenever the BMC answers again).
	AfterBack      func(ctx context.Context, serverID string)
	AfterTimeout   func(serverID string)
	Logger         *slog.Logger
	Now            func() time.Time
	Cooldown       time.Duration
	RequestTimeout time.Duration
}

// Service runs BMC resets. It is safe for concurrent use.
type Service struct {
	cfg     Config
	targets atomic.Pointer[map[string]Target]

	// stopCtx is cancelled by Shutdown; the work after a BMC's return derives from it.
	stopCtx context.Context
	stop    context.CancelFunc

	mu       sync.Mutex
	closed   bool
	inflight map[string]string           // server → correlation ID of the request between reserve and its return
	next     map[string]time.Time        // cooldown end per server
	open     map[string]openReset        // the restart window per server
	refused  map[string]bool             // sticky: the operator account lacked the privilege
	last     map[string]Record           // latest row per server
	verified map[string]Record           // latest confirmed restart per server (verified, empty detail)
	stats    map[string]map[string]int64 // resets per server and result since start
	wg       sync.WaitGroup
}

// openReset is a reset whose BMC the app is waiting for.
type openReset struct {
	rowID  int64
	rq     request
	sentAt time.Time // just before the POST: the window and the downtime start here
	until  time.Time
	// unconfirmed: the POST got no answer; rearmed: the app restarted during the window,
	// so part of it was not watched.
	unconfirmed, rearmed bool
}

// New validates cfg and builds the service; call Start once the fleet has its servers.
func New(cfg Config) (*Service, error) {
	if cfg.Audit == nil || cfg.Store == nil || cfg.Fleet == nil {
		return nil, errors.New("bmcreset: Audit, Store and Fleet are required")
	}
	cfg = withDefaults(cfg)
	ts, err := targetMap(cfg.Targets)
	if err != nil {
		return nil, err
	}
	s := &Service{cfg: cfg, next: map[string]time.Time{}, open: map[string]openReset{}, refused: map[string]bool{},
		last: map[string]Record{}, verified: map[string]Record{}, stats: map[string]map[string]int64{},
		inflight: map[string]string{}}
	s.stopCtx, s.stop = context.WithCancel(context.Background())
	s.targets.Store(&ts)
	return s, nil
}

func withDefaults(c Config) Config {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Cooldown <= 0 {
		c.Cooldown = DefaultCooldown
	}
	if c.RequestTimeout <= 0 {
		c.RequestTimeout = DefaultRequestTimeout
	}
	return c
}

func targetMap(ts []Target) (map[string]Target, error) {
	out := make(map[string]Target, len(ts))
	for _, t := range ts {
		if _, dup := out[t.ServerID]; dup || t.ServerID == "" {
			return nil, fmt.Errorf("bmcreset: duplicate or empty server ID %q", t.ServerID)
		}
		if t.Deadline <= 0 {
			t.Deadline = Deadline("")
		}
		out[t.ServerID] = t
	}
	return out, nil
}

// SetTargets replaces the servers (settings slice S3, hot apply). Cooldowns and open
// windows are kept (the fleet ends the window of a rebuilt server); the sticky privilege
// refusal is cleared, since the operator login may have changed.
func (s *Service) SetTargets(ts []Target) error {
	next, err := targetMap(ts)
	if err != nil {
		return err
	}
	s.targets.Store(&next)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refused = map[string]bool{}
	return nil
}

// Info is what the UI needs to know about a server's BMC reset.
type Info struct {
	Configured bool
	Operator   bool
	SelfHost   bool
	Deadline   time.Duration
}

// Info describes server id (zero when unknown).
func (s *Service) Info(id string) Info {
	t, ok := (*s.targets.Load())[id]
	if !ok {
		return Info{}
	}
	return Info{Configured: true, Operator: t.Open != nil, SelfHost: t.SelfHost, Deadline: t.Deadline}
}

// Record is one reset as the UI, API and metrics show it.
type Record struct {
	RequestedAt time.Time
	SentAt      time.Time // zero for a row written before the POST time was stored
	By          string
	Result      string // store.BMCReset*
	BackAt      time.Time
	Deadline    time.Time
	Class       string
	Detail      string
}

func recordOf(r store.BMCResetRow) Record {
	return Record{RequestedAt: r.RequestedAt, SentAt: r.SentAt, By: r.RequestedBy, Result: r.Result, BackAt: r.BackAt,
		Deadline: r.DeadlineAt, Class: r.ErrorClass, Detail: r.Detail}
}

// State is a server's reset state now.
type State struct {
	// Restarting: the app is waiting for the BMC (the window is open). InFlight: a
	// request is between its reservation and its return (login, discovery, the POST).
	Restarting   bool
	InFlight     bool
	Window       Record
	CooldownLeft time.Duration
	// PrivilegeRefused: the last attempt was refused for lack of privilege (sticky until
	// a reset succeeds, a hot apply or a restart).
	PrivilegeRefused bool
	Last             Record
	HasLast          bool
	// LastVerified is the latest confirmed restart: verified with an empty Detail. A
	// return that did not confirm the restart is not one (review N3).
	LastVerified Record
	HasVerified  bool
}

// State reports server id's reset state.
func (s *Service) State(id string) State {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	st := State{CooldownLeft: max(s.next[id].Sub(now), 0), PrivilegeRefused: s.refused[id], InFlight: s.inflight[id] != ""}
	if o, ok := s.open[id]; ok {
		st.Restarting = true
		st.Window = Record{RequestedAt: o.rq.at, SentAt: o.sentAt, By: o.rq.actor.Username, Result: store.BMCResetSent,
			Deadline: o.until}
	}
	st.Last, st.HasLast = s.last[id]
	st.LastVerified, st.HasVerified = s.verified[id]
	return st
}

// CooldownLeft is how long until the next reset of id may start (0: now).
func (s *Service) CooldownLeft(id string) time.Duration { return s.State(id).CooldownLeft }

// Counts returns the resets per server and result since the app started (metrics).
func (s *Service) Counts() map[string]map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]map[string]int64, len(s.stats))
	for id, m := range s.stats {
		out[id] = maps.Clone(m)
	}
	return out
}

func (s *Service) count(id, result string) {
	if s.stats[id] == nil {
		s.stats[id] = map[string]int64{}
	}
	s.stats[id][result]++
}

// Shutdown refuses new requests, ignores windows that end from now on, cancels the work
// after a BMC's return and waits for it. Open windows stay open in the database: the
// next start re-arms them.
func (s *Service) Shutdown() {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	s.stop()
	s.wg.Wait()
}
