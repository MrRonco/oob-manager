package power

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/store"
)

// Defaults for Config.
const (
	DefaultCooldown        = 60 * time.Second // security.md §3: power cooldown 60 s per server
	DefaultPollEvery       = 3 * time.Second
	DefaultGracefulTimeout = 5 * time.Minute
	DefaultForcedTimeout   = 2 * time.Minute
	// DefaultRequestTimeout bounds login, reads and the reset POST (an iDRAC8 login alone
	// takes about 7 s).
	DefaultRequestTimeout = 60 * time.Second
)

// Controller is one operator session on one BMC (*redfish.Resetter).
type Controller interface {
	// Allowed is the BMC's ResetType@Redfish.AllowableValues.
	Allowed() []string
	PowerState(ctx context.Context) (bmc.PowerState, error)
	// Reset sends one ResetType; it must refuse values outside the closed set.
	Reset(ctx context.Context, resetType string) error
	Close(ctx context.Context) error
}

// Opener logs in with the server's operator account.
type Opener func(ctx context.Context) (Controller, error)

// Target is one configured server. A nil Open means the server has no operator login:
// its actions are disabled with that reason. SelfHost and Impact are the server's
// config power block, passed through for the confirm page.
type Target struct {
	ServerID string
	Open     Opener
	SelfHost bool
	Impact   []string
}

// Info is what the UI needs to know about a server's power control.
type Info struct {
	Configured bool // the server is known
	Operator   bool // an operator login exists, so actions can be sent
	SelfHost   bool
	Impact     []string // a copy
}

// Auditor records audit entries (*audit.Logger, which also ships them to GELF).
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) (store.AuditRecord, error)
}

// Actor is who asked, as the audit log records it.
type Actor struct {
	Username, Role, SrcIP, AuthMethod string
}

// Observation is a verified power transition: the end state as read from the BMC,
// when, and the action and user behind it (fleet.ObservePower takes it).
type Observation struct {
	State  bmc.PowerState
	At     time.Time
	Action Action
	By     string
}

// Config wires a Service. Audit is required.
type Config struct {
	Targets []Target
	Audit   Auditor
	// OnVerified, when set, is called with every verified end state (phase done), so the
	// fleet can show it at once instead of after the next poll (audit R2-08).
	OnVerified func(id string, o Observation)
	// Restarting, when set, reports that a server's BMC is restarting (the fleet's
	// restart window, tech_doc §37): its requests are refused before anything is sent.
	Restarting      func(id string) bool
	Logger          *slog.Logger
	Now             func() time.Time
	Cooldown        time.Duration
	PollEvery       time.Duration
	GracefulTimeout time.Duration // verification limit for graceful actions
	ForcedTimeout   time.Duration // verification limit for On and forced actions
	RequestTimeout  time.Duration
}

// Service runs power actions. It is safe for concurrent use.
type Service struct {
	cfg     Config
	targets atomic.Pointer[map[string]Target] // immutable; replaced by SetTargets

	mu      sync.Mutex
	closed  bool
	next    map[string]time.Time          // per server: when the cooldown ends
	last    map[string]Operation          // per server: latest operation
	cancels map[string]context.CancelFunc // per server: the running verification
	retired map[string]bool               // removed by SetTargets while verifying
	wg      sync.WaitGroup
}

// New validates cfg and builds the service.
func New(cfg Config) (*Service, error) {
	if cfg.Audit == nil {
		return nil, errors.New("power: Audit is required")
	}
	cfg = withDefaults(cfg)
	targets, err := targetMap(cfg.Targets)
	if err != nil {
		return nil, err
	}
	s := &Service{cfg: cfg, next: map[string]time.Time{}, last: map[string]Operation{},
		cancels: map[string]context.CancelFunc{}, retired: map[string]bool{}}
	s.targets.Store(&targets)
	return s, nil
}

func targetMap(ts []Target) (map[string]Target, error) {
	out := make(map[string]Target, len(ts))
	for _, t := range ts {
		if _, dup := out[t.ServerID]; dup || t.ServerID == "" {
			return nil, fmt.Errorf("power: duplicate or empty server ID %q", t.ServerID)
		}
		t.Impact = slices.Clone(t.Impact)
		out[t.ServerID] = t
	}
	return out, nil
}

// SetTargets replaces the controllable servers (settings slice S3). A server that is no
// longer listed stops its running verification (recorded as config_changed) and its
// state is forgotten; a server that stays keeps its cooldown and latest operation, and
// its new login and confirm-page context apply to the next request.
func (s *Service) SetTargets(ts []Target) error {
	next, err := targetMap(ts)
	if err != nil {
		return err
	}
	old := s.targets.Swap(&next)
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range *old {
		if _, ok := next[id]; ok {
			continue
		}
		if cancel := s.cancels[id]; cancel != nil {
			s.retired[id] = true
			cancel()
			delete(s.cancels, id)
		}
		delete(s.next, id)
		delete(s.last, id)
	}
	return nil
}

func withDefaults(c Config) Config {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.Now == nil {
		c.Now = time.Now
	}
	c.Cooldown = orDur(c.Cooldown, DefaultCooldown)
	c.PollEvery = orDur(c.PollEvery, DefaultPollEvery)
	c.GracefulTimeout = orDur(c.GracefulTimeout, DefaultGracefulTimeout)
	c.ForcedTimeout = orDur(c.ForcedTimeout, DefaultForcedTimeout)
	c.RequestTimeout = orDur(c.RequestTimeout, DefaultRequestTimeout)
	return c
}

func orDur(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}

// Info describes server id (zero Info when unknown).
func (s *Service) Info(id string) Info {
	t, ok := (*s.targets.Load())[id]
	if !ok {
		return Info{}
	}
	return Info{Configured: true, Operator: t.Open != nil, SelfHost: t.SelfHost, Impact: slices.Clone(t.Impact)}
}

// CooldownLeft is how long until the next action on id may start (0: now).
func (s *Service) CooldownLeft(id string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return max(s.next[id].Sub(s.cfg.Now()), 0)
}

// Last returns the latest operation on id.
func (s *Service) Last(id string) (Operation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.last[id]
	return op, ok
}

// Shutdown stops every running verification (each records "stopped") and refuses new
// requests. It waits for the verifications to finish.
func (s *Service) Shutdown() {
	s.mu.Lock()
	s.closed = true
	for _, cancel := range s.cancels {
		cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// request is one Request in flight.
type request struct {
	id     string
	action Action
	actor  Actor
	corr   string
	at     time.Time
}

// Request runs action on server id for actor: checks, audit "started" (fail-closed),
// login, ResetType offered and applicable, the reset POST, then verification in the
// background. A nil error means the BMC accepted the request; Last reports the outcome.
func (s *Service) Request(ctx context.Context, id string, action Action, actor Actor) error {
	rq := request{id: id, action: action, actor: actor, corr: newCorrelationID(), at: s.cfg.Now()}
	open, err := s.admit(rq)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()
	ctl, sent, err := s.send(ctx, rq, open)
	if err != nil {
		s.fail(rq, err, sent)
		return wrapBMC(err)
	}
	s.startVerify(rq, ctl)
	return nil
}

// admit applies the checks that need no BMC, reserves the cooldown and writes the
// "started" record.
func (s *Service) admit(rq request) (Opener, error) {
	t, known := (*s.targets.Load())[rq.id]
	open := t.Open
	switch {
	case !known:
		_ = s.audit(rq, audit.ResultDenied, "not_configured", nil)
		return nil, ErrNotConfigured
	case open == nil:
		_ = s.audit(rq, audit.ResultDenied, "no_operator", nil)
		return nil, ErrNoOperator
	case rq.action.ResetType() == "":
		_ = s.audit(rq, audit.ResultDenied, "unsupported", nil)
		return nil, ErrUnsupported
	case s.cfg.Restarting != nil && s.cfg.Restarting(rq.id):
		_ = s.audit(rq, audit.ResultDenied, "bmc_restarting", nil)
		return nil, ErrBMCRestarting
	}
	prev, err := s.reserve(rq)
	if err != nil {
		_ = s.audit(rq, audit.ResultDenied, auditClass(err), nil)
		return nil, err
	}
	if err := s.audit(rq, audit.ResultStarted, "", map[string]any{"phase": "requested"}); err != nil {
		s.release(rq, prev)
		return nil, ErrAudit
	}
	return open, nil
}

// reservation is what reserve replaced, so release can put it back: the previous
// cooldown end and the previous latest operation.
type reservation struct {
	next   time.Time
	op     Operation
	hadOp  bool
	sentAt time.Time // RequestedAt of the Sending operation reserve published
}

// reserve starts the cooldown, supersedes a running verification and publishes the
// operation as Sending, all under the lock that also checks the BMC reset interlock, so
// a reset that checks for a pending power action from now on sees this one (review N2:
// also while the "started" row is being written). It returns what it replaced, so a
// refusal before the POST can give it back.
func (s *Service) reserve(rq request) (reservation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return reservation{}, ErrNotConfigured
	}
	prev := s.next[rq.id]
	if left := prev.Sub(rq.at); left > 0 {
		return reservation{}, &CooldownError{Left: left}
	}
	if s.cfg.Restarting != nil && s.cfg.Restarting(rq.id) {
		// A BMC reset became busy since the first check (review N2). Checked under the
		// lock, before a running verification is superseded; the reset service never
		// holds its own lock while it reads this service, so the order is safe.
		return reservation{}, ErrBMCRestarting
	}
	if cancel := s.cancels[rq.id]; cancel != nil {
		cancel()
		delete(s.cancels, rq.id)
	}
	r := reservation{next: prev, sentAt: rq.at}
	r.op, r.hadOp = s.last[rq.id]
	s.next[rq.id] = rq.at.Add(s.cfg.Cooldown)
	s.last[rq.id] = Operation{Action: rq.action, By: rq.actor.Username, RequestedAt: rq.at, Phase: PhaseSending}
	return r, nil
}

// release gives back the cooldown and the previous latest operation (the started row
// could not be written, so nothing was sent), unless a newer request replaced them.
func (s *Service) release(rq request, r reservation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.last[rq.id]; !ok || cur.Phase != PhaseSending || !cur.RequestedAt.Equal(r.sentAt) {
		return
	}
	s.next[rq.id] = r.next
	if r.hadOp {
		s.last[rq.id] = r.op
	} else {
		delete(s.last, rq.id)
	}
}

// send logs in and posts the reset. sent reports whether the POST may have reached
// the BMC (then the cooldown stays).
func (s *Service) send(ctx context.Context, rq request, open Opener) (Controller, bool, error) {
	ctl, err := open(ctx)
	if err != nil {
		return nil, false, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = ctl.Close(ctx)
		}
	}()
	if !slices.Contains(ctl.Allowed(), rq.action.ResetType()) {
		return nil, false, ErrUnsupported
	}
	state, err := ctl.PowerState(ctx)
	if err != nil {
		return nil, false, err
	}
	if !rq.action.Applies(state) {
		return nil, false, fmt.Errorf("%w (%s)", ErrState, state)
	}
	if err := ctl.Reset(ctx, rq.action.ResetType()); err != nil {
		return nil, true, err
	}
	keep = true
	return ctl, true, nil
}

// fail records a refused or failed request and returns the cooldown when nothing was sent.
func (s *Service) fail(rq request, err error, sent bool) {
	class := auditClass(err)
	result := audit.ResultError
	if errors.Is(err, ErrUnsupported) || errors.Is(err, ErrState) {
		result = audit.ResultDenied
	}
	_ = s.audit(rq, result, class, nil)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !sent {
		delete(s.next, rq.id)
	}
	s.last[rq.id] = Operation{Action: rq.action, By: rq.actor.Username, RequestedAt: rq.at,
		FinishedAt: s.cfg.Now(), Phase: PhaseFailed, Class: class}
}

// wrapBMC wraps a failure for the caller: refusals keep their sentinel, BMC trouble
// becomes ErrBMC with the class.
func wrapBMC(err error) error {
	if errors.Is(err, ErrUnsupported) || errors.Is(err, ErrState) || errors.Is(err, ErrNotConfigured) ||
		errors.Is(err, ErrBMCRestarting) {
		return err
	}
	return fmt.Errorf("%w: %s", ErrBMC, bmc.Classify(err))
}

func auditClass(err error) string {
	switch {
	case errors.Is(err, ErrCoolingDown):
		return "cooldown"
	case errors.Is(err, ErrBMCRestarting):
		return "bmc_restarting"
	case errors.Is(err, ErrUnsupported):
		return "unsupported"
	case errors.Is(err, ErrState):
		return "state"
	case errors.Is(err, ErrNotConfigured):
		return "not_configured"
	default:
		return string(bmc.Classify(err))
	}
}

// audit records one entry for rq.
func (s *Service) audit(rq request, result, class string, extra map[string]any) error {
	params := map[string]any{"reset_type": rq.action.ResetType()}
	for k, v := range extra {
		params[k] = v
	}
	_, err := s.cfg.Audit.Record(context.Background(), audit.Entry{CorrelationID: rq.corr,
		Principal: rq.actor.Username, AuthMethod: rq.actor.AuthMethod, Role: rq.actor.Role, SrcIP: rq.actor.SrcIP,
		ServerID: rq.id, Action: auditAction(rq.action), Params: params, Result: result, ErrorClass: class})
	if err != nil {
		s.cfg.Logger.Error("power audit record failed", "server", rq.id, "action", string(rq.action), "err", err)
	}
	return err
}

// auditAction is the audit action name; an action outside the enum is still recorded.
func auditAction(a Action) string {
	if name := a.Authz(); name != "" {
		return string(name)
	}
	return "power.invalid"
}

func newCorrelationID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
