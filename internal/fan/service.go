package fan

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/audit"
	"oob-manager/internal/authz"
	"oob-manager/internal/store"
)

// Audit actions written by the service besides authz.FanLeaseCreate/FanLeaseEnd.
const (
	ActionApplied = "fan.lease.applied" // the enforcing side confirmed the lease
	ActionExpire  = "fan.lease.expire"  // expiry, enforced by the reconciler
	ActionReapply = "fan.lease.reapply" // startup: an unexpired lease applied again
	systemActor   = "system"
)

// DefaultTick is how often Run reconciles (expiry, pending → applied).
const DefaultTick = 15 * time.Second

// Auditor records audit entries (*audit.Logger, which also ships GELF).
type Auditor interface {
	Record(ctx context.Context, e audit.Entry) (store.AuditRecord, error)
}

// Actor is who asked, for the audit row.
type Actor struct {
	Username, Role, IP, Method string
}

// Config wires a Service.
type Config struct {
	Policies []Policy
	// Appliers holds one applier per server with a fan mode other than none.
	Appliers map[string]Applier
	Leases   store.LeaseRepository
	Audit    Auditor
	Now      func() time.Time
	Logger   *slog.Logger
	Tick     time.Duration
	// AuditTimeout bounds each audit write (default DefaultAuditTimeout): writes run under
	// a server's mutex, so a hung audit store must not hold it, and End and the
	// reconciler behind it, forever.
	AuditTimeout time.Duration
}

// DefaultAuditTimeout is Config.AuditTimeout when unset.
const DefaultAuditTimeout = 10 * time.Second

// Service is the lease arbiter. It is safe for concurrent use; work on one server is
// serialised by that server's mutex. The server set can be replaced at run time
// (SetTargets): readers load an immutable table, and work that started on a table
// that was replaced in the meantime is refused (ErrNotConfigured).
type Service struct {
	cfg   Config
	cur   atomic.Pointer[table]
	setMu sync.Mutex // serialises SetTargets

	// pending are BMC-side fan floors to apply again after a BMC restart whose return
	// was not (yet) followed by a successful re-apply (bmcreset.go).
	reMu    sync.Mutex
	pending map[string]reapplyState
}

// table is one immutable generation of the fan setup. A server's mutex is kept while
// its setup is unchanged and replaced when it changes, so a holder of the old mutex
// can tell (current) that it must not act.
type table struct {
	policies map[string]Policy
	appliers map[string]Applier
	locks    map[string]*sync.Mutex
	fps      map[string]string
}

func (t *table) lockOf(id string) *sync.Mutex { return t.locks[id] }

// Status is one server's fan state for the UI and API.
type Status struct {
	Policy Policy
	Observation
	Lease     store.FanLease
	HasLease  bool
	Remaining time.Duration
}

// New validates cfg: every enabled policy needs an applier and every applier a policy.
func New(cfg Config) (*Service, error) {
	if cfg.Leases == nil || cfg.Audit == nil {
		return nil, errors.New("fan: Leases and Audit are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Tick <= 0 {
		cfg.Tick = DefaultTick
	}
	if cfg.AuditTimeout <= 0 {
		cfg.AuditTimeout = DefaultAuditTimeout
	}
	ts := make([]Target, 0, len(cfg.Policies))
	for _, p := range cfg.Policies {
		ts = append(ts, Target{Policy: p, Applier: cfg.Appliers[p.ServerID]})
	}
	t, err := buildTable(ts)
	if err != nil {
		return nil, err
	}
	for id := range cfg.Appliers {
		if p, ok := t.policies[id]; !ok || !p.Enabled() {
			return nil, fmt.Errorf("fan: applier for %q without an enabled policy", id)
		}
	}
	s := &Service{cfg: cfg, pending: map[string]reapplyState{}}
	s.cur.Store(t)
	return s, nil
}

// buildTable validates targets: unique servers, an applier exactly for enabled policies.
func buildTable(ts []Target) (*table, error) {
	t := &table{policies: map[string]Policy{}, appliers: map[string]Applier{}, locks: map[string]*sync.Mutex{},
		fps: map[string]string{}}
	for _, x := range ts {
		p := x.Policy
		if _, dup := t.policies[p.ServerID]; dup || p.ServerID == "" {
			return nil, fmt.Errorf("fan: duplicate or empty server %q", p.ServerID)
		}
		switch {
		case p.Enabled() && x.Applier == nil:
			return nil, fmt.Errorf("fan: server %q has mode %s but no applier", p.ServerID, p.Mode)
		case !p.Enabled() && x.Applier != nil:
			return nil, fmt.Errorf("fan: applier for %q without an enabled policy", p.ServerID)
		case p.Enabled():
			t.appliers[p.ServerID] = x.Applier
		}
		t.policies[p.ServerID], t.locks[p.ServerID], t.fps[p.ServerID] = p, &sync.Mutex{}, x.Fingerprint
	}
	return t, nil
}

// Policy returns the policy of a server whose fans can be leased.
func (s *Service) Policy(serverID string) (Policy, bool) {
	p, ok := s.cur.Load().policies[serverID]
	return p, ok && p.Enabled()
}

func (s *Service) target(serverID string) (Policy, Applier, *sync.Mutex, error) {
	t := s.cur.Load()
	p, ok := t.policies[serverID]
	if !ok || !p.Enabled() {
		return Policy{}, nil, nil, ErrNotConfigured
	}
	return p, t.appliers[serverID], t.lockOf(serverID), nil
}

// current reports whether mu (taken from target) is still serverID's mutex, i.e. its
// fan setup was not replaced while the caller waited for the lock.
func (s *Service) current(serverID string, mu *sync.Mutex) bool {
	return s.cur.Load().lockOf(serverID) == mu
}

// Status reads the active lease (if any) and the enforcing side's report. It never
// contacts a BMC.
func (s *Service) Status(ctx context.Context, serverID string) (Status, error) {
	p, ap, _, err := s.target(serverID)
	if err != nil {
		return Status{}, err
	}
	st := Status{Policy: p}
	l, err := s.cfg.Leases.Active(ctx, serverID)
	switch {
	case err == nil:
		st.Lease, st.HasLease = l, true
		st.Remaining = max(l.ExpiresAt.Sub(s.cfg.Now()), 0)
	case !errors.Is(err, store.ErrNotFound):
		return Status{}, err
	}
	st.Observation = ap.Observe(st.Lease, st.HasLease)
	return st, nil
}

// Start creates and applies a lease. The row is stored (with the value to restore)
// before the applier touches anything, so a crash at any point is reconciled.
func (s *Service) Start(ctx context.Context, a Actor, serverID string, r Request) (store.FanLease, error) {
	p, ap, mu, err := s.target(serverID)
	if err != nil {
		return store.FanLease{}, err
	}
	if r.Pct < p.SafeMin || r.Pct > 100 || r.Duration < MinLease || r.Duration > p.MaxLease {
		return store.FanLease{}, ErrInvalid
	}
	mu.Lock()
	defer mu.Unlock()
	if !s.current(serverID, mu) {
		return store.FanLease{}, ErrNotConfigured
	}
	if _, activeErr := s.cfg.Leases.Active(ctx, serverID); activeErr == nil {
		s.record(ctx, a, authz.FanLeaseCreate, serverID, audit.ResultDenied, "active", nil)
		return store.FanLease{}, ErrActive
	}
	// Fail closed like power and the consoles: no BMC read, lease row or applier call
	// without a "started" row in the audit log.
	if auditErr := s.recordStrict(ctx, a, authz.FanLeaseCreate, serverID, audit.ResultStarted, "", requestParams(p, r)); auditErr != nil {
		return store.FanLease{}, ErrAudit
	}
	return s.startAudited(ctx, a, p, ap, r)
}

// startAudited is Start after its "started" row: every failure from here on writes a
// closing error row, so no started row is left without an outcome.
func (s *Service) startAudited(ctx context.Context, a Actor, p Policy, ap Applier, r Request) (store.FanLease, error) {
	serverID := p.ServerID
	plan, err := ap.Prepare(ctx, r.Pct, p.SafeMin)
	if err == nil && (plan.Pct < p.SafeMin || plan.Pct > 100) {
		err = fmt.Errorf("planned floor %d %% is outside [%d, 100]", plan.Pct, p.SafeMin)
	}
	if err != nil {
		s.record(ctx, a, authz.FanLeaseCreate, serverID, audit.ResultError, errorClass(err), requestParams(p, r))
		return store.FanLease{}, fmt.Errorf("%w: %w", ErrApply, err)
	}
	l, err := s.newLease(a, p, r, plan)
	if err == nil {
		err = s.cfg.Leases.Create(ctx, l)
	}
	if err != nil {
		s.record(ctx, a, authz.FanLeaseCreate, serverID, audit.ResultError, "store", requestParams(p, r))
		return store.FanLease{}, err
	}
	return s.apply(ctx, a, p, ap, l, r)
}

func (s *Service) newLease(a Actor, p Policy, r Request, plan Plan) (store.FanLease, error) {
	id, err := newLeaseID()
	if err != nil {
		return store.FanLease{}, err
	}
	now := s.cfg.Now().UTC().Truncate(time.Second)
	return store.FanLease{LeaseID: id, ServerID: p.ServerID, Mode: store.LeaseBoost, Pct: plan.Pct,
		IssuedAt: now, ExpiresAt: now.Add(r.Duration), RequestedBy: a.Username, State: store.LeasePending,
		OriginalValue: plan.Original, HasOriginal: plan.HasOriginal, UpdatedAt: now}, nil
}

func (s *Service) apply(ctx context.Context, a Actor, p Policy, ap Applier, l store.FanLease, r Request) (store.FanLease, error) {
	params := leaseParams(p, l, r)
	immediate, err := ap.Apply(ctx, l)
	if err != nil {
		relErr := ap.Release(ctx, l)
		trErr := s.cfg.Leases.Transition(ctx, l.LeaseID, store.LeasePending, store.LeaseRejected, s.cfg.Now())
		if relErr != nil || trErr != nil {
			s.cfg.Logger.Error("fan lease cleanup after a failed apply", "server", l.ServerID,
				"release_error", relErr, "transition_error", trErr)
		}
		s.record(ctx, a, authz.FanLeaseCreate, l.ServerID, audit.ResultError, errorClass(err), params)
		return store.FanLease{}, fmt.Errorf("%w: %w", ErrApply, err)
	}
	if immediate {
		if trErr := s.cfg.Leases.Transition(ctx, l.LeaseID, store.LeasePending, store.LeaseApplied, s.cfg.Now()); trErr != nil {
			// The floor is applied but its state is not stored; the reconciler finds the
			// pending row and expiry still applies.
			s.record(ctx, a, authz.FanLeaseCreate, l.ServerID, audit.ResultError, "store", params)
			return store.FanLease{}, trErr
		}
		l.State = store.LeaseApplied
	}
	s.record(ctx, a, authz.FanLeaseCreate, l.ServerID, audit.ResultOK, "", params)
	return l, nil
}

// End removes the active lease's effect, then marks it ended. If the applier fails the
// lease stays active (and expiry still applies), so nothing is silently left behind.
func (s *Service) End(ctx context.Context, a Actor, serverID string) error {
	_, ap, mu, err := s.target(serverID)
	if err != nil {
		return err
	}
	mu.Lock()
	defer mu.Unlock()
	if !s.current(serverID, mu) {
		return ErrNotConfigured
	}
	l, err := s.cfg.Leases.Active(ctx, serverID)
	if errors.Is(err, store.ErrNotFound) {
		return ErrNoLease
	}
	if err != nil {
		return err
	}
	params := map[string]any{"lease_id": l.LeaseID, "pct": l.Pct}
	if err := ap.Release(ctx, l); err != nil {
		s.record(ctx, a, authz.FanLeaseEnd, serverID, audit.ResultError, errorClass(err), params)
		return fmt.Errorf("%w: %w", ErrRelease, err)
	}
	if err := s.cfg.Leases.Transition(ctx, l.LeaseID, l.State, store.LeaseEnded, s.cfg.Now()); err != nil {
		return err
	}
	s.record(ctx, a, authz.FanLeaseEnd, serverID, audit.ResultOK, "", params)
	return nil
}

func (s *Service) record(ctx context.Context, a Actor, action authz.Action, serverID, result, class string, params map[string]any) {
	_ = s.recordStrict(ctx, a, action, serverID, result, class, params) // logged by audit
}

// recordStrict is record that returns the audit error, for the row that gates an action.
func (s *Service) recordStrict(ctx context.Context, a Actor, action authz.Action, serverID, result, class string, params map[string]any) error {
	return s.audit(ctx, audit.Entry{Principal: a.Username, AuthMethod: a.Method, Role: a.Role, SrcIP: a.IP,
		ServerID: serverID, Action: string(action), Params: params, Result: result, ErrorClass: class})
}

func (s *Service) audit(ctx context.Context, e audit.Entry) error {
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.AuditTimeout)
	defer cancel()
	_, err := s.cfg.Audit.Record(actx, e)
	if err != nil {
		s.cfg.Logger.Error("fan audit record failed", "action", e.Action, "server", e.ServerID, "err", err)
	}
	return err
}

func requestParams(p Policy, r Request) map[string]any {
	return map[string]any{"pct": r.Pct, "minutes": int(r.Duration / time.Minute), "mode": string(p.Mode)}
}

func leaseParams(p Policy, l store.FanLease, r Request) map[string]any {
	m := requestParams(p, r)
	m["pct"], m["lease_id"], m["expires_at"] = l.Pct, l.LeaseID, l.ExpiresAt.Unix()
	if l.Pct != r.Pct {
		m["requested_pct"] = r.Pct
	}
	return m
}

// newLeaseID is 128 random bits in hex: the lease file's nonce and the ack's key.
func newLeaseID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("fan: lease id: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}
