package bmcsec

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
	"oob-manager/internal/notify"
	"oob-manager/internal/store"
)

// Audit actions (the authz action names are server.security.view, .rerun and .accept).
const (
	ActionAccept   = "server.security.accept"
	ActionUnaccept = "server.security.unaccept"
	ActionRerun    = "server.security.rerun"
)

// Defaults.
const (
	// DefaultWatchEvery is how often Run looks for new findings and stale acceptances (an
	// in-memory evaluation, like the notification detector's pass).
	DefaultWatchEvery = 15 * time.Second
	// DefaultRerunCooldown is the shortest time between two re-runs of one server: a run
	// is a few dozen BMC reads and handshakes.
	DefaultRerunCooldown = 5 * time.Minute
	// MaxComment is the longest acceptance comment, in bytes.
	MaxComment = 500
)

// Errors.
var (
	ErrUnavailable = errors.New("bmcsec: not available (no database)")
	ErrNotFound    = errors.New("bmcsec: no such server or finding")
	ErrInvalid     = errors.New("bmcsec: invalid input")
	ErrNotProblem  = errors.New("bmcsec: only a warning or a failure can be accepted as a risk")
	// ErrChanged: the finding is not the one the admin looked at (another result or
	// subject since the page was loaded), so nothing was accepted.
	ErrChanged = errors.New("bmcsec: the finding changed since the page was loaded")
)

// CooldownError refuses a re-run inside the cooldown.
type CooldownError struct{ Left time.Duration }

func (e *CooldownError) Error() string {
	return "bmcsec: the checks ran moments ago; try again in " + e.Left.Round(time.Second).String()
}

// Recorder writes audit rows (*audit.Logger).
type Recorder = admin.Recorder

// Config wires a Service. Fleet and Inputs are required; without DB (and Audit) the
// service only evaluates: acceptances, re-runs and notifications are off.
type Config struct {
	DB     *store.DB
	Audit  Recorder
	Fleet  fleet.Reader
	Inputs func(serverID string) (Inputs, bool)
	// Rerun asks the server's poller to run the checks now (fleet.RequestPosture).
	Rerun func(serverID string) error
	// Emit sends notifications (nil: none); ServerName names servers in them.
	Emit       func(notify.Event)
	ServerName func(id string) string
	WatchEvery time.Duration
	Cooldown   time.Duration
	Logger     *slog.Logger
	Now        func() time.Time
}

// Service evaluates the fleet's postures, keeps the accepted risks and sends the
// notifications of new findings. Reads are lock-free.
type Service struct {
	cfg     Config
	accepts atomic.Pointer[map[string]Acceptance] // by acceptKey
	write   sync.Mutex                            // serialises changes (reload after each)
	rerunMu sync.Mutex
	rerunAt map[string]time.Time // last accepted re-run per server
	// notified is the watch loop's copy of security_notified (Tick runs on one goroutine).
	notified map[string]map[string]string
}

// New loads the stored acceptances and notification state.
func New(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Fleet == nil || cfg.Inputs == nil {
		return nil, errors.New("bmcsec: Fleet and Inputs are required")
	}
	if cfg.DB != nil && cfg.Audit == nil {
		return nil, errors.New("bmcsec: Audit is required with DB")
	}
	cfg.Logger = cmp.Or(cfg.Logger, slog.Default())
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.WatchEvery = cmp.Or(cfg.WatchEvery, DefaultWatchEvery)
	cfg.Cooldown = cmp.Or(cfg.Cooldown, DefaultRerunCooldown)
	s := &Service{cfg: cfg, rerunAt: map[string]time.Time{}, notified: map[string]map[string]string{}}
	if err := s.reload(ctx); err != nil {
		return nil, err
	}
	if err := s.loadNotified(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

func acceptKey(serverID, checkID string) string { return serverID + "\x00" + checkID }

func (s *Service) reload(ctx context.Context) error {
	m := map[string]Acceptance{}
	if s.cfg.DB != nil {
		rows, err := s.cfg.DB.Security().Accepts(ctx)
		if err != nil {
			return err
		}
		for _, r := range rows {
			m[acceptKey(r.ServerID, r.CheckID)] = Acceptance{ServerID: r.ServerID, ServerAddr: r.ServerAddr, CheckID: r.CheckID,
				Result: Result(r.Result), Subject: r.Subject, SubjectHash: r.SubjectHash, Comment: r.Comment, By: r.AcceptedBy,
				At: r.AcceptedAt}
		}
	}
	s.accepts.Store(&m)
	return nil
}

// Available reports whether acceptances and re-runs can be used (a database is wired).
func (s *Service) Available() bool { return s.cfg.DB != nil }

// evaluate is the server's report before acceptances are applied, with the inputs it
// was evaluated with. A server the registry has no inputs for (being removed, or gone
// from config.yaml) is not evaluated: zero inputs would make its findings look resolved.
func (s *Service) evaluate(id string) (Report, Inputs, bool) {
	st, ok := s.cfg.Fleet.Server(id)
	if !ok || !st.HasPosture {
		return Report{}, Inputs{}, false
	}
	in, ok := s.cfg.Inputs(id)
	if !ok {
		return Report{}, Inputs{}, false
	}
	return Evaluate(id, st.Posture, in, s.cfg.Now()), in, true
}

// Report is the server's evaluated checks with the accepted risks marked. It never
// contacts a BMC: the posture is the poller's last read. An acceptance applies only
// while the server still has the BMC address it was made for: the binding holds here,
// where acceptances are applied, not only in the sweep that deletes stale rows.
func (s *Service) Report(serverID string) (Report, bool) {
	r, in, ok := s.evaluate(serverID)
	if !ok {
		return Report{}, false
	}
	accepts := *s.accepts.Load()
	for i, f := range r.Findings {
		if a, found := accepts[acceptKey(serverID, f.Check.ID)]; found && a.ServerAddr == in.Address && a.Covers(f) {
			r.Findings[i].Accepted = &a
		}
	}
	return r, true
}

// RunStatus is a server's security check run state, for the page.
type RunStatus struct {
	Enabled    bool // the server has security checks
	HasReport  bool
	AsOf       time.Time
	Took       time.Duration
	Every      time.Duration
	NextAround time.Time // when the next scheduled run is due (zero: none read yet)
	Running    bool
	Requested  bool
	Overdue    bool
	Error      bmc.ErrorClass // the last run failed (the previous report is kept)
	// CooldownLeft is how long until a re-run is accepted.
	CooldownLeft time.Duration
}

// Status reports a server's run state from the fleet.
func (s *Service) Status(serverID string) RunStatus {
	st, ok := s.cfg.Fleet.Server(serverID)
	if !ok {
		return RunStatus{}
	}
	rs := RunStatus{Enabled: st.PostureEnabled, HasReport: st.HasPosture, Every: st.PostureEvery, Running: st.PostureRunning,
		Requested: st.PostureRequested, Overdue: st.PostureOverdue, Error: st.PostureError, CooldownLeft: s.cooldownLeft(serverID)}
	if st.HasPosture {
		rs.AsOf, rs.Took, rs.NextAround = st.PostureAsOf, st.Posture.Duration, st.PostureAsOf.Add(st.PostureEvery)
	}
	return rs
}

func (s *Service) cooldownLeft(id string) time.Duration {
	s.rerunMu.Lock()
	defer s.rerunMu.Unlock()
	at, ok := s.rerunAt[id]
	if !ok {
		return 0
	}
	return max(at.Add(s.cfg.Cooldown).Sub(s.cfg.Now()), 0)
}

// Rerun asks the server's poller to run the checks now. The per-server cooldown is
// reserved before the fleet is asked and given back when the fleet refuses. Audited
// fail-closed like a power action: a `started` row is written before the fleet is
// asked (no row, no request), then exactly one final row, `ok` or `error` with the
// refusal's class; a cooldown refusal is a `denied` row.
func (s *Service) Rerun(ctx context.Context, a admin.Actor, serverID string) error {
	if s.cfg.DB == nil || s.cfg.Rerun == nil {
		return ErrUnavailable
	}
	if st, ok := s.cfg.Fleet.Server(serverID); !ok || !st.PostureEnabled {
		return ErrNotFound
	}
	if left, ok := s.reserve(serverID); !ok {
		return errors.Join(&CooldownError{Left: left}, s.record(ctx, auditEntry(a, serverID, ActionRerun, nil, audit.ResultDenied, "cooldown")))
	}
	if err := s.record(ctx, auditEntry(a, serverID, ActionRerun, nil, audit.ResultStarted, "")); err != nil {
		s.release(serverID)
		return err
	}
	if err := s.cfg.Rerun(serverID); err != nil {
		s.release(serverID)
		return errors.Join(err, s.record(ctx, auditEntry(a, serverID, ActionRerun, nil, audit.ResultError, rerunClass(err))))
	}
	return s.record(ctx, auditEntry(a, serverID, ActionRerun, nil, audit.ResultOK, ""))
}

func rerunClass(err error) string {
	if errors.Is(err, fleet.ErrPaused) {
		return "paused"
	}
	return "refused"
}

func (s *Service) reserve(id string) (time.Duration, bool) {
	s.rerunMu.Lock()
	defer s.rerunMu.Unlock()
	now := s.cfg.Now()
	if at, ok := s.rerunAt[id]; ok && now.Before(at.Add(s.cfg.Cooldown)) {
		return at.Add(s.cfg.Cooldown).Sub(now), false
	}
	s.rerunAt[id] = now
	return 0, true
}

func (s *Service) release(id string) {
	s.rerunMu.Lock()
	defer s.rerunMu.Unlock()
	delete(s.rerunAt, id)
}

// record writes an audit row outside a transaction. A failure is logged and returned:
// the callers fail closed, an action that cannot be audited is refused.
func (s *Service) record(ctx context.Context, e audit.Entry) error {
	if _, err := s.cfg.Audit.Record(ctx, e); err != nil {
		s.cfg.Logger.Error("bmcsec: audit failed", "action", e.Action, "err", err)
		return fmt.Errorf("bmcsec: audit %s: %w", e.Action, err)
	}
	return nil
}

func auditEntry(a admin.Actor, serverID, action string, p map[string]any, result, class string) audit.Entry {
	return audit.Entry{Principal: a.Username, AuthMethod: a.Method, Role: string(a.Role), SrcIP: a.IP,
		ServerID: serverID, Action: action, Params: p, Result: result, ErrorClass: class}
}

var systemActor = admin.Actor{Username: "system", Method: "system"}

// Run watches the fleet until ctx ends: it ends acceptances whose finding was resolved
// or changed and sends the notifications of new findings and expiring certificates.
func (s *Service) Run(ctx context.Context) {
	tick := time.NewTicker(s.cfg.WatchEvery)
	defer tick.Stop()
	for {
		s.Tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Tick is one pass of Run (exported for tests and for a first pass at startup).
func (s *Service) Tick(ctx context.Context) {
	if s.cfg.DB == nil {
		return
	}
	s.expireAcceptances(ctx)
	s.watch(ctx)
}

func (s *Service) name(id string) string {
	if s.cfg.ServerName != nil {
		return cmp.Or(s.cfg.ServerName(id), id)
	}
	return id
}

func itoa(n int) string { return strconv.Itoa(n) }
