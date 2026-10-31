package notify

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/fleet"
	"oob-manager/internal/store"
)

// Service defaults.
const (
	DefaultWatchEvery = 15 * time.Second
	eventQueueSize    = 256
)

// Errors returned by the change methods. Messages are safe to show to an admin.
var (
	ErrNotFound = errors.New("notify: no such notification target")
	ErrLocked   = errors.New("notify: managed by config.yaml or the Integrations section is locked")
	ErrExists   = errors.New("notify: a target with this id already exists")
)

// Recorder writes audit rows (*audit.Logger).
type Recorder = admin.Recorder

// FileTarget is a target from config.yaml with its secrets from the age file.
type FileTarget struct {
	Target  Target
	Secrets Secrets
}

// Config wires a Service. DB, Audit and Sealer are required for browser-managed
// targets; without DB only file targets exist and every change is refused.
type Config struct {
	DB     *store.DB
	Audit  Recorder
	Sealer *Sealer
	File   []FileTarget
	// Locked is settings.locked containing "integrations": the browser cannot change
	// targets (maintenance mode stays available).
	Locked bool
	// Suppress is maintenance mode and event acknowledgement (nil: nothing is suppressed).
	Suppress Suppressor
	// Fleet is read by the detector every WatchEvery (nil: no poller events).
	Fleet      fleet.Reader
	WatchEvery time.Duration
	Debounce   time.Duration
	Dispatch   DispatchConfig
	Logger     *slog.Logger
	Now        func() time.Time
}

// entry is one routable target with its opened secrets.
type entry struct {
	t         Target
	sec       Secrets
	unsealErr bool // stored secrets could not be opened; deliveries would fail
}

// registry is an immutable view of every target, swapped atomically.
type registry struct {
	order    []string
	byID     map[string]entry
	shadowed []string // DB target ids hidden by a file target with the same id
}

// Service routes events to targets and manages targets.
type Service struct {
	cfg    Config
	disp   *Dispatcher
	det    *Detector
	reg    atomic.Pointer[registry]
	events chan Event
	write  sync.Mutex // serialises changes (reload after each)

	droppedEvents atomic.Uint64
}

// New loads the targets and returns an idle service; call Run.
func New(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	cfg.WatchEvery = orDur(cfg.WatchEvery, DefaultWatchEvery)
	if cfg.DB != nil && (cfg.Audit == nil || cfg.Sealer == nil) {
		return nil, errors.New("notify: Audit and Sealer are required with DB")
	}
	for _, f := range cfg.File {
		if err := Validate(f.Target, f.Secrets); err != nil {
			return nil, err
		}
	}
	s := &Service{cfg: cfg, det: NewDetector(cfg.Debounce), events: make(chan Event, eventQueueSize)}
	if cfg.Suppress != nil {
		s.det.acked = cfg.Suppress.Acked
	}
	dc := cfg.Dispatch
	dc.Logger, dc.Now = cfg.Logger, cfg.Now
	dc.OnFailing = s.onFailing
	s.disp = NewDispatcher(dc)
	if err := s.reload(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// reload rebuilds the registry from the file targets and the database.
func (s *Service) reload(ctx context.Context) error {
	reg := &registry{byID: map[string]entry{}}
	for _, f := range s.cfg.File {
		t := f.Target.clone()
		t.Source = SourceFile
		reg.order = append(reg.order, t.ID)
		reg.byID[t.ID] = entry{t: t, sec: f.Secrets}
	}
	if s.cfg.DB != nil {
		if err := s.loadDB(ctx, reg); err != nil {
			return err
		}
	}
	s.reg.Store(reg)
	return nil
}

func (s *Service) loadDB(ctx context.Context, reg *registry) error {
	rows, lerr := s.cfg.DB.Notify().Targets(ctx)
	if lerr != nil {
		return lerr
	}
	for _, r := range rows {
		if _, dup := reg.byID[r.ID]; dup {
			reg.shadowed = append(reg.shadowed, r.ID)
			s.cfg.Logger.Warn("notify: target shadowed by config.yaml", "target", r.ID)
			continue
		}
		t, err := fromRow(r)
		if err != nil {
			s.cfg.Logger.Error("notify: stored target ignored", "target", r.ID, "err", err)
			continue
		}
		e := entry{t: t}
		if len(r.SecretEnc) > 0 {
			sec, err := s.cfg.Sealer.Open(t, r.SecretEnc)
			e.sec, e.unsealErr = sec, err != nil
			if err != nil {
				s.cfg.Logger.Error("notify: stored secrets cannot be opened", "target", r.ID)
			}
		}
		reg.order = append(reg.order, t.ID)
		reg.byID[t.ID] = e
	}
	return nil
}

// Emit queues an event without blocking (dropped and counted when the queue is full).
func (s *Service) Emit(e Event) {
	if e.ID == "" {
		e.ID = newEventID()
	}
	if e.At.IsZero() {
		e.At = s.cfg.Now()
	}
	select {
	case s.events <- e:
	default:
		if n := s.droppedEvents.Add(1); n == 1 || n%100 == 0 {
			s.cfg.Logger.Warn("notify: event queue full; event dropped", "class", string(e.Class), "dropped", n)
		}
	}
}

// Run routes events and watches the fleet until ctx ends, then waits for in-flight
// deliveries to stop.
func (s *Service) Run(ctx context.Context) {
	s.disp.Start(ctx)
	defer s.disp.Wait()
	tick := time.NewTicker(s.cfg.WatchEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-s.events:
			s.route(e)
		case <-tick.C:
			s.watch()
		}
	}
}

func (s *Service) watch() {
	if s.cfg.Fleet == nil {
		return
	}
	for _, e := range s.det.Observe(s.cfg.Fleet.Servers(), s.cfg.Now()) {
		s.route(e)
	}
}

// route hands e to every target that wants it, unless the server is in maintenance and
// the class is mutable. When a window ends the detector forgets the server, so a
// problem that is still present is reported again (once, after the debounce).
func (s *Service) route(e Event) {
	reg := s.reg.Load()
	if e.Class == ClassMaintenance && e.Recovery {
		s.det.Forget(e.ServerID)
	}
	if e.Class.Mutable() && e.ServerID != "" && s.cfg.Suppress != nil && s.cfg.Suppress.InMaintenance(e.ServerID, s.cfg.Now()) {
		s.cfg.Logger.Info("notify: suppressed by maintenance", "server", e.ServerID, "class", string(e.Class))
		return
	}
	for _, id := range reg.order {
		en := reg.byID[id]
		if en.t.Wants(e) {
			s.disp.Enqueue(en.t, en.sec, e)
		}
	}
}

// onFailing raises the self-alert to every other target.
func (s *Service) onFailing(t Target, failing bool) {
	e := Event{Class: ClassNotify, Severity: SeverityWarning, Key: "notify/" + t.ID, ExcludeTarget: t.ID,
		Recovery: !failing}
	if failing {
		e.Title = "Notifications to " + t.Name + " are failing"
		e.Message = "Messages to the " + t.Kind.Label() + " target " + t.Name + " failed several times in a row. " +
			"Check Settings → Notifications."
	} else {
		e.Title = "Notifications to " + t.Name + " work again"
		e.Message = "Messages to the " + t.Kind.Label() + " target " + t.Name + " are delivered again."
	}
	s.Emit(e)
}

// TargetView is what the UI shows about a target: never its secrets, only whether
// they are set and their version.
type TargetView struct {
	Target      Target
	HasSecret   bool
	SecretError bool // stored secrets cannot be opened (re-enter them)
	Status      Status
}

// Targets lists every target in order (file targets first).
func (s *Service) Targets() []TargetView {
	reg := s.reg.Load()
	out := make([]TargetView, 0, len(reg.order))
	for _, id := range reg.order {
		out = append(out, s.view(reg.byID[id]))
	}
	return out
}

// Target returns one target.
func (s *Service) Target(id string) (TargetView, bool) {
	en, ok := s.reg.Load().byID[id]
	if !ok {
		return TargetView{}, false
	}
	return s.view(en), true
}

func (s *Service) view(en entry) TargetView {
	return TargetView{Target: en.t.clone(), HasSecret: !en.sec.IsZero() || en.unsealErr, SecretError: en.unsealErr,
		Status: s.disp.Status(en.t.ID)}
}

// Shadowed lists browser-saved target ids hidden by config.yaml.
func (s *Service) Shadowed() []string { return slices.Clone(s.reg.Load().shadowed) }

// Failing returns the names of targets that keep failing (the Overview banner).
func (s *Service) Failing() []string {
	var out []string
	for _, v := range s.Targets() {
		if v.Target.Enabled && v.Status.Failing {
			out = append(out, v.Target.Name)
		}
	}
	return out
}

// Locked reports whether targets are read-only in the browser.
func (s *Service) Locked() bool { return s.cfg.Locked || s.cfg.DB == nil }
