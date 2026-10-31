package fleet

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/bmc"
)

// closeTimeout bounds deleting BMC sessions at shutdown and when a server is removed.
const closeTimeout = 10 * time.Second

// ErrStopped is returned by Apply once Run has returned.
var ErrStopped = errors.New("fleet: stopped")

// Fleet runs the pollers and implements Reader. The set of servers can change at run
// time through Apply (settings slice S3); readers load an immutable roster without
// locks.
type Fleet struct {
	cfg    Config
	roster atomic.Pointer[roster]

	// mu serialises writers (Apply, Run start and stop); readers never take it.
	mu      sync.Mutex
	runCtx  context.Context // nil before Run
	stopped bool
}

// roster is one immutable generation of the server set, in display order.
type roster struct {
	order []*poller
	byID  map[string]*poller
}

func newRoster(ps []*poller) *roster {
	r := &roster{order: ps, byID: make(map[string]*poller, len(ps))}
	for _, p := range ps {
		r.byID[p.target.ID] = p
	}
	return r
}

var _ Reader = (*Fleet)(nil)

// New validates cfg and builds an idle fleet; call Run to start polling. A fleet with
// no targets is valid (servers can be added later with Apply).
func New(cfg Config) (*Fleet, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg = cfg.withDefaults()
	f := &Fleet{cfg: cfg}
	ps := make([]*poller, 0, len(cfg.Targets))
	for _, t := range cfg.Targets {
		ps = append(ps, f.newPoller(t))
	}
	f.roster.Store(newRoster(ps))
	return f, nil
}

func (f *Fleet) newPoller(t Target) *poller {
	p := newPoller(f.cfg, t)
	if p.interval > orValue(t.Interval, f.cfg.Interval) {
		f.cfg.Logger.Info("fleet: poll interval raised to the cycle timeout", "server", t.ID, "interval", p.interval)
	}
	return p
}

// Run polls every server (one goroutine each) until ctx ends, then stops every poller
// and closes the drivers.
func (f *Fleet) Run(ctx context.Context) {
	f.mu.Lock()
	f.runCtx = ctx
	for _, p := range f.roster.Load().order {
		p.start(ctx)
	}
	f.mu.Unlock()
	<-ctx.Done()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stopped = true
	f.retire(f.roster.Load().order)
}

// Apply replaces the server set (settings slice S3: hot add, edit, disable, remove).
// It takes ownership of every driver passed: each is either polled or closed.
// Targets are matched by ID and Fingerprint: an unchanged server keeps its poller and
// state (only its name and tags are updated, and the new, unused driver is closed); a
// changed or removed one has its poller stopped and its driver closed (BMC session
// deleted) before anything new starts; an added one starts polling at once. An empty
// Fingerprint always counts as changed. Readers switch to the new roster atomically.
func (f *Fleet) Apply(targets []Target) error {
	if err := validateTargets(targets); err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopped {
		closeAll(f.cfg, targetDrivers(targets))
		return ErrStopped
	}
	old := f.roster.Load()
	next := make([]*poller, 0, len(targets))
	keep := map[*poller]bool{}
	var unused []bmc.Driver
	for _, t := range targets {
		if p, ok := old.byID[t.ID]; ok && t.Fingerprint != "" && p.target.Fingerprint == t.Fingerprint {
			p.setMeta(t.Name, t.Tags)
			keep[p] = true
			next = append(next, p)
			unused = append(unused, t.Driver)
			continue
		}
		next = append(next, f.newPoller(t))
	}
	var gone []*poller
	now := f.cfg.Clock.Now()
	for _, p := range old.order {
		if !keep[p] {
			gone = append(gone, p)
		}
	}
	f.retire(gone)
	closeAll(f.cfg, unused)
	f.roster.Store(newRoster(next))
	// A rebuilt server is another BMC: its restart window ends. After the roster swap, so
	// an ExpectRestart racing this Apply either sees the new roster or is dropped here.
	for _, p := range gone {
		p.dropRestart(now)
	}
	if f.runCtx != nil {
		for _, p := range next {
			if !keep[p] {
				p.start(f.runCtx)
			}
		}
	}
	return nil
}

func targetDrivers(ts []Target) []bmc.Driver {
	out := make([]bmc.Driver, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Driver)
	}
	return out
}

// retire stops pollers (cancel, wait) and then releases their BMC-side state.
func (f *Fleet) retire(ps []*poller) {
	for _, p := range ps {
		p.stop()
	}
	ds := make([]bmc.Driver, 0, len(ps))
	for _, p := range ps {
		ds = append(ds, p.target.Driver)
	}
	closeAll(f.cfg, ds)
}

// Closer is implemented by drivers that hold state on the BMC (a Redfish session).
type Closer interface {
	Close(ctx context.Context) error
}

// closeAll releases BMC-side state in parallel, bounded by closeTimeout.
func closeAll(cfg Config, ds []bmc.Driver) {
	ctx, cancel := context.WithTimeout(context.Background(), closeTimeout)
	defer cancel()
	var wg sync.WaitGroup
	for _, d := range ds {
		c, ok := d.(Closer)
		if !ok {
			continue
		}
		wg.Go(func() {
			if err := c.Close(ctx); err != nil {
				cfg.Logger.Warn("fleet: close driver failed", "class", string(bmc.Classify(err)))
			}
		})
	}
	wg.Wait()
}

// Servers implements Reader.
func (f *Fleet) Servers() []ServerState {
	now := f.cfg.Clock.Now()
	r := f.roster.Load()
	out := make([]ServerState, 0, len(r.order))
	for _, p := range r.order {
		out = append(out, p.view(now))
	}
	return out
}

// Server implements Reader.
func (f *Fleet) Server(id string) (ServerState, bool) {
	p, ok := f.roster.Load().byID[id]
	if !ok {
		return ServerState{}, false
	}
	return p.view(f.cfg.Clock.Now()), true
}

// ObservePower publishes a verified power transition of server id at once (audit
// R2-08), so every reader shows one state until the next poll: the snapshot's power
// state becomes o.State as of o.At, PowerSince moves when the state changed, and
// PowerCause records the action. It is ignored (false) for an unknown server, a server
// without a snapshot, or an observation older than the power state already published.
func (f *Fleet) ObservePower(id string, o PowerObservation) bool {
	p, ok := f.roster.Load().byID[id]
	if !ok {
		return false
	}
	return p.observePower(o)
}

// Polled implements Reader. A fleet with no servers has nothing to wait for.
func (f *Fleet) Polled() bool {
	r := f.roster.Load()
	if len(r.order) == 0 {
		return true
	}
	for _, p := range r.order {
		if p.state.Load().HasSnapshot {
			return true
		}
	}
	return false
}

// Errors of RequestPosture.
var (
	ErrUnknownServer = errors.New("fleet: unknown server")
	ErrNoPosture     = errors.New("fleet: this server has no security checks")
	ErrPaused        = errors.New("fleet: polling is paused (the BMC certificate does not match its pin)")
)

// RequestPosture asks a server's poller to run its security checks now: the poller
// wakes, polls the snapshot and then runs the posture tier. Requests made before the
// tier runs are folded into one. The caller rate-limits (it is a BMC read).
func (f *Fleet) RequestPosture(id string) error {
	p, ok := f.roster.Load().byID[id]
	switch {
	case !ok:
		return ErrUnknownServer
	case p.target.Posture == nil:
		return ErrNoPosture
	case p.state.Load().Paused:
		return ErrPaused
	}
	p.postureReq.Store(true)
	select {
	case p.wake <- struct{}{}:
	default: // a wake-up is already pending
	}
	return nil
}
