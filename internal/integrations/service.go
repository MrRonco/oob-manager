// Package integrations runs the audit stream's off-box copy (Settings → Integrations,
// tech_doc §34): it builds the GELF shipper from the effective settings, swaps it into
// the audit logger's switch sink without a restart, applies the destination policy to
// every address (security.md T10), fetches a log server's certificate for pinning,
// sends a test frame and reports the shipper's live state. It never contacts a BMC.
package integrations

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/settings"
	"oob-manager/internal/store"
	"oob-manager/internal/tlspin"
)

// Audit actions written by this package (settings writes update, reset and pin).
const (
	ActionApplied     = "admin.integrations.applied"
	ActionFingerprint = "admin.integrations.gelf.fingerprint"
	ActionTest        = "admin.integrations.gelf.test"
)

// Settings is the runtime settings service (*settings.Service).
type Settings interface {
	Current() settings.Effective
	UpdateIntegrations(ctx context.Context, a admin.Actor, rev int64, form map[string]string, pin settings.PinOrigin) ([]settings.Change, error)
	ResetIntegrations(ctx context.Context, a admin.Actor, rev int64, key string) ([]settings.Change, error)
}

// Recorder writes audit rows (*audit.Logger).
type Recorder interface {
	Record(ctx context.Context, e audit.Entry) (store.AuditRecord, error)
}

// Config wires a Service. Settings, Audit and Switch are required.
type Config struct {
	Settings Settings
	Audit    Recorder
	// Switch is the audit logger's GELF sink; the service installs shippers into it.
	Switch *audit.SwitchSink
	Policy Policy
	// Dial (nil: net.Dialer) opens the checked "ip:port"; tests point it at receivers.
	Dial DialFunc
	// Tuning holds file-only shipper settings (queue, timeouts); Address, Dial, TLS and
	// the callbacks are set by the service.
	Tuning audit.ShipperConfig
	// OnTrust reports the certificate check: a mismatch or an expired certificate, its
	// resolution, or its withdrawal when the target changed. cmd turns it into a trust
	// notification. Called on a shipper or request goroutine, a withdrawal while the
	// service's state lock is held: must not block or call back into the Service.
	OnTrust func(TrustChange)
	// PreviousTimeout bounds how long Apply waits for the previous destination to receive
	// what is queued for it (default DefaultPreviousTimeout).
	PreviousTimeout time.Duration
	Logger          *slog.Logger
	Now             func() time.Time
}

// running is one started shipper.
type running struct {
	sh     *audit.Shipper
	cancel context.CancelFunc
	done   chan struct{}
}

// Service owns the GELF shipper. Apply calls are serialised by applyMu (held across the
// wait for the previous destination); mu guards the shipper state only briefly, so page
// renders and shutdown never wait behind an Apply. Readers are lock-free.
type Service struct {
	cfg Config

	applyMu  sync.Mutex
	mu       sync.Mutex
	runCtx   context.Context // set by Run; nil until then
	finished bool            // Run has returned: Apply does nothing
	cur      *running        // nil when shipping is disabled
	applied  atomic.Pointer[config.GELF]
	stopped  sync.WaitGroup

	state     atomic.Pointer[shipState] // what Stats reads (counters.go)
	gen       atomic.Uint64             // the current shipper's generation (bumped by install)
	trustOpen atomic.Bool               // a reported pin mismatch is unresolved
}

// New builds the shipper for the settings in force and installs it in the switch (rows
// recorded before Run are queued, as before). Nothing is dialled until Run.
func New(cfg Config) (*Service, error) {
	if cfg.Settings == nil || cfg.Audit == nil || cfg.Switch == nil {
		return nil, errors.New("integrations: Settings, Audit and Switch are required")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.PreviousTimeout <= 0 {
		cfg.PreviousTimeout = DefaultPreviousTimeout
	}
	s := &Service{cfg: cfg}
	g := cfg.Settings.Current().Integrations
	if err := s.install(g, nil); err != nil {
		return nil, err
	}
	return s, nil
}

// Run starts the installed shipper, then waits for ctx; on return every shipper has
// flushed (bounded by its flush timeout) and closed.
func (s *Service) Run(ctx context.Context) {
	s.mu.Lock()
	s.runCtx = context.WithoutCancel(ctx)
	if s.cur != nil {
		s.start(s.cur)
	}
	s.mu.Unlock()
	<-ctx.Done()
	s.mu.Lock()
	if s.cur != nil {
		s.stop(s.cur)
	}
	s.runCtx, s.finished = nil, true
	s.mu.Unlock()
	s.stopped.Wait()
}

// Flush waits until the running shipper has written every row queued so far, or ctx
// ends; it reports whether all of them were written (true when shipping is off). The CLI
// commands call it before they exit, so their audit rows leave the box (plan 06 §3.6).
func (s *Service) Flush(ctx context.Context) bool {
	s.mu.Lock()
	cur := s.cur
	s.mu.Unlock()
	if cur == nil || cur.sh == nil {
		return true
	}
	return cur.sh.WaitSent(ctx)
}

// DefaultPreviousTimeout bounds how long Apply waits for the previous destination to
// receive the rows queued for it (among them the one recording this change).
const DefaultPreviousTimeout = 2 * time.Second

// Apply makes the target in force in the settings the running one (read under the
// lock, so overlapping saves always end with the newest). Before the swap it waits up
// to Config.PreviousTimeout until the current shipper has written what is queued: the
// admin.integrations.update row the change just committed reaches the previous
// destination first, and the applied row says whether it did (previous_confirmed).
// Then a new shipper is built, started and swapped in, and the old one flushes and
// closes in the background. admin.integrations.applied (principal system) is recorded
// after the swap, so it travels to the new destination. An unchanged target, or a call
// after Run returned, does nothing.
func (s *Service) Apply(ctx context.Context) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	g := s.cfg.Settings.Current().Integrations
	s.mu.Lock()
	old, done := s.cur, s.finished
	s.mu.Unlock()
	if done || g == s.Applied() {
		return
	}
	prev := s.confirmPrevious(ctx, old) // without mu: renders and shutdown go on
	s.mu.Lock()
	if s.finished { // Run returned while we waited
		s.mu.Unlock()
		return
	}
	var retire *audit.Shipper
	if old != nil {
		retire = old.sh
	}
	err := s.install(g, retire) // one store: the old shipper keeps counting as retired
	if err == nil && old != nil {
		s.stop(old)
	}
	s.mu.Unlock()
	s.recordApplied(ctx, g, prev, err)
}

// previous is what Apply learned about the old destination (nil: there was none running).
type previous struct {
	confirmed bool
	queued    int
}

func (s *Service) confirmPrevious(ctx context.Context, old *running) *previous {
	if old == nil || old.cancel == nil {
		return nil
	}
	wctx, cancel := context.WithTimeout(ctx, s.cfg.PreviousTimeout)
	defer cancel()
	ok := old.sh.WaitSent(wctx)
	return &previous{confirmed: ok, queued: old.sh.Stats().Queued}
}

// install builds the shipper for g (none when disabled), swaps it into the switch and
// starts it when Run is active. The caller holds mu (or is New). A new generation
// starts: callbacks of older shippers are ignored. When shipping is disabled or moves
// to another address, an open certificate alert is withdrawn here, after the old
// shipper's callbacks stopped counting and before the new one can report: a mismatch
// the old shipper raised while Apply waited for it is closed too, and a later good
// connection of the new target reports no recovery.
func (s *Service) install(g config.GELF, retire *audit.Shipper) error {
	var next *running
	gen := s.gen.Load() + 1
	if g.Enabled {
		sh, err := s.build(g, gen)
		if err != nil {
			return err
		}
		next = &running{sh: sh}
	}
	prev := s.Applied()
	s.gen.Store(gen)
	if (!g.Enabled || g.Address != prev.Address) && s.trustOpen.Swap(false) {
		s.trust(TrustWithdrawn) // the alert was about a destination no longer used
	}
	s.cur = next
	s.applied.Store(&g)
	if next == nil {
		s.cfg.Switch.Swap(nil)
		s.publish(nil, retire)
		return nil
	}
	s.cfg.Switch.Swap(next.sh)
	s.publish(next.sh, retire)
	if s.runCtx != nil {
		s.start(next)
	}
	return nil
}

func (s *Service) build(g config.GELF, gen uint64) (*audit.Shipper, error) {
	sc := s.cfg.Tuning
	sc.Address = g.Address
	sc.Dial = s.cfg.Policy.Dialer(s.cfg.Dial)
	sc.OnPinMismatch = func(class string) { s.pinMismatch(gen, class) }
	sc.OnConnected = func() { s.connected(gen) }
	if g.Transport == config.TransportTLS {
		pin, err := tlspin.ParseHex(g.PinSHA256)
		if err != nil {
			return nil, err
		}
		sc.TLS = tlspin.IssuerConfig(pin, verifyName(g), audit.ErrPinMismatch)
		sc.TLS.ServerName = serverName(g)
	}
	return audit.NewShipper(sc, s.cfg.Logger)
}

// serverName is the SNI: the configured name, else the host when it is a DNS name.
func serverName(g config.GELF) string {
	if g.ServerName != "" {
		return g.ServerName
	}
	host, _, err := net.SplitHostPort(g.Address)
	if err != nil {
		return ""
	}
	if _, perr := netip.ParseAddr(host); perr == nil {
		return ""
	}
	return host
}

// verifyName is the name an issuer pin checks the leaf against: the server name, else
// the host of the address (a DNS name or an IP literal).
func verifyName(g config.GELF) string {
	if g.ServerName != "" {
		return g.ServerName
	}
	host, _, err := net.SplitHostPort(g.Address)
	if err != nil {
		return ""
	}
	return host
}

func (s *Service) start(r *running) {
	ctx, cancel := context.WithCancel(s.runCtx)
	r.cancel, r.done = cancel, make(chan struct{})
	go func() { defer close(r.done); r.sh.Run(ctx) }()
}

// Applied is the target the running shipper was built from.
func (s *Service) Applied() config.GELF {
	if g := s.applied.Load(); g != nil {
		return *g
	}
	return config.GELF{}
}

// Locked reports settings.locked listing integrations.
func (s *Service) Locked() bool { return s.cfg.Settings.Current().IntegrationsLocked }

// Networks is audit.gelf.allowed_networks as enforced (for the page).
func (s *Service) Networks() []netip.Prefix {
	return append([]netip.Prefix(nil), s.cfg.Policy.Allowed...)
}
