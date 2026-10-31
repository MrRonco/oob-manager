package registry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/audit"
	"oob-manager/internal/config"
	"oob-manager/internal/netpolicy"
	"oob-manager/internal/secrets"
	"oob-manager/internal/secrets/credstore"
	"oob-manager/internal/store"
)

// Errors. Messages are safe to show to an admin; none echoes a secret.
var (
	ErrLocked      = errors.New("this server is managed by config.yaml or the Servers section is locked")
	ErrConflict    = errors.New("the server was changed elsewhere; reload the page and try again")
	ErrNotFound    = errors.New("no such server")
	ErrExists      = errors.New("a server with this id already exists (in config.yaml or here)")
	ErrInvalid     = errors.New("invalid server settings")
	ErrLeaseActive = errors.New("a fan lease is active on this server; end it before changing its fans or address")
	ErrNoCred      = errors.New("the credential is not stored or cannot be opened")
)

// Audit actions written by this package.
const (
	ActionCreate     = "admin.server.create"
	ActionUpdate     = "admin.server.update"
	ActionPin        = "admin.server.pin"
	ActionCredential = "admin.server.credential" //nolint:gosec // G101: an audit action name
	ActionEnable     = "admin.server.enable"
	ActionDisable    = "admin.server.disable"
	ActionDelete     = "admin.server.delete"
	ActionImport     = "admin.server.import"
	ActionShadowed   = "settings.shadowed"
)

// Recorder writes audit rows; *audit.Logger implements it.
type Recorder interface {
	Record(ctx context.Context, e audit.Entry) (store.AuditRecord, error)
	RecordTx(ctx context.Context, tx *store.Tx, e audit.Entry) (store.AuditRecord, error)
}

// Config wires a Service. DB, Audit and Creds are required.
type Config struct {
	DB    *store.DB
	Audit Recorder
	File  config.Config
	// Creds seals and opens browser-saved credentials (secrets.PurposeBMCCred).
	Creds *credstore.Store
	// Self lists the app's own addresses, never accepted as a BMC.
	Self []netip.Addr
	// LeaseActive reports an active fan lease on a server: fan and address changes are
	// refused while one is (nil: never).
	LeaseActive func(ctx context.Context, serverID string) (bool, error)
	Now         func() time.Time
	Logger      *slog.Logger
}

// Service reads and changes the registry. Readers call Current per use; every change
// publishes a new Effective and signals Changes.
type Service struct {
	cfg     Config
	policy  netpolicy.Policy
	cur     atomic.Pointer[Effective]
	changed chan struct{}
}

// New loads the registry, logs its warnings and audits every shadowed row once.
func New(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.DB == nil || cfg.Audit == nil || cfg.Creds == nil {
		return nil, errors.New("registry: DB, Audit and Creds are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.LeaseActive == nil {
		cfg.LeaseActive = func(context.Context, string) (bool, error) { return false, nil }
	}
	s := &Service{cfg: cfg, policy: netpolicy.Policy{Networks: cfg.File.BMCNetworks(), Deny: cfg.Self},
		changed: make(chan struct{}, 1)}
	e, err := s.load(ctx, cfg.DB.Servers(), cfg.DB.Credentials())
	if err != nil {
		return nil, err
	}
	s.cur.Store(&e)
	for _, w := range e.Warnings {
		cfg.Logger.Warn("servers: " + w)
	}
	s.auditShadowed(ctx, e)
	return s, nil
}

func (s *Service) auditShadowed(ctx context.Context, e Effective) {
	for _, x := range e.entries {
		if !x.Shadowed {
			continue
		}
		_, err := s.cfg.Audit.Record(ctx, audit.Entry{Principal: "system", AuthMethod: "system", ServerID: x.Server.ID,
			Action: ActionShadowed, Result: audit.ResultOK,
			Params: map[string]any{"target": "server:" + x.Server.ID, "source": "config.yaml"}})
		if err != nil {
			s.cfg.Logger.Error("servers: audit shadowed row", "server", x.Server.ID, "err", err)
		}
	}
}

func (s *Service) load(ctx context.Context, rows store.ServerRepository, creds store.CredentialRepository) (Effective, error) {
	rs, err := rows.All(ctx)
	if err != nil {
		return Effective{}, err
	}
	cs, err := creds.All(ctx)
	if err != nil {
		return Effective{}, err
	}
	return Resolve(s.cfg.File, rs, cs, s.policy), nil
}

// Current returns the published registry.
func (s *Service) Current() Effective { return *s.cur.Load() }

// Changes signals (coalesced) that Current changed.
func (s *Service) Changes() <-chan struct{} { return s.changed }

// Policy is the BMC address policy in force (settings.bmc_networks and the app's own
// addresses).
func (s *Service) Policy() netpolicy.Policy { return s.policy }

func (s *Service) publish(e Effective) {
	s.cur.Store(&e)
	select {
	case s.changed <- struct{}{}:
	default:
	}
}

// Credential opens a stored credential of a database server, bound to the row's
// current kind, address and port. It is called when drivers are built.
func (s *Service) Credential(ctx context.Context, id string, slot credstore.Slot) (secrets.Credential, error) {
	row, err := s.cfg.DB.Servers().Get(ctx, id)
	if err != nil {
		return secrets.Credential{}, ErrNoCred
	}
	cs, err := s.cfg.DB.Credentials().List(ctx, id)
	if err != nil {
		return secrets.Credential{}, err
	}
	for _, c := range cs {
		if c.Slot != string(slot) {
			continue
		}
		cred, oerr := s.cfg.Creds.Open(binding(row, slot, c.Version), c.SecretEnc)
		if oerr != nil {
			return secrets.Credential{}, fmt.Errorf("%w: %s %s", ErrNoCred, id, slot)
		}
		return cred, nil
	}
	return secrets.Credential{}, ErrNoCred
}

func binding(r store.ServerRow, slot credstore.Slot, version int) credstore.Binding {
	return credstore.Binding{ServerID: r.ID, Slot: slot, Kind: r.Kind, Address: r.Address, Port: r.Port, Version: version}
}

// deny audits a refused change (locked, conflict, lease) outside any transaction.
func (s *Service) deny(ctx context.Context, a admin.Actor, action, id string, err error) {
	class := ""
	switch {
	case errors.Is(err, ErrLocked):
		class = "locked"
	case errors.Is(err, ErrConflict):
		class = "conflict"
	case errors.Is(err, ErrLeaseActive):
		class = "lease_active"
	case errors.Is(err, ErrExists):
		class = "exists"
	default:
		return
	}
	e := entry(a, action, id, map[string]any{"target": "server:" + id})
	e.Result, e.ErrorClass = audit.ResultDenied, class
	if _, rerr := s.cfg.Audit.Record(ctx, e); rerr != nil {
		s.cfg.Logger.Error("servers: denial audit failed", "err", rerr)
	}
}

func entry(a admin.Actor, action, id string, p map[string]any) audit.Entry {
	return audit.Entry{Principal: a.Username, AuthMethod: a.Method, Role: string(a.Role), SrcIP: a.IP,
		ServerID: id, Action: action, Params: p, Result: audit.ResultOK}
}

// invalid wraps validation problems into ErrInvalid (at most three, for the form).
func invalid(problems []string) error {
	if len(problems) > 3 {
		problems = append(problems[:3:3], fmt.Sprintf("and %d more", len(problems)-3))
	}
	return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
}
