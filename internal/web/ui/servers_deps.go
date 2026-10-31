package ui

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"oob-manager/internal/admin"
	"oob-manager/internal/config"
	"oob-manager/internal/netpolicy"
	"oob-manager/internal/registry"
	"oob-manager/internal/secrets/credstore"
	"oob-manager/internal/tofu"
)

// ServerAdmin is the server registry service (*registry.Service, slice S3). Every
// change it makes is audited in the same transaction; the UI authorizes and
// step-up-checks first.
type ServerAdmin interface {
	Current() registry.Effective
	Policy() netpolicy.Policy
	Create(ctx context.Context, a admin.Actor, d registry.Draft) (registry.Entry, error)
	UpdateIdentity(ctx context.Context, a admin.Actor, id string, rev int64, name string, tags []string) ([]registry.Change, error)
	UpdateConnection(ctx context.Context, a admin.Actor, id string, rev int64, c registry.Connection) ([]registry.Change, error)
	UpdateFeatures(ctx context.Context, a admin.Actor, id string, rev int64, f registry.Features) ([]registry.Change, error)
	SetPin(ctx context.Context, a admin.Actor, id string, rev int64, kind, value, via string) ([]registry.Change, error)
	SetCredential(ctx context.Context, a admin.Actor, id string, rev int64, slot credstore.Slot, username, password string) ([]registry.Change, error)
	SetEnabled(ctx context.Context, a admin.Actor, id string, rev int64, on bool) ([]registry.Change, error)
	Delete(ctx context.Context, a admin.Actor, id string, rev int64) error
}

// ErrTestRunning is returned by ServerProber.StartTest while a test of that server runs.
var ErrTestRunning = errors.New("a connection test of this server is already running")

// ServerProber reaches BMCs for Settings → Servers: handshake-only fingerprint fetches
// (internal/tofu) and the read-only "Test connection".
type ServerProber interface {
	FetchTLS(ctx context.Context, addr netip.AddrPort, rsaKex bool) (tofu.CertInfo, error)
	FetchSSH(ctx context.Context, addr netip.AddrPort, legacy bool) (tofu.HostKey, error)
	// StartTest runs the test of server id in the background (it can take a minute on
	// a slow BMC); by is who asked, for the audit row.
	StartTest(id, by string) error
	LastTest(id string) (ServerTest, bool)
}

// ProofSigner signs and checks fingerprint proofs (*tofu.Prover).
type ProofSigner interface {
	Sign(c tofu.Claim) string
	Verify(c tofu.Claim, proof string) error
}

// ServerTest is the outcome of a Test connection. Nothing in it is a secret.
type ServerTest struct {
	Running    bool
	By         string
	StartedAt  time.Time
	FinishedAt time.Time
	OK         bool
	// Kind is the BMC kind the answers suggest ("" when unknown).
	Kind  config.BMCKind
	Steps []TestStep
}

// TestStep is one check of a test: what was read and what it said.
type TestStep struct {
	Name   string
	OK     bool
	Detail string
}
