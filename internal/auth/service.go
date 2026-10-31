package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"oob-manager/internal/authz"
)

// Defaults from docs/tech_doc.md §4 and docs/security.md §3.
const (
	DefaultIssuer       = "oob-manager"
	DefaultSessionIdle  = 30 * time.Minute
	DefaultSessionMax   = 12 * time.Hour
	DefaultStepUpWindow = 5 * time.Minute
	DefaultPendingTTL   = 5 * time.Minute // password accepted, waiting for TOTP
)

// Config wires an Authenticator. Repos, Hasher and Sealer are required; zero durations
// and policies take the defaults above.
type Config struct {
	Users    UserRepo
	Sessions SessionRepo
	Lockouts LockoutRepo
	Hasher   *PasswordHasher
	Sealer   Sealer
	Now      func() time.Time
	Logger   *slog.Logger
	Issuer   string // TOTP issuer shown in authenticator apps

	SessionIdle    time.Duration
	SessionMax     time.Duration
	StepUpWindow   time.Duration
	PendingTTL     time.Duration
	AccountLockout LockoutPolicy
	IPLockout      LockoutPolicy
	// Policy, when set, is read on every use instead of the three static durations
	// above, so Settings → General changes apply without a restart. It must return
	// validated values (config.ValidateGeneral).
	Policy func() Policy
	// OnFailure, when set, hears each failed sign-in stage ("password" or "totp") for
	// the /metrics counter. It must not block.
	OnFailure func(stage string)
}

// Policy is the session and step-up limits in force.
type Policy struct {
	SessionIdle  time.Duration
	SessionMax   time.Duration
	StepUpWindow time.Duration
}

// policy returns the limits in force now.
func (a *Authenticator) policy() Policy {
	if a.cfg.Policy != nil {
		return a.cfg.Policy()
	}
	return Policy{SessionIdle: a.cfg.SessionIdle, SessionMax: a.cfg.SessionMax, StepUpWindow: a.cfg.StepUpWindow}
}

// Authenticator runs local login, sessions and step-up.
type Authenticator struct {
	cfg    Config
	hasher *PasswordHasher
	sealer Sealer
	locks  lockouts
	log    *slog.Logger
}

// Identity is an authenticated full session.
type Identity struct {
	User    User
	Session Session
}

// Principal is the authz view of the identity.
func (i Identity) Principal() authz.Principal {
	return authz.Principal{Kind: authz.KindSession, Role: i.User.Role}
}

// New validates cfg and returns an Authenticator.
func New(cfg Config) (*Authenticator, error) {
	if cfg.Users == nil || cfg.Sessions == nil || cfg.Lockouts == nil {
		return nil, errors.New("auth: user, session and lockout repos are required")
	}
	if cfg.Hasher == nil || cfg.Sealer == nil {
		return nil, errors.New("auth: hasher and sealer are required")
	}
	cfg = withDefaults(cfg)
	if cfg.SessionIdle > cfg.SessionMax {
		return nil, fmt.Errorf("auth: session idle %s exceeds max %s", cfg.SessionIdle, cfg.SessionMax)
	}
	return &Authenticator{
		cfg: cfg, hasher: cfg.Hasher, sealer: cfg.Sealer, log: cfg.Logger,
		locks: lockouts{repo: cfg.Lockouts, now: cfg.Now},
	}, nil
}

func withDefaults(c Config) Config {
	c.Now = orDefaultFunc(c.Now, time.Now)
	c.Logger = orDefault(c.Logger, slog.Default())
	c.Issuer = orDefault(c.Issuer, DefaultIssuer)
	c.SessionIdle = orDefault(c.SessionIdle, DefaultSessionIdle)
	c.SessionMax = orDefault(c.SessionMax, DefaultSessionMax)
	c.StepUpWindow = orDefault(c.StepUpWindow, DefaultStepUpWindow)
	c.PendingTTL = orDefault(c.PendingTTL, DefaultPendingTTL)
	if c.AccountLockout.FreeAttempts == 0 {
		c.AccountLockout = DefaultAccountLockout()
	}
	if c.IPLockout.FreeAttempts == 0 {
		c.IPLockout = DefaultIPLockout()
	}
	return c
}

func orDefault[T comparable](v, def T) T {
	var zero T
	if v == zero {
		return def
	}
	return v
}

// orDefaultFunc is orDefault for clocks (func values are not comparable).
func orDefaultFunc(v, def func() time.Time) func() time.Time {
	if v == nil {
		return def
	}
	return v
}

// StepUpFresh reports whether s completed a TOTP within the step-up window.
func (a *Authenticator) StepUpFresh(s Session) bool {
	return !s.StepUpAt.IsZero() && a.cfg.Now().Sub(s.StepUpAt) <= a.policy().StepUpWindow
}

// SessionCookieFor returns the cookie for token, expiring with the session's absolute
// lifetime.
func (a *Authenticator) SessionCookieFor(token string, s Session) *http.Cookie {
	left := s.CreatedAt.Add(a.policy().SessionMax).Sub(a.cfg.Now())
	return SessionCookie(token, max(left, 0))
}

func (a *Authenticator) accountKey(username string) lockKey {
	return lockKey{key: "acct:" + username, policy: a.cfg.AccountLockout}
}

func (a *Authenticator) ipKey(ip string) lockKey {
	return lockKey{key: "ip:" + ip, policy: a.cfg.IPLockout}
}

// fail records a failed attempt and returns ErrInvalidCredentials (joined with any
// repository error, which must still deny).
func (a *Authenticator) fail(ctx context.Context, stage, ip string, keys ...lockKey) error {
	a.log.Warn("auth failure", "stage", stage, "ip", ip)
	if a.cfg.OnFailure != nil {
		a.cfg.OnFailure(stage)
	}
	if err := a.locks.fail(ctx, keys...); err != nil {
		return errors.Join(ErrInvalidCredentials, err)
	}
	return ErrInvalidCredentials
}
