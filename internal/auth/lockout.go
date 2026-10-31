package auth

import (
	"context"
	"time"
)

// LockoutPolicy is exponential backoff after FreeAttempts consecutive failures:
// delay = BaseDelay × 2^(failures-FreeAttempts), capped at MaxDelay. Failures older than
// ForgetAfter are discarded.
type LockoutPolicy struct {
	FreeAttempts int
	BaseDelay    time.Duration
	MaxDelay     time.Duration
	ForgetAfter  time.Duration
}

// DefaultAccountLockout allows 5 free tries per account, then 30 s doubling to 15 min.
func DefaultAccountLockout() LockoutPolicy {
	return LockoutPolicy{FreeAttempts: 5, BaseDelay: 30 * time.Second, MaxDelay: 15 * time.Minute, ForgetAfter: 24 * time.Hour}
}

// DefaultIPLockout allows 10 free tries per source IP (spraying across usernames), then 10 s
// doubling to 15 min.
func DefaultIPLockout() LockoutPolicy {
	return LockoutPolicy{FreeAttempts: 10, BaseDelay: 10 * time.Second, MaxDelay: 15 * time.Minute, ForgetAfter: 24 * time.Hour}
}

func (p LockoutPolicy) delay(failures int) time.Duration {
	if failures < p.FreeAttempts {
		return 0
	}
	d := p.BaseDelay
	for i := p.FreeAttempts; i < failures; i++ {
		d *= 2
		if d >= p.MaxDelay {
			return p.MaxDelay
		}
	}
	return min(d, p.MaxDelay)
}

func (p LockoutPolicy) stale(s LockoutState, now time.Time) bool {
	return s.Failures > 0 && now.Sub(s.LastFailure) > p.ForgetAfter
}

// retryAfter is how long until the next attempt is allowed (0 = now).
func (p LockoutPolicy) retryAfter(s LockoutState, now time.Time) time.Duration {
	if p.stale(s, now) {
		return 0
	}
	wait := s.LastFailure.Add(p.delay(s.Failures)).Sub(now)
	return max(wait, 0)
}

// lockKey pairs a repository key with the policy that governs it.
type lockKey struct {
	key    string
	policy LockoutPolicy
}

// lockouts applies policies to keys over a LockoutRepo.
type lockouts struct {
	repo LockoutRepo
	now  func() time.Time
}

// check returns a *LockedOutError for the longest wait among keys, or nil.
func (l lockouts) check(ctx context.Context, keys ...lockKey) error {
	var wait time.Duration
	for _, k := range keys {
		st, err := l.repo.Get(ctx, k.key)
		if err != nil {
			return err
		}
		wait = max(wait, k.policy.retryAfter(st, l.now()))
	}
	if wait > 0 {
		return &LockedOutError{RetryAfter: wait}
	}
	return nil
}

// fail records a failure on every key, forgetting stale history first.
func (l lockouts) fail(ctx context.Context, keys ...lockKey) error {
	now := l.now()
	for _, k := range keys {
		st, err := l.repo.Get(ctx, k.key)
		if err != nil {
			return err
		}
		if k.policy.stale(st, now) {
			if err := l.repo.Reset(ctx, k.key); err != nil {
				return err
			}
		}
		if _, err := l.repo.RecordFailure(ctx, k.key, now); err != nil {
			return err
		}
	}
	return nil
}

func (l lockouts) reset(ctx context.Context, keys ...lockKey) error {
	for _, k := range keys {
		if err := l.repo.Reset(ctx, k.key); err != nil {
			return err
		}
	}
	return nil
}
