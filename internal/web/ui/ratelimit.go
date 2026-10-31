package ui

import (
	"strconv"
	"sync"
	"time"
)

// RateLimit is "Events per Per" as a token bucket: a burst of Events, refilled
// continuously at Events/Per.
type RateLimit struct {
	Events int
	Per    time.Duration
}

func (r RateLimit) valid() bool { return r.Events > 0 && r.Per > 0 }

// bucket is one key's state. Stored by value in the map; replaced, never shared.
type bucket struct {
	tokens float64
	last   time.Time
}

// limiter is an in-memory, per-key token bucket (security.md §3 login limits). It is
// bounded: keys derive from attacker input (IP, typed username), so when maxKeys is
// reached refilled buckets are dropped first, then the least recently used one.
type limiter struct {
	mu sync.Mutex
	// rate is read on every call (a live setting); a change keeps the buckets, so it
	// never grants a fresh allowance.
	rate    func() RateLimit
	maxKeys int
	now     func() time.Time
	m       map[string]bucket
}

func newLimiter(rate RateLimit, maxKeys int, now func() time.Time) *limiter {
	return newLiveLimiter(func() RateLimit { return rate }, maxKeys, now)
}

// newLiveLimiter reads its rate from fn on every call; fn must return a valid rate.
func newLiveLimiter(fn func() RateLimit, maxKeys int, now func() time.Time) *limiter {
	return &limiter{rate: fn, maxKeys: maxKeys, now: now, m: make(map[string]bucket)}
}

// perToken is how long one token takes to refill.
func (r RateLimit) perToken() time.Duration { return r.Per / time.Duration(r.Events) }

func refilled(r RateLimit, b bucket, now time.Time) bucket {
	burst := float64(r.Events)
	elapsed := now.Sub(b.last)
	if elapsed < 0 {
		elapsed = 0
	}
	t := min(burst, b.tokens+elapsed.Seconds()/r.perToken().Seconds())
	return bucket{tokens: t, last: now}
}

// allow takes one token for key. When none is left it returns false and how long until
// the next token.
func (l *limiter) allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now, r := l.now(), l.rate()
	b, ok := l.m[key]
	if !ok {
		l.makeRoom(r, now)
		b = bucket{tokens: float64(r.Events), last: now}
	}
	b = refilled(r, b, now)
	if b.tokens < 1 {
		l.m[key] = b
		wait := time.Duration((1 - b.tokens) * float64(r.perToken()))
		return false, max(wait, time.Second)
	}
	b.tokens--
	l.m[key] = b
	return true, 0
}

// makeRoom keeps the map under maxKeys. Callers hold mu.
func (l *limiter) makeRoom(r RateLimit, now time.Time) {
	if len(l.m) < l.maxKeys {
		return
	}
	for k, b := range l.m {
		if refilled(r, b, now).tokens >= float64(r.Events) {
			delete(l.m, k)
		}
	}
	for len(l.m) >= l.maxKeys {
		l.evictOldest()
	}
}

func (l *limiter) evictOldest() {
	var oldestKey string
	var oldest time.Time
	first := true
	for k, b := range l.m {
		if first || b.last.Before(oldest) {
			oldestKey, oldest, first = k, b.last, false
		}
	}
	delete(l.m, oldestKey)
}

func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.m)
}

// tryAgainIn says how long to wait (UX-14): "Try again in 40 seconds." It reveals only
// the limiter's own window, nothing about an account.
func tryAgainIn(d time.Duration) string {
	secs := int((d + time.Second - 1) / time.Second)
	switch {
	case secs <= 1:
		return "Try again in a second."
	case secs < 120:
		return "Try again in " + strconv.Itoa(secs) + " seconds."
	default:
		return "Try again in " + strconv.Itoa((secs+59)/60) + " minutes."
	}
}
