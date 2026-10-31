package api

import (
	"context"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"oob-manager/internal/authz"
	"oob-manager/internal/web"
)

const bearerChallenge = `Bearer realm="oob-manager"` // #nosec G101 -- an auth challenge, not a credential

// protected authenticates the bearer token, authorizes action for its principal and
// rate-limits per token before calling h. The method check runs first.
func (a *API) protected(action authz.Action, h http.HandlerFunc) http.Handler {
	return getOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r)
		if !ok {
			unauthorized(w, r)
			return
		}
		tok, p, err := a.deps.Tokens.Verify(r.Context(), raw)
		if err != nil {
			a.deps.Logger.Info("api: token rejected", "path", r.URL.Path)
			unauthorized(w, r)
			return
		}
		if err := authz.Authorize(p, action, false); err != nil {
			web.WriteProblem(w, r, http.StatusForbidden, "this token may not perform that action")
			return
		}
		if wait, ok := a.limiter.allow(tok.ID); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
			web.WriteProblem(w, r, http.StatusTooManyRequests, "token rate limit exceeded")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), tokenKey{}, tok.ID)))
	}))
}

// bearerToken reads "Authorization: Bearer <token>". Query parameters are never
// consulted, so tokens do not end up in access logs or browser history.
func bearerToken(r *http.Request) (string, bool) {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	tok = strings.TrimSpace(tok)
	return tok, tok != ""
}

func unauthorized(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("WWW-Authenticate", bearerChallenge)
	web.WriteProblem(w, r, http.StatusUnauthorized, "a valid API bearer token is required")
}

// limiter is a token bucket per API token ID (capacity = rate per minute).
type limiter struct {
	perMinute float64
	now       func() time.Time

	mu      sync.Mutex
	buckets map[string]bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newLimiter(perMinute int, now func() time.Time) *limiter {
	return &limiter{perMinute: float64(perMinute), now: now, buckets: map[string]bucket{}}
}

// allow takes one token for id, or reports how long until one is available.
func (l *limiter) allow(id string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[id]
	if !ok {
		b = bucket{tokens: l.perMinute, at: now}
	}
	refill := now.Sub(b.at).Minutes() * l.perMinute
	b = bucket{tokens: math.Min(l.perMinute, b.tokens+math.Max(refill, 0)), at: now}
	if b.tokens < 1 {
		l.buckets[id] = b
		return time.Duration((1 - b.tokens) / l.perMinute * float64(time.Minute)), false
	}
	l.buckets[id] = bucket{tokens: b.tokens - 1, at: now}
	return 0, true
}
