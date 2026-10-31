package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"runtime"
	"runtime/debug"
	"sort"
	"sync"
	"time"
)

// Readiness values. Kuma matches on the body keyword, so none contains another.
const (
	StatusOK          = "ok"
	StatusDegraded    = "degraded"
	StatusUnavailable = "unavailable"
)

type statusJSON struct {
	Status string `json:"status"`
}

func (a *API) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, statusJSON{Status: StatusOK})
}

// /readyz is unauthenticated, so a flood must not hold the single database connection
// (security.md D1): the answer is cached for readyCacheFor, so the database is pinged at
// most about once a second whatever the request rate. There is deliberately no per-address
// 429: monitors on the same host can share one source address, and Kuma reads 429 as down.
const readyCacheFor = time.Second

// readyCache is the last /readyz answer and when it was computed.
type readyCache struct {
	mu     sync.Mutex
	at     time.Time
	status string
}

// readyz: unavailable (503) when the database does not answer or no BMC has been polled
// yet; degraded (200) when the audit shipper is configured but disconnected or paused on a
// certificate mismatch (actions still succeed and audit rows queue). No details beyond the status word.
func (a *API) readyz(w http.ResponseWriter, r *http.Request) {
	status := a.cachedReadiness(r.Context())
	code := http.StatusOK
	if status == StatusUnavailable {
		code = http.StatusServiceUnavailable
	}
	writeJSON(w, code, statusJSON{Status: status})
}

// cachedReadiness answers from the cache while it is younger than readyCacheFor. The
// lock is held while computing, so concurrent requests wait for one ping instead of each
// pinging. The shared answer is computed without the first caller's cancellation (still
// bounded by readyTimeout), so a client that hangs up cannot cache "unavailable" for
// everyone, and it is stamped when it is ready, so a slow ping does not hand the waiters
// an answer that has already expired.
func (a *API) cachedReadiness(ctx context.Context) string {
	a.readyAnswer.mu.Lock()
	defer a.readyAnswer.mu.Unlock()
	now := a.deps.Now()
	if a.readyAnswer.status != "" && now.Sub(a.readyAnswer.at) < readyCacheFor && !now.Before(a.readyAnswer.at) {
		return a.readyAnswer.status
	}
	status, cacheable := a.readiness(context.WithoutCancel(ctx))
	if cacheable {
		a.readyAnswer.status, a.readyAnswer.at = status, a.deps.Now()
	}
	return status
}

// readiness computes the status word. cacheable is false when the ping failed because
// it was cancelled (never the database's fault, so never worth remembering).
func (a *API) readiness(ctx context.Context) (status string, cacheable bool) {
	ctx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	if err := a.deps.DB.Ping(ctx); err != nil {
		a.deps.Logger.Warn("api: readyz database ping failed", "error", err)
		return StatusUnavailable, !errors.Is(err, context.Canceled)
	}
	if !a.deps.Fleet.Polled() {
		return StatusUnavailable, true
	}
	if a.deps.Shipper != nil {
		if st := a.deps.Shipper.Stats(); st.Active && (!st.Connected || st.PinMismatch) {
			return StatusDegraded, true
		}
	}
	return StatusOK, true
}

// BuildInfo is what /api/v1/version reports (for external scanners).
type BuildInfo struct {
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	GoVersion  string `json:"go_version"`
	DepsSHA256 string `json:"deps_sha256"`
}

func readBuild(version string) BuildInfo {
	b := BuildInfo{Version: version, GoVersion: runtime.Version()}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return b
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			b.Commit = s.Value
		}
	}
	b.DepsSHA256 = depsHash(info.Deps)
	return b
}

// depsHash is the SHA-256 of the sorted "path@version" module list.
func depsHash(deps []*debug.Module) string {
	lines := make([]string, 0, len(deps))
	for _, d := range deps {
		lines = append(lines, d.Path+"@"+d.Version)
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		h.Write([]byte(l + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (a *API) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.build)
}
