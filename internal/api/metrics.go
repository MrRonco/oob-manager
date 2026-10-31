package api

import (
	"net/http"
	"net/netip"

	"oob-manager/internal/authz"
	"oob-manager/internal/web"
)

// PathMetrics is the Prometheus scrape endpoint (tech_doc §29).
const PathMetrics = "/metrics"

// metricsRoute serves Deps.Metrics behind, in order: the method check, the
// allow_networks check (before any token is looked at), the bearer token, the
// fleet.view permission and the per-token rate limit. Without Deps.Metrics the path
// answers 404, so a disabled endpoint looks like no endpoint.
func (a *API) metricsRoute() http.Handler {
	if a.deps.Metrics == nil {
		return getOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			web.WriteProblem(w, r, http.StatusNotFound, "metrics are not enabled")
		}))
	}
	inner := a.protected(authz.ViewFleet, a.deps.Metrics.ServeHTTP)
	return getOnly(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !networkAllowed(r.RemoteAddr, a.deps.MetricsNetworks) {
			a.deps.Logger.Info("api: metrics scrape from outside allow_networks refused")
			web.WriteProblem(w, r, http.StatusForbidden, "this address may not scrape metrics")
			return
		}
		inner.ServeHTTP(w, r)
	}))
}

// networkAllowed reports whether remote (an http.Request RemoteAddr, the TCP peer:
// forwarding headers are never trusted) lies in one of nets. No nets allows all.
func networkAllowed(remote string, nets []netip.Prefix) bool {
	if len(nets) == 0 {
		return true
	}
	ap, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	addr := ap.Addr().Unmap()
	for _, n := range nets {
		if n.Contains(addr) {
			return true
		}
	}
	return false
}
