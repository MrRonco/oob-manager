package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"oob-manager/internal/auth"
	"oob-manager/internal/authz"
)

// countingVerifier wraps fakeVerifier and counts Verify calls.
type countingVerifier struct {
	fakeVerifier
	calls *atomic.Int64
}

func (v countingVerifier) Verify(ctx context.Context, raw string) (auth.APIToken, authz.Principal, error) {
	v.calls.Add(1)
	return v.fakeVerifier.Verify(ctx, raw)
}

const scrapeBody = "oob_server_up{server=\"r730xd\"} 1\n"

func metricsStub() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = w.Write([]byte(scrapeBody))
	})
}

func scrape(t *testing.T, h http.Handler, remote string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, PathMetrics, nil)
	r.RemoteAddr = remote
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestMetricsDisabledIs404(t *testing.T) {
	a := newTestAPI(t, Deps{})
	assertProblem(t, scrape(t, a, "192.0.2.10:5000", map[string]string{"Authorization": "Bearer " + goodToken}),
		http.StatusNotFound)
}

func TestMetricsAuth(t *testing.T) {
	a := newTestAPI(t, Deps{Metrics: metricsStub()})
	w := scrape(t, a, "192.0.2.10:5000", nil)
	assertProblem(t, w, http.StatusUnauthorized)
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("401 without a challenge")
	}
	assertProblem(t, scrape(t, a, "192.0.2.10:5000", map[string]string{"Authorization": "Bearer oobk_wrong"}),
		http.StatusUnauthorized)
	// A browser session (even an admin's) is never accepted: only a bearer token is read.
	assertProblem(t, scrape(t, a, "192.0.2.10:5000", map[string]string{"Cookie": "__Host-oob_session=admin-session"}),
		http.StatusUnauthorized)
	ok := scrape(t, a, "192.0.2.10:5000", map[string]string{"Authorization": "Bearer " + goodToken})
	if ok.Code != http.StatusOK || ok.Body.String() != scrapeBody || !strings.HasPrefix(ok.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("scrape: %d %q", ok.Code, ok.Body.String())
	}
}

func TestMetricsWrongPrincipalIs403(t *testing.T) {
	for _, p := range []authz.Principal{
		{Kind: authz.KindToken, Role: ""},           // a token without a valid role
		{Kind: authz.Kind("other"), Role: "viewer"}, // an unknown principal kind
	} {
		a := newTestAPI(t, Deps{Metrics: metricsStub(), Tokens: fakeVerifier{token: goodToken, p: p}})
		assertProblem(t, scrape(t, a, "192.0.2.10:5000", map[string]string{"Authorization": "Bearer " + goodToken}),
			http.StatusForbidden)
	}
}

func TestMetricsAllowNetworks(t *testing.T) {
	var calls atomic.Int64
	v := countingVerifier{fakeVerifier{token: goodToken, p: authz.Principal{Kind: authz.KindToken, Role: authz.RoleViewer}}, &calls}
	a := newTestAPI(t, Deps{Metrics: metricsStub(), Tokens: v,
		MetricsNetworks: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/28"), netip.MustParsePrefix("2001:db8::1/128")}})
	auth := map[string]string{"Authorization": "Bearer " + goodToken}
	for _, remote := range []string{"192.0.2.10:5000", "[::ffff:192.0.2.3]:80", "[2001:db8::1]:9090"} {
		if w := scrape(t, a, remote, auth); w.Code != http.StatusOK {
			t.Errorf("%s: %d", remote, w.Code)
		}
	}
	before := calls.Load()
	for _, remote := range []string{"192.0.2.200:5000", "[2001:db8::2]:9090", "garbage"} {
		assertProblem(t, scrape(t, a, remote, auth), http.StatusForbidden)
	}
	if calls.Load() != before {
		t.Fatal("a token was verified for an address outside allow_networks")
	}
}

func TestMetricsReadOnlyAndRateLimited(t *testing.T) {
	a := newTestAPI(t, Deps{Metrics: metricsStub(), TokenRatePerMinute: 2})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, PathMetrics, nil)
	r.Header.Set("Authorization", "Bearer "+goodToken)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	assertProblem(t, w, http.StatusMethodNotAllowed)
	auth := map[string]string{"Authorization": "Bearer " + goodToken}
	scrape(t, a, "192.0.2.10:5000", auth)
	scrape(t, a, "192.0.2.10:5000", auth)
	w = scrape(t, a, "192.0.2.10:5000", auth)
	assertProblem(t, w, http.StatusTooManyRequests)
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("429 without Retry-After")
	}
}
