package main

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTLSServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestCheckHealthOK(t *testing.T) {
	srv := newTLSServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Errorf("path = %q, want /healthz", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	})
	if err := checkHealth(context.Background(), srv.URL+"/healthz", time.Second); err != nil {
		t.Fatalf("checkHealth: %v", err)
	}
}

func TestCheckHealthFailures(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"server error": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		},
		"unavailable": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		},
		"redirect is not followed": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.com/healthz", http.StatusFound)
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newTLSServer(t, h)
			if err := checkHealth(context.Background(), srv.URL+"/healthz", time.Second); err == nil {
				t.Fatal("checkHealth: want error, got nil")
			}
		})
	}
}

func TestCheckHealthTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusOK)
	})
	defer close(release)
	start := time.Now()
	err := checkHealth(context.Background(), srv.URL+"/healthz", 100*time.Millisecond)
	if err == nil {
		t.Fatal("checkHealth: want timeout error, got nil")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("timeout not honoured: took %v", elapsed)
	}
}

func TestCheckHealthConnectionRefused(t *testing.T) {
	srv := httptest.NewTLSServer(http.NotFoundHandler())
	url := srv.URL + "/healthz"
	srv.Close()
	if err := checkHealth(context.Background(), url, time.Second); err == nil {
		t.Fatal("checkHealth: want error for closed server, got nil")
	}
}

// The insecure TLS client must never be pointed anywhere but loopback.
func TestCheckHealthRejectsNonLoopback(t *testing.T) {
	bad := []string{
		"https://192.0.2.45:8443/healthz",
		"https://example.com/healthz",
		"http://127.0.0.1:8443/healthz",
		"https://127.0.0.1.example.com/healthz",
		"::not a url",
	}
	for _, u := range bad {
		t.Run(u, func(t *testing.T) {
			err := checkHealth(context.Background(), u, time.Second)
			if err == nil || !strings.Contains(err.Error(), "healthcheck") {
				t.Fatalf("checkHealth(%q) = %v, want refusal", u, err)
			}
		})
	}
}

func TestRunVersion(t *testing.T) {
	var out, errOut strings.Builder
	if code := run([]string{"oob-manager", "version"}, testEnv(&out, &errOut, defaultHealthURL)); code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if !strings.HasPrefix(out.String(), "oob-manager ") {
		t.Fatalf("stdout = %q", out.String())
	}
}

func TestRunHealthcheck(t *testing.T) {
	ok := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	bad := newTLSServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) })

	var out, errOut strings.Builder
	if code := run([]string{"oob-manager", "healthcheck"}, testEnv(&out, &errOut, ok.URL+"/healthz")); code != 0 {
		t.Fatalf("healthy: exit = %d, stderr = %q", code, errOut.String())
	}
	errOut.Reset()
	if code := run([]string{"oob-manager", "healthcheck"}, testEnv(&out, &errOut, bad.URL+"/healthz")); code != 1 {
		t.Fatalf("unhealthy: exit = %d, want 1", code)
	}
	if errOut.Len() == 0 {
		t.Fatal("unhealthy: want a message on stderr")
	}
}

func TestRunUnknown(t *testing.T) {
	var out, errOut strings.Builder
	for _, args := range [][]string{{"oob-manager"}, {"oob-manager", "bogus"}} {
		if code := run(args, testEnv(&out, &errOut, defaultHealthURL)); code != 2 {
			t.Fatalf("run(%v) = %d, want 2", args, code)
		}
	}
}

// testEnv is an env with no terminal, no listener and no drivers.
func testEnv(out, errOut io.Writer, healthURL string) env {
	return env{
		ctx: context.Background(), in: bufio.NewReader(strings.NewReader("")), out: out, errOut: errOut,
		healthURL: healthURL, noEcho: func() (func(), error) { return nil, errNotTerminal },
		listen: net.Listen, newDriver: newBMCDriver,
	}
}
