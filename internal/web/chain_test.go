package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testHandler(t *testing.T) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("POST /servers/{id}/power", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h, err := NewHandler(mux, Options{
		Logger:         slog.New(slog.DiscardHandler),
		TrustedOrigins: []string{"https://oob.lan.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCrossOriginPostRejected(t *testing.T) {
	h := testHandler(t)
	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		{"sec-fetch cross-site", map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		{"foreign origin", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"same-origin fetch", map[string]string{"Sec-Fetch-Site": "same-origin"}, http.StatusNoContent},
		{"trusted origin", map[string]string{"Origin": "https://oob.lan.example"}, http.StatusNoContent},
		{"non-browser client", nil, http.StatusNoContent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://oob.example/servers/r240/power", strings.NewReader("a=1"))
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d", rec.Code, tc.want)
			}
			if tc.want == http.StatusForbidden {
				assertProblem(t, rec, http.StatusForbidden)
				if rec.Header().Get("Content-Security-Policy") == "" {
					t.Error("security headers missing on rejection")
				}
			}
		})
	}
}

func TestCrossOriginGetAllowed(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	rec := httptest.NewRecorder()
	testHandler(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestChainEnforcesBodyLimit(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/servers/r240/power", strings.NewReader(strings.Repeat("a", DefaultBodyLimit+1)))
	rec := httptest.NewRecorder()
	testHandler(t).ServeHTTP(rec, req)
	assertProblem(t, rec, http.StatusRequestEntityTooLarge)
}

func TestNewHandlerRejectsBadOrigin(t *testing.T) {
	_, err := NewHandler(http.NewServeMux(), Options{TrustedOrigins: []string{"not a url"}})
	if err == nil {
		t.Fatal("bad trusted origin accepted")
	}
}

func TestNewHandlerDefaults(t *testing.T) {
	h, err := NewHandler(http.NewServeMux(), Options{})
	if err != nil || h == nil {
		t.Fatalf("NewHandler zero options: %v", err)
	}
}

func TestChainOrder(t *testing.T) {
	var order []string
	mw := func(name string) Middleware {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name)
				next.ServeHTTP(w, r)
			})
		}
	}
	Chain(okHandler(), mw("a"), mw("b"), mw("c")).ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
	if strings.Join(order, "") != "abc" {
		t.Fatalf("order = %v, want a b c", order)
	}
}

func assertProblem(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, want %d", rec.Code, status)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil || p.Status != status {
		t.Fatalf("problem body %q: %v", rec.Body.String(), err)
	}
}
