package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteProblem(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/servers/x?secret=1", nil)
	WriteProblem(rec, req, http.StatusNotFound, "no such server")

	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	want := Problem{Type: "about:blank", Title: "Not Found", Status: 404,
		Detail: "no such server", Instance: "/servers/x"}
	if p != want {
		t.Fatalf("problem = %+v, want %+v", p, want)
	}
}

func TestWriteProblemUnknownStatusTitle(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteProblem(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil), 599, "")
	var p Problem
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if p.Title != "Error" || p.Status != 599 {
		t.Fatalf("problem = %+v", p)
	}
	if strings.Contains(rec.Body.String(), `"detail"`) {
		t.Fatal("empty detail should be omitted")
	}
}

func TestRecoverWritesGeneric500(t *testing.T) {
	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	h := Recover(logger)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("db password=hunter2 leaked")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatal("panic value leaked to client")
	}
	if !strings.Contains(logs.String(), "panic") {
		t.Fatalf("panic not logged: %q", logs.String())
	}
}

func TestRecoverRepanicsAbortHandler(t *testing.T) {
	h := Recover(slog.New(slog.DiscardHandler))(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	defer func() {
		if r := recover(); r != http.ErrAbortHandler {
			t.Fatalf("recovered %v, want ErrAbortHandler", r)
		}
	}()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
}

func TestLogPathRedactsEnrolmentLinks(t *testing.T) {
	cases := map[string]string{"/enroll/abc": "/enroll/[redacted]", "/enroll": "/enroll", "/enroll/": "/enroll/",
		"/servers/x": "/servers/x"}
	for in, want := range cases {
		if got := LogPath(in); got != want {
			t.Errorf("LogPath(%q) = %q, want %q", in, got, want)
		}
	}
}
