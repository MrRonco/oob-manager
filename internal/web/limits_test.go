package web

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestBodyLimit(t *testing.T) {
	h := BodyLimit(8)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			var mbe *http.MaxBytesError
			if !errors.As(err, &mbe) {
				t.Errorf("err = %v, want MaxBytesError", err)
			}
			WriteProblem(w, r, http.StatusRequestEntityTooLarge, "")
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	cases := []struct {
		body string
		want int
	}{{"12345678", 200}, {"123456789", 413}}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader(tc.body)))
		if rec.Code != tc.want {
			t.Errorf("body %d bytes: status %d, want %d", len(tc.body), rec.Code, tc.want)
		}
	}
}

func TestBodyLimitRejectsDeclaredOversize(t *testing.T) {
	called := false
	h := BodyLimit(8)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/", strings.NewReader("123456789"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if called || rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("called=%v status=%d, want handler skipped and 413", called, rec.Code)
	}
}

func TestRequestTimeoutSetsDeadline(t *testing.T) {
	h := RequestTimeout(50 * time.Millisecond)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dl, ok := r.Context().Deadline()
		if !ok || time.Until(dl) > 50*time.Millisecond {
			t.Errorf("deadline = %v, %v", dl, ok)
		}
		<-r.Context().Done()
		if !errors.Is(r.Context().Err(), context.DeadlineExceeded) {
			t.Errorf("ctx err = %v", r.Context().Err())
		}
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil))
}
