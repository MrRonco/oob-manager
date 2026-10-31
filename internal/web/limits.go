package web

import (
	"context"
	"net/http"
	"time"
)

// DefaultBodyLimit is the request body cap: no route needs more (security.md D1).
const DefaultBodyLimit = 64 << 10

// DefaultRequestTimeout bounds handler work via the request context. It is kept below
// the server WriteTimeout so handlers can still write their error.
const DefaultRequestTimeout = 25 * time.Second

// BodyLimit caps request bodies at n bytes. A declared Content-Length over the limit is
// rejected before the handler runs; otherwise reads past n fail with *http.MaxBytesError.
func BodyLimit(n int64) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.ContentLength > n {
				WriteProblem(w, r, http.StatusRequestEntityTooLarge, "request body too large")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, n)
			next.ServeHTTP(w, r)
		})
	}
}

// RequestTimeout attaches a deadline to the request context. Handlers and everything
// they call (store, BMC drivers) must honour ctx. http.TimeoutHandler is deliberately not
// used: it buffers responses and would break the console WebSockets added in P4.
func RequestTimeout(d time.Duration) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
