package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
)

// Problem is an RFC 9457 Problem Details body. Detail must be safe to show a user: never
// put internal errors, BMC responses or secrets in it (security.md I4).
type Problem struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// ProblemContentType is the RFC 9457 media type.
const ProblemContentType = "application/problem+json"

// WriteProblem writes a Problem Details response. Instance is the request path without
// the query string, so tokens or tickets in a query never echo back.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, detail string) {
	title := http.StatusText(status)
	if title == "" {
		title = "Error"
	}
	p := Problem{Type: "about:blank", Title: title, Status: status, Detail: detail, Instance: r.URL.Path}
	w.Header().Set("Content-Type", ProblemContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	// The only failure is a broken client connection; nothing useful to do about it.
	_ = json.NewEncoder(w).Encode(p)
}

// Recover turns a handler panic into a generic 500. The panic value is logged server-side
// only. http.ErrAbortHandler is re-raised so net/http can abort the response as designed.
func Recover(logger *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				v := recover()
				if v == nil {
					return
				}
				if v == http.ErrAbortHandler {
					panic(v)
				}
				logger.Error("handler panic", "method", r.Method, "path", LogPath(r.URL.Path), "panic", v)
				WriteProblem(w, r, http.StatusInternalServerError, "")
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// LogPath is a request path safe to log: the secret part of a one-time enrolment link
// (/enroll/<token>) is replaced, so a link can never end up in the app log.
func LogPath(p string) string {
	const enrol = "/enroll/"
	if strings.HasPrefix(p, enrol) && len(p) > len(enrol) {
		return enrol + "[redacted]"
	}
	return p
}
