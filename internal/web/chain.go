package web

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// Middleware wraps a handler.
type Middleware func(http.Handler) http.Handler

// Chain applies middlewares so the first one listed runs first (outermost).
func Chain(h http.Handler, mws ...Middleware) http.Handler {
	for i := len(mws) - 1; i >= 0; i-- {
		h = mws[i](h)
	}
	return h
}

// Options configures NewHandler. Zero values select the documented defaults.
type Options struct {
	Logger         *slog.Logger
	HSTS           bool          // send HSTS on TLS requests
	BodyLimit      int64         // default DefaultBodyLimit
	RequestTimeout time.Duration // default DefaultRequestTimeout
	// TrustedOrigins are extra origins (scheme://host[:port]) allowed to make
	// state-changing requests, e.g. the public_url when it differs from the Host header.
	TrustedOrigins []string
}

// NewHandler wraps app in the standard chain:
// Recover → SecurityHeaders → Compress → CrossOriginProtection → BodyLimit → RequestTimeout → app.
// Cross-origin rejections and panics still carry the security headers; text responses
// are gzipped for clients that accept it (Compress).
func NewHandler(app http.Handler, o Options) (http.Handler, error) {
	o = withDefaults(o)
	cop, err := crossOrigin(o.TrustedOrigins)
	if err != nil {
		return nil, err
	}
	return Chain(app,
		Recover(o.Logger),
		SecurityHeaders(o.HSTS),
		Compress(),
		cop,
		BodyLimit(o.BodyLimit),
		RequestTimeout(o.RequestTimeout),
	), nil
}

func withDefaults(o Options) Options {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.BodyLimit <= 0 {
		o.BodyLimit = DefaultBodyLimit
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = DefaultRequestTimeout
	}
	return o
}

// crossOrigin uses net/http's CrossOriginProtection (Sec-Fetch-Site, then Origin vs Host)
// for every non-safe method, and answers rejections with Problem Details. The session
// cookie is also SameSite=Strict; a synchronizer token is added with the form handlers.
func crossOrigin(trusted []string) (Middleware, error) {
	cop := http.NewCrossOriginProtection()
	for _, origin := range trusted {
		if err := cop.AddTrustedOrigin(origin); err != nil {
			return nil, fmt.Errorf("web: trusted origin %q: %w", origin, err)
		}
	}
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		WriteProblem(w, r, http.StatusForbidden, "cross-origin request rejected")
	}))
	return cop.Handler, nil
}
