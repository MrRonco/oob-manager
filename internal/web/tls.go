package web

import (
	"crypto/tls"
	"log/slog"
	"net/http"
	"time"
)

// Server timeouts from security.md D1.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second
	maxHeaderBytes    = 16 << 10
)

// TLSConfig returns the UI listener policy: TLS 1.2 minimum, TLS 1.3 preferred, and for
// TLS 1.2 only ECDHE key exchange with AEAD ciphers (TLS 1.3 suites are not configurable
// in Go and are all AEAD). A fresh value is returned on every call. The caller sets
// Certificates or GetCertificate.
func TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256},
		NextProtos:       []string{"h2", "http/1.1"},
	}
}

// NewServer builds the http.Server with the D1 timeouts and TLSConfig() (add the
// certificate before serving). A nil logger uses slog.Default().
func NewServer(addr string, h http.Handler, logger *slog.Logger) *http.Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         TLSConfig(),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
}
