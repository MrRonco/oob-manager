package audit

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// GELF syslog levels used by this app.
const (
	LevelError  = 3
	LevelWarn   = 4
	LevelNotice = 5
	LevelInfo   = 6
	LevelDebug  = 7
)

// DefaultHost is the GELF host field.
const DefaultHost = "oob-manager"

// MaxMessageBytes caps one encoded GELF frame; larger messages are dropped.
const MaxMessageBytes = 32 << 10

// Message is one GELF 1.1 message. Fields are emitted as additional fields with a
// leading underscore; keys are sanitised to GELF's [A-Za-z0-9_.-] and "id" is renamed.
type Message struct {
	Host      string
	Short     string
	Full      string
	Timestamp time.Time
	Level     int
	Fields    map[string]any
}

// encode returns the NUL-terminated GELF/TCP frame.
func (m Message) encode() ([]byte, error) {
	ts := m.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	obj := make(map[string]any, len(m.Fields)+6)
	for k, v := range m.Fields {
		obj["_"+fieldKey(k)] = v
	}
	obj["version"] = "1.1"
	obj["host"] = orDash(m.Host)
	obj["short_message"] = orDash(m.Short)
	obj["timestamp"] = float64(ts.UnixMilli()) / 1000
	obj["level"] = m.Level
	if m.Full != "" {
		obj["full_message"] = m.Full
	}
	b, err := json.Marshal(obj) // JSON escapes NUL, so the terminator is unambiguous
	if err != nil {
		return nil, fmt.Errorf("audit: gelf encode: %w", err)
	}
	return append(b, 0), nil
}

func fieldKey(k string) string {
	if k == "id" {
		return "id_" // _id is reserved by GELF
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '.', r == '-':
			return r
		default:
			return '_'
		}
	}, k)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ShipperConfig configures a Shipper. Zero durations and sizes take defaults.
type ShipperConfig struct {
	Address      string
	QueueSize    int
	DialTimeout  time.Duration
	WriteTimeout time.Duration
	BackoffMin   time.Duration
	BackoffMax   time.Duration
	FlushTimeout time.Duration
	// Dial overrides the TCP dialer: the integrations service passes one that applies
	// the destination policy; tests pass fakes. An error with an ErrorClass method keeps
	// its class (policy).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// TLS, when set, wraps every connection in TLS with this config (tlspin.Config with
	// ErrPinMismatch); nil is plain TCP. Each connection gets a clone.
	TLS *tls.Config
	// PinPause is how long dialling stops after a pin mismatch (default 5 min).
	PinPause time.Duration
	// OnPinMismatch runs once when a mismatch starts; OnRecovered once when a frame is
	// written after one; OnConnected after every successful dial (and handshake). All
	// run on the Run goroutine and must not block.
	OnPinMismatch            func(class string) // ClassTLSPin or ClassTLSExpired
	OnRecovered, OnConnected func()
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// Shipper defaults.
const (
	DefaultQueueSize    = 1024
	DefaultDialTimeout  = 5 * time.Second
	DefaultWriteTimeout = 5 * time.Second
	DefaultBackoffMin   = 1 * time.Second
	DefaultBackoffMax   = 30 * time.Second
	DefaultFlushTimeout = 3 * time.Second
	DefaultPinPause     = 5 * time.Minute
)

func (c ShipperConfig) withDefaults() ShipperConfig {
	c.QueueSize = orInt(c.QueueSize, DefaultQueueSize)
	c.DialTimeout = orDur(c.DialTimeout, DefaultDialTimeout)
	c.WriteTimeout = orDur(c.WriteTimeout, DefaultWriteTimeout)
	c.BackoffMin = orDur(c.BackoffMin, DefaultBackoffMin)
	c.BackoffMax = orDur(c.BackoffMax, DefaultBackoffMax)
	c.FlushTimeout = orDur(c.FlushTimeout, DefaultFlushTimeout)
	c.PinPause = orDur(c.PinPause, DefaultPinPause)
	if c.Now == nil {
		c.Now = time.Now
	}
	if c.Dial == nil {
		var d net.Dialer
		c.Dial = d.DialContext
	}
	return c
}

func (c ShipperConfig) validate() error {
	host, port, err := net.SplitHostPort(c.Address)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("audit: gelf address %q must be host:port", c.Address)
	}
	return nil
}

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func orDur(v, def time.Duration) time.Duration {
	if v <= 0 {
		return def
	}
	return v
}
