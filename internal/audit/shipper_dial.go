package audit

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	"oob-manager/internal/tlspin"
)

// Failure classes of the shipper (Stats.LastError, ShipError). Only the class is ever
// shown or logged with the address, never what the server sent.
const (
	ClassDial    = "dial"    // the TCP connection failed
	ClassTimeout = "timeout" // dial, handshake or write timed out
	ClassTLS     = "tls"     // the TLS handshake failed (not a TLS server, protocol)
	ClassTLSPin  = "tls_pin" // the certificate does not match the pin: shipping paused
	// ClassTLSExpired: under an issuer pin, the right CA and name but a certificate outside
	// its validity period (renew it): shipping paused, nothing suggests an impostor.
	ClassTLSExpired = "tls_expired"
	ClassPolicy     = "policy"   // the destination is not allowed (audit.gelf.allowed_networks)
	ClassWrite      = "write"    // writing the frame failed (connection lost)
	ClassEncode     = "encode"   // the message could not be encoded or is too large
	ClassOff        = "disabled" // no shipper is configured
)

// ErrPinMismatch is the error a pinned TLS config returns (tlspin.Config's mismatch
// argument) so the shipper can tell an impostor from a broken network.
var ErrPinMismatch = errors.New("audit: gelf server certificate does not match the pin")

// ShipError is a classified delivery failure.
type ShipError struct{ Class string }

func (e *ShipError) Error() string { return "audit: gelf delivery failed: " + e.Class }

// ErrorClass reports the class (the interface other packages' dial errors implement).
func (e *ShipError) ErrorClass() string { return e.Class }

// classed is implemented by errors that carry their own class (a refused destination).
type classed interface{ ErrorClass() string }

// ErrorClassOf classifies err: "" for nil, the error's own class when it has one,
// tls_pin for a pin mismatch, timeout, else dial.
func ErrorClassOf(err error) string {
	var c classed
	var ne net.Error
	switch {
	case err == nil:
		return ""
	case errors.As(err, &c):
		return c.ErrorClass()
	case errors.Is(err, ErrPinMismatch):
		return ClassTLSPin
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return ClassTimeout
	default:
		return ClassDial
	}
}

// errPaused is returned while dialling is paused after a pin mismatch or an expired
// certificate (the class is the reason, kept by the shipper).
func (s *Shipper) errPaused() error {
	if c := s.pauseClass.Load(); c != nil {
		return &ShipError{Class: *c}
	}
	return &ShipError{Class: ClassTLSPin}
}

func (s *Shipper) dial(ctx context.Context, probe bool) error {
	if !probe && s.cfg.Now().UnixNano() < s.pausedUntil.Load() {
		return s.errPaused()
	}
	dctx, cancel := context.WithTimeout(ctx, s.cfg.DialTimeout)
	defer cancel()
	conn, err := s.cfg.Dial(dctx, "tcp", s.cfg.Address)
	if err != nil {
		return s.fail(ErrorClassOf(err), err)
	}
	if s.cfg.TLS != nil {
		tc := tls.Client(conn, s.cfg.TLS.Clone())
		if err = tc.HandshakeContext(dctx); err != nil {
			_ = conn.Close()
			return s.handshakeFailed(err)
		}
		conn = tc
	}
	s.up(conn)
	return nil
}

func (s *Shipper) up(conn net.Conn) {
	s.conn = conn
	if s.everUp {
		s.reconnects.Add(1)
	}
	s.everUp = true
	s.since.Store(s.cfg.Now().UnixNano())
	s.connected.Store(true)
	s.pausedUntil.Store(0)
	s.pauseClass.Store(nil)
	if s.mismatch.Swap(false) {
		s.pending = true // a recovery is reported once the next frame is written
	}
	s.log.Info("gelf connected", "address", s.cfg.Address, "tls", s.cfg.TLS != nil)
	if s.cfg.OnConnected != nil {
		s.cfg.OnConnected()
	}
}

// handshakeFailed classifies a TLS failure. A pin mismatch or an expired certificate
// under an issuer pin pauses dialling and is reported once per episode.
func (s *Shipper) handshakeFailed(err error) error {
	class := ClassTLSPin
	switch {
	case errors.Is(err, tlspin.ErrExpired):
		class = ClassTLSExpired
	case !errors.Is(err, ErrPinMismatch):
		if ErrorClassOf(err) == ClassTimeout {
			return s.fail(ClassTimeout, err)
		}
		return s.fail(ClassTLS, err)
	}
	s.pausedUntil.Store(s.cfg.Now().Add(s.cfg.PinPause).UnixNano())
	s.pauseClass.Store(&class) // the reason: a failed probe during the pause cannot change it
	failed := s.fail(class, err)
	if !s.mismatch.Swap(true) {
		s.log.Warn("gelf server certificate refused; shipping paused", "address", s.cfg.Address,
			"class", class, "retry_in", s.cfg.PinPause)
		if s.cfg.OnPinMismatch != nil {
			s.cfg.OnPinMismatch(class)
		}
	}
	return failed
}

// fail records the class, drops the connection and returns the classified error; it
// logs only on the up→down edge so a long outage does not flood the local log.
func (s *Shipper) fail(class string, err error) error {
	s.lastClass.Store(&class)
	if s.connected.Swap(false) {
		s.log.Warn("gelf connection lost; queueing and dropping when full", "address", s.cfg.Address,
			"class", class, "err", err)
	}
	s.closeConn()
	return &ShipError{Class: class}
}

func (s *Shipper) closeConn() {
	if s.conn == nil {
		return
	}
	if err := s.conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.log.Debug("gelf close", "err", err)
	}
	s.conn = nil
	s.connected.Store(false)
}
