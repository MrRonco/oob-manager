// Package secprobe holds the network probes of the BMC security checks
// (docs/tech_doc.md §31). None of them sends a credential or changes anything on the
// BMC:
//   - a TLS probe completes one handshake and closes without sending application data;
//     every TLS connection after the first also checks the configured SPKI pin;
//   - the SSH probe exchanges identification strings, reads the server's KEXINIT and
//     closes before any key exchange or authentication;
//   - the HTTP probes send HEAD (GET only when HEAD is refused) without credentials,
//     follow no redirect, keep no connection and discard the body.
//
// Only the address the caller passes is dialled (no DNS, no proxy), with short bounds.
// Results carry a bmc.ErrorClass, never text the peer sent, except the sanitized SSH
// identification string and certificate fields.
package secprobe

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"oob-manager/internal/bmc"
)

// Default bounds of one probe connection, and the pause between two probe connections
// to the same port (a BMC web server that sees a burst of handshakes may drop them).
const (
	DefaultDialTimeout      = 5 * time.Second
	DefaultHandshakeTimeout = 5 * time.Second
	DefaultProbeGap         = 150 * time.Millisecond
)

// Dialer opens a TCP connection. nil uses net.Dialer; the e2e harness redirects the
// TEST-NET addresses of its mock BMCs.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Options bound the probes.
type Options struct {
	Dial             Dialer
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	// ProbeGap is the pause before each TLS variant handshake (0: DefaultProbeGap).
	// Tests shorten it.
	ProbeGap time.Duration
}

func (o Options) withDefaults() Options {
	if o.DialTimeout <= 0 {
		o.DialTimeout = DefaultDialTimeout
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if o.ProbeGap <= 0 {
		o.ProbeGap = DefaultProbeGap
	}
	if o.Dial == nil {
		o.Dial = (&net.Dialer{}).DialContext
	}
	return o
}

// dial connects to addr within DialTimeout; the connection's deadline is the handshake
// bound (callers may move it), and a cancelled ctx ends any read or write on it.
func (o Options) dial(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, o.DialTimeout)
	defer cancel()
	c, err := o.Dial(dctx, "tcp", addr.String())
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(o.HandshakeTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = c.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Now()) })
	return &ctxConn{Conn: c, stop: stop}, nil
}

// ctxConn is a probe connection whose pending reads and writes end when the context is
// cancelled (the deadline is pulled in); Close releases the watcher.
type ctxConn struct {
	net.Conn
	stop func() bool
}

func (c *ctxConn) Close() error {
	c.stop()
	return c.Conn.Close()
}

// pause waits ProbeGap before the next probe connection to a port, or until ctx ends.
func (o Options) pause(ctx context.Context) error {
	t := time.NewTimer(o.ProbeGap)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// connRefused reports a connection refused: the one dial failure that means nothing
// listens on the port (no route or a dialer refusal say nothing about it).
func connRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

// errNotProtocol marks a peer that answered something other than the expected protocol.
var errNotProtocol = errors.New("secprobe: unexpected answer")

// classify maps a probe error to a bmc error class.
func classify(err error) bmc.ErrorClass {
	var ne net.Error
	switch {
	case err == nil:
		return bmc.ClassNone
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded),
		errors.As(err, &ne) && ne.Timeout():
		return bmc.ClassTimeout
	case errors.Is(err, bmc.ErrPinMismatch):
		return bmc.ClassTLS
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return bmc.ClassUnreachable
	case errors.Is(err, errNotProtocol), errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return bmc.ClassProtocol
	default:
		var op *net.OpError
		if errors.As(err, &op) && op.Op == "dial" {
			return bmc.ClassUnreachable
		}
		return bmc.ClassProtocol
	}
}

func failed(err error) bmc.Section { return bmc.Section{State: bmc.ReadFailed, Class: classify(err)} }
