package secprobe

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"syscall"

	"oob-manager/internal/bmc"
)

// TLSTarget is one TLS port to scan.
type TLSTarget struct {
	Addr netip.AddrPort
	// Pin is the SHA-256 of the expected certificate's SubjectPublicKeyInfo.
	Pin []byte
	// RSAKeyExchange also offers RSA key exchange in the identity handshake (an iDRAC8
	// VNC port offers nothing else).
	RSAKeyExchange bool
	// IdentityOnly stops after the identity handshake: the certificate is wanted, the
	// version and suite variants are not (the VNC port, whose TLS settings are the web
	// server's; it also takes one client at a time).
	IdentityOnly bool
	// Abort, when set, is asked before each variant handshake; a non-empty answer is
	// why the scan stops there (a graphical console session opened on the port) and the
	// remaining variants stay unknown with that reason.
	Abort func() string
}

// Why the version and suite variants of a probe are unknown (bmc.TLSProbe.Partial).
const (
	PartialIdentityOnly = "only the certificate was read on this port"
	PartialNoAnswer     = "the port reset or closed the probe connections without a TLS answer"
	PartialInconsistent = "the port refused the TLS version it had just negotiated, so its answers cannot be trusted"
	PartialCutShort     = "the run ran out of time"
)

// dialFailed wraps a failure to connect, so a probe that could not be tried is told
// apart from one the server refused.
type dialFailed struct{ err error }

func (e *dialFailed) Error() string { return "secprobe: dial: " + e.err.Error() }
func (e *dialFailed) Unwrap() error { return e.err }

// ScanTLS runs the identity handshake (the settings the app itself uses) and records
// the leaf certificate. When it matches the pin and the certificate is not all that is
// wanted, seven more handshakes, spaced by Options.ProbeGap, find out which TLS
// versions and cipher suite groups the port accepts when offered alone. A variant
// counts as refused only when the peer answers with a TLS alert; a reset, a closed
// connection or a timeout leaves it unknown. The version the identity handshake
// negotiated must be accepted by its own variant, or no variant is trusted. Every
// connection closes right after its handshake: no application data is ever sent.
func ScanTLS(ctx context.Context, t TLSTarget, o Options) bmc.TLSProbe {
	o = o.withDefaults()
	p := bmc.TLSProbe{Port: int(t.Addr.Port())}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, CipherSuites: identitySuites(t.RSAKeyExchange)}
	st, leaf, err := identityHandshake(ctx, t.Addr, cfg, o)
	if err != nil {
		p.Read, p.Refused = failed(err), connRefused(err)
		return p
	}
	p.Read, p.Cert, p.PinMatch = bmc.SectionOf(nil), certFacts(leaf), pinMatches(leaf, t.Pin)
	p.Negotiated, p.Cipher = tls.VersionName(st.Version), tls.CipherSuiteName(st.CipherSuite)
	switch {
	case !p.PinMatch:
		return p // some other host answers at this address: it is not scanned
	case t.IdentityOnly:
		p.Partial = PartialIdentityOnly
		return p
	}
	results, reached, partial := runVariants(ctx, t, o)
	p.Partial = partial
	if partial == "" {
		results, p.Partial = consistent(st.Version, results, reached)
	}
	p.TLS10, p.TLS11, p.TLS12, p.TLS13 = results[0], results[1], results[2], results[3]
	p.WeakCipher, p.RSAKeyExchange, p.ForwardSecrecy = results[4], results[5], results[6]
	return p
}

// runVariants tries each variant in turn, pausing before each one and asking Abort
// first; it returns the facts (unknown for variants not tried), whether each variant
// reached the port (dialled), and why it stopped early ("" when every variant was tried).
func runVariants(ctx context.Context, t TLSTarget, o Options) ([]bmc.Fact[bool], []bool, string) {
	vs := variants()
	results, reached := make([]bmc.Fact[bool], len(vs)), make([]bool, len(vs))
	for i, v := range vs {
		if t.Abort != nil {
			if why := t.Abort(); why != "" {
				return results, reached, why
			}
		}
		if o.pause(ctx) != nil {
			return results, reached, PartialCutShort
		}
		results[i], reached[i] = accepts(ctx, t, v, o)
	}
	return results, reached, ""
}

// consistent checks that the version the identity handshake negotiated is accepted by
// its own variant. If the port was reached but refused it, or gave no TLS answer, the
// port is not answering the probes consistently and every variant is returned unknown,
// with why. A variant that could not be dialled says nothing about the port.
func consistent(negotiated uint16, results []bmc.Fact[bool], reached []bool) ([]bmc.Fact[bool], string) {
	own := ownVariant(negotiated)
	switch {
	case own < 0, !reached[own], results[own].Known && results[own].Value:
		return results, ""
	case !results[own].Known:
		return make([]bmc.Fact[bool], len(results)), PartialNoAnswer
	default:
		return make([]bmc.Fact[bool], len(results)), PartialInconsistent
	}
}

// ownVariant is the index of the "<version> only" variant of a negotiated version.
func ownVariant(version uint16) int {
	switch version {
	case tls.VersionTLS10:
		return 0
	case tls.VersionTLS11:
		return 1
	case tls.VersionTLS12:
		return 2
	case tls.VersionTLS13:
		return 3
	default:
		return -1
	}
}

// accepts runs one variant: accepted, refused (a TLS alert from the peer), or unknown
// when nothing can be concluded (dial failure, timeout, reset, a host without the
// pinned key). reached reports whether the port was dialled at all.
func accepts(ctx context.Context, t TLSTarget, v variant, o Options) (fact bmc.Fact[bool], reached bool) {
	cfg := &tls.Config{MinVersion: v.min, MaxVersion: v.max, CipherSuites: v.suites} //nolint:gosec // G402: probing old versions on purpose; no data is sent
	_, _, err := handshake(ctx, t.Addr, cfg, t.Pin, o)
	var df *dialFailed
	switch {
	case err == nil:
		return bmc.FactOf(true, "TLS probe: "+v.name), true
	case errors.As(err, &df):
		return bmc.Fact[bool]{}, false
	case refusedByPeer(err):
		return bmc.FactOf(false, "TLS probe: "+v.name), true
	default:
		return bmc.Fact[bool]{}, true
	}
}

// refusedByPeer reports a TLS alert from the peer that means "the port does not accept
// this": protocol_version (70), handshake_failure (40) or insufficient_security (71).
// Any other alert (an internal_error from a server that cannot serve the hello, a
// certificate complaint) says nothing about what the port accepts, like a reset, EOF or
// timeout. Go delivers a received alert as a *net.OpError with Op "remote error" whose
// Err is the unexported alert type, so the alert is told by its Error() text, taken from
// tls.AlertError of the same number (one source of truth, no string literals);
// tls.AlertError itself is matched too for the transports that return it.
func refusedByPeer(err error) bool {
	var alert tls.AlertError
	if errors.As(err, &alert) {
		return refusalAlert(alert.Error())
	}
	var op *net.OpError
	return errors.As(err, &op) && op.Op == "remote error" && op.Err != nil && refusalAlert(op.Err.Error())
}

// refusalAlert reports whether an alert's text is one of the three refusals.
func refusalAlert(text string) bool {
	for _, a := range []tls.AlertError{40, 70, 71} { // handshake_failure, protocol_version, insufficient_security
		if text == a.Error() {
			return true
		}
	}
	return false
}

// identityHandshake completes one handshake with the app's own settings and returns
// the leaf certificate for the caller to compare with the pin; it is the one handshake
// that does not fail on a mismatch, so the certificate of whatever answers is recorded.
func identityHandshake(ctx context.Context, addr netip.AddrPort, cfg *tls.Config, o Options) (tls.ConnectionState, *x509.Certificate, error) {
	return connect(ctx, addr, cfg, func(*x509.Certificate) error { return nil }, o)
}

// handshake completes one TLS handshake with cfg and closes the connection. It fails
// closed (bmc.ErrPinMismatch) on any key but the pinned one; a nil or malformed pin
// matches nothing.
func handshake(ctx context.Context, addr netip.AddrPort, cfg *tls.Config, pin []byte, o Options) (tls.ConnectionState, *x509.Certificate, error) {
	return connect(ctx, addr, cfg, func(leaf *x509.Certificate) error {
		if !pinMatches(leaf, pin) {
			return bmc.ErrPinMismatch
		}
		return nil
	}, o)
}

// connect dials, handshakes with cfg (verify judges the leaf certificate) and closes.
func connect(ctx context.Context, addr netip.AddrPort, cfg *tls.Config, verify func(*x509.Certificate) error,
	o Options) (tls.ConnectionState, *x509.Certificate, error) {
	raw, err := o.dial(ctx, addr)
	switch {
	case errors.Is(err, syscall.ECONNRESET):
		// The port took the connection and reset it before the dial returned (its RST can
		// land first on a loaded host): reached, with no TLS answer, like a later reset.
		return tls.ConnectionState{}, nil, err
	case err != nil:
		return tls.ConnectionState{}, nil, &dialFailed{err: err}
	}
	defer raw.Close()
	var leaf *x509.Certificate
	c := cfg.Clone()
	c.InsecureSkipVerify = true //nolint:gosec // G402: BMC certificates are self-signed; verify checks the SPKI pin
	c.SessionTicketsDisabled = true
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errNotProtocol
		}
		leaf = cs.PeerCertificates[0]
		return verify(leaf)
	}
	hctx, cancel := context.WithTimeout(ctx, o.HandshakeTimeout)
	defer cancel()
	conn := tls.Client(raw, c)
	if err := conn.HandshakeContext(hctx); err != nil {
		return tls.ConnectionState{}, nil, err
	}
	st := conn.ConnectionState()
	_ = conn.Close()
	return st, leaf, nil
}

func pinMatches(leaf *x509.Certificate, pin []byte) bool {
	sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	return len(pin) == sha256.Size && subtle.ConstantTimeCompare(sum[:], pin) == 1
}
