package console

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"
)

// Dial and handshake bounds for the BMC hop.
const (
	dialTimeout      = 5 * time.Second
	handshakeTimeout = 10 * time.Second
)

// ErrPinMismatch means the VNC port's certificate does not match the configured pin.
var ErrPinMismatch = errors.New("console: VNC certificate does not match the pin")

// ErrTLS means the TLS handshake on the VNC port failed for another reason (for example
// the BMC speaks plain RFB because its VNC SSL setting is off).
var ErrTLS = errors.New("console: VNC TLS handshake failed")

// DialFunc opens a TCP connection. Production uses net.Dialer; the e2e harness
// redirects the configured (TEST-NET) address to a fake VNC server.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func defaultDial(ctx context.Context, network, addr string) (net.Conn, error) {
	return (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, network, addr)
}

// rsaKexSuites is the TLS 1.2 suite list of the idrac8_rsa_kex_tls quirk: the ECDHE AEAD
// suites first, then RSA key-exchange AES-GCM as the last resort (no CBC, no SHA-1).
func rsaKexSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}
}

// vncTLS is the VNC port's TLS config. rsaKex (the idrac8_rsa_kex_tls quirk) also allows
// RSA key exchange, which iDRAC8 2.8x needs; TLS 1.3 is unaffected. The web/Redfish
// transport never uses this config.
func vncTLS(pin []byte, rsaKex bool) *tls.Config {
	c := pinnedTLS(pin)
	if rsaKex {
		c.CipherSuites = rsaKexSuites()
	}
	return c
}

// pinnedTLS trusts exactly the configured SPKI hash (BMC certificates are self-signed);
// chain verification is replaced, never skipped.
func pinnedTLS(pin []byte) *tls.Config {
	want := append([]byte(nil), pin...)
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec // replaced by the SPKI pin check below
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return ErrPinMismatch
			}
			sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], want) != 1 {
				return ErrPinMismatch
			}
			return nil
		},
	}
}

// dialTarget connects to the BMC VNC port, with pinned TLS when configured. A TLS
// target never falls back to plain RFB (some BMCs answer plain when no ClientHello
// arrives): a failed handshake is ErrTLS.
func dialTarget(ctx context.Context, dial DialFunc, t Target) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	raw, err := dial(dctx, "tcp", t.Addr)
	if err != nil {
		return nil, fmt.Errorf("console: dial %s: %w", t.ServerID, err)
	}
	if !t.TLS {
		return raw, nil
	}
	c := tls.Client(raw, vncTLS(t.pin, t.RSAKeyExchange))
	hctx, hcancel := context.WithTimeout(ctx, handshakeTimeout)
	defer hcancel()
	if err := c.HandshakeContext(hctx); err != nil {
		_ = raw.Close()
		if errors.Is(err, ErrPinMismatch) {
			return nil, ErrPinMismatch
		}
		return nil, fmt.Errorf("%w: %s", ErrTLS, t.ServerID)
	}
	return c, nil
}
