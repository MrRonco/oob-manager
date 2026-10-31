// Package tofu fetches a BMC's identity for trust-on-first-use pinning
// (settings_design.md §3, TOFU fingerprint): the SPKI of its HTTPS (or VNC) certificate
// and its SSH host key. Fetches are handshake-only: the TLS fetch completes a handshake,
// records the leaf certificate and closes without sending a single HTTP byte (so there
// is nothing to redirect and no credential to leak); the SSH fetch aborts inside the
// host key callback, before any authentication. Only the validated address is dialled,
// with short bounds and no proxy. Errors carry a class only.
package tofu

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"strings"
	"time"

	"oob-manager/internal/tlspin"
)

// Default bounds of one fetch.
const (
	DefaultDialTimeout      = 5 * time.Second
	DefaultHandshakeTimeout = 5 * time.Second
)

// Class is the only thing a failed fetch reports.
type Class string

// Error classes.
const (
	ClassUnreachable Class = "unreachable"
	ClassTimeout     Class = "timeout"
	ClassNotTLS      Class = "not_tls"
	ClassBadCert     Class = "bad_cert"
	ClassNotSSH      Class = "not_ssh"
)

// Error is a failed fetch. Its text never includes anything the peer sent.
type Error struct{ Class Class }

func (e *Error) Error() string { return "tofu: fetch failed: " + string(e.Class) }

// Message is the sentence for the page.
func (e *Error) Message() string {
	switch e.Class {
	case ClassUnreachable:
		return "Nothing answered at that address and port. Check the address, the port and any IP filter on the BMC."
	case ClassTimeout:
		return "The BMC did not answer in time."
	case ClassNotTLS:
		return "Something answered, but it did not complete a TLS handshake. Check the port."
	case ClassBadCert:
		return "The BMC sent no usable certificate."
	default:
		return "Something answered, but it is not an SSH service this console can talk to (check the port and the legacy SSH setting)."
	}
}

func fail(c Class) error { return &Error{Class: c} }

// Dialer opens a TCP connection. nil uses net.Dialer; the e2e harness redirects
// TEST-NET addresses to its fakes.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Options bound a fetch.
type Options struct {
	DialTimeout      time.Duration
	HandshakeTimeout time.Duration
	Dial             Dialer
	// ServerName is sent as SNI (a GELF server behind an SNI router); empty sends none.
	ServerName string
	// RSAKeyExchange also offers TLS 1.2 RSA key-exchange suites (iDRAC8's VNC port,
	// quirk idrac8_rsa_kex_tls).
	RSAKeyExchange bool
}

func (o Options) withDefaults() Options {
	if o.DialTimeout <= 0 {
		o.DialTimeout = DefaultDialTimeout
	}
	if o.HandshakeTimeout <= 0 {
		o.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if o.Dial == nil {
		o.Dial = (&net.Dialer{}).DialContext
	}
	return o
}

func (o Options) dial(ctx context.Context, addr netip.AddrPort) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, o.DialTimeout)
	defer cancel()
	c, err := o.Dial(dctx, "tcp", addr.String())
	if err != nil {
		if isTimeout(err) {
			return nil, fail(ClassTimeout)
		}
		return nil, fail(ClassUnreachable)
	}
	return c, nil
}

// CertInfo is what the fingerprint page shows about a fetched certificate: the leaf,
// and in Chain the other certificates the server presented (issuers), in order, at
// most maxChain. A chain member carries no Chain of its own.
type CertInfo struct {
	SPKI      string // hex SHA-256 of the SubjectPublicKeyInfo (the pin)
	Subject   string
	Issuer    string
	NotBefore time.Time
	NotAfter  time.Time
	SANs      []string
	// SelfIssued: subject and issuer are the same name (a self-signed certificate or a root).
	SelfIssued bool
	Chain      []CertInfo
	// IssuerVerified: the leaf verifiably chains to Chain[0] and is valid for the name it
	// was fetched for (an issuer pin would hold). IssuerProblem says why not when a chain
	// was sent: IssuerUnrelated or IssuerWrongName. IssuerPublic: Chain[0] is trusted by the
	// system roots (a public CA signs certificates for anyone; prefer the leaf).
	IssuerVerified bool
	IssuerProblem  string
	IssuerPublic   bool
}

// maxChain bounds the presented certificates reported after the leaf.
const maxChain = 4

// Why an issuer pin would not hold.
const (
	IssuerUnrelated = "unrelated"  // the leaf does not chain to the CA the server sent
	IssuerWrongName = "wrong_name" // the leaf is not valid for the address or server name
)

// verifyName is the name an issuer pin checks the leaf against: the server name when
// one is set, else the IP address dialled.
func verifyName(addr netip.AddrPort, serverName string) string {
	if serverName != "" {
		return serverName
	}
	return addr.Addr().String()
}

func withIssuer(info CertInfo, peers []*x509.Certificate, name string) CertInfo {
	switch {
	case !tlspin.ChainsTo(peers[0], nil, peers[1]):
		info.IssuerProblem = IssuerUnrelated
	case peers[0].VerifyHostname(name) != nil:
		info.IssuerProblem = IssuerWrongName
	default:
		info.IssuerVerified = true
	}
	if sys, err := x509.SystemCertPool(); err == nil {
		_, verr := peers[1].Verify(x509.VerifyOptions{Roots: sys, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
		info.IssuerPublic = verr == nil
	}
	return info
}

// Recommended is the pin to offer first: the first issuer when the server sent a chain
// the leaf verifiably belongs to and that is not publicly trusted (the log server can then
// renew its leaf without a new pin), else the leaf.
func (c CertInfo) Recommended() string {
	if c.IssuerVerified && !c.IssuerPublic {
		return c.Chain[0].SPKI
	}
	return c.SPKI
}

// Grouped is the SPKI in groups of four hex digits, for comparing by eye.
func (c CertInfo) Grouped() string {
	var parts []string
	for i := 0; i+4 <= len(c.SPKI); i += 4 {
		parts = append(parts, c.SPKI[i:i+4])
	}
	return strings.Join(parts, " ")
}

var errNoCert = errors.New("tofu: no certificate")

// FetchTLS completes one TLS handshake with addr, records the leaf certificate and
// closes. No application data is sent.
func FetchTLS(ctx context.Context, addr netip.AddrPort, o Options) (CertInfo, error) {
	o = o.withDefaults()
	raw, err := o.dial(ctx, addr)
	if err != nil {
		return CertInfo{}, err
	}
	defer raw.Close()
	var peers []*x509.Certificate
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         o.ServerName,
		InsecureSkipVerify: true, //nolint:gosec // TOFU: the certificate is shown to an admin, never trusted here
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errNoCert
			}
			peers = cs.PeerCertificates
			return nil
		},
	}
	if o.RSAKeyExchange {
		cfg.CipherSuites = rsaKexSuites()
	}
	hctx, cancel := context.WithTimeout(ctx, o.HandshakeTimeout)
	defer cancel()
	c := tls.Client(raw, cfg)
	if err := c.HandshakeContext(hctx); err != nil {
		return CertInfo{}, classifyTLS(err)
	}
	_ = c.Close()
	info := infoOf(peers[0])
	for _, p := range peers[1:min(len(peers), maxChain+1)] {
		info.Chain = append(info.Chain, infoOf(p))
	}
	if len(peers) > 1 {
		info = withIssuer(info, peers, verifyName(addr, o.ServerName))
	}
	return info, nil
}

func classifyTLS(err error) error {
	var rh tls.RecordHeaderError
	switch {
	case errors.Is(err, errNoCert):
		return fail(ClassBadCert)
	case isTimeout(err):
		return fail(ClassTimeout)
	case errors.As(err, &rh):
		return fail(ClassNotTLS)
	case strings.Contains(err.Error(), "x509"), strings.Contains(err.Error(), "certificate"):
		return fail(ClassBadCert)
	default:
		return fail(ClassNotTLS)
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout())
}

func infoOf(c *x509.Certificate) CertInfo {
	sum := sha256.Sum256(c.RawSubjectPublicKeyInfo)
	sans := append([]string(nil), c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}
	return CertInfo{SPKI: hex.EncodeToString(sum[:]), Subject: c.Subject.String(), Issuer: c.Issuer.String(),
		NotBefore: c.NotBefore.UTC(), NotAfter: c.NotAfter.UTC(), SANs: sans,
		SelfIssued: bytes.Equal(c.RawSubject, c.RawIssuer)}
}

// rsaKexSuites: the ECDHE AEAD suites first, then RSA key-exchange AES-GCM (the same
// list the console uses for the idrac8_rsa_kex_tls quirk).
func rsaKexSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}
}
