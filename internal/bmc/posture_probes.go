package bmc

import "time"

// TLSProbe is what handshake-only probes of one TLS port found. No application data is
// sent on any of its connections.
type TLSProbe struct {
	Read Section
	// Refused: the connection was refused (nothing listens): a known closed port, not a
	// failure to reach the BMC.
	Refused bool
	Port    int
	// PinMatch: the leaf certificate's SPKI equals the configured pin. A probe whose
	// certificate does not match describes some other host and is not evaluated.
	PinMatch bool
	Cert     CertFacts
	// Negotiated and Cipher are what the identity handshake (the app's own settings)
	// agreed on.
	Negotiated string // "TLS 1.3"
	Cipher     string // Go's name of the suite
	// Versions accepted when offered alone.
	TLS10, TLS11, TLS12, TLS13 Fact[bool]
	// WeakCipher: an RC4 or 3DES suite was accepted.
	WeakCipher Fact[bool]
	// RSAKeyExchange: a suite without forward secrecy (RSA key exchange) was accepted.
	RSAKeyExchange Fact[bool]
	// ForwardSecrecy: an ECDHE suite was accepted at TLS 1.2 or below.
	ForwardSecrecy Fact[bool]
	// Partial says why the version and suite variants are unknown ("" when every
	// variant was tried and answered): only the certificate was wanted, the probe was
	// stopped for a console session, or the port did not answer consistently. Written
	// by this app, never BMC text.
	Partial string
}

// Usable reports whether the probe read a certificate of the pinned BMC.
func (p TLSProbe) Usable() bool { return p.Read.OK() && p.PinMatch }

// CertFacts describe a leaf certificate. Text fields are sanitized and capped.
type CertFacts struct {
	SHA256         string // hex SHA-256 of the DER certificate (its fingerprint)
	Subject        string
	Issuer         string
	SubjectOrg     string
	SubjectOrgUnit string
	SubjectCN      string
	NotBefore      time.Time
	NotAfter       time.Time
	// SelfSigned: issuer equals subject and the signature verifies with its own key.
	SelfSigned bool
	KeyType    string // RSA, ECDSA, Ed25519 or unknown
	KeyBits    int
	Signature  string // x509 signature algorithm name, e.g. SHA256-RSA
}

// DaysLeft is the number of whole days until NotAfter, or -1 once the certificate has
// expired (how long ago is the evaluator's business, from NotAfter itself).
func (c CertFacts) DaysLeft(now time.Time) int {
	d := c.NotAfter.Sub(now)
	if d < 0 {
		return -1
	}
	return int(d / (24 * time.Hour))
}

// SSHProbe is the server's half of an SSH key exchange: its identification string and
// the algorithm lists of its KEXINIT. The probe stops there: no key exchange, no
// authentication.
type SSHProbe struct {
	Read Section
	// Refused: the connection was refused (nothing listens): a known closed port.
	Refused bool
	Port    int
	Version string // identification string, sanitized
	// Name-lists exactly as offered (comma-separated, capped).
	KeyExchanges, HostKeys, Ciphers, MACs string
}

// HTTPProbe is one unauthenticated HEAD (or GET) of "/" on the plain-HTTP port.
type HTTPProbe struct {
	Read Section
	// Refused: the connection was refused (ECONNREFUSED), the one failure that means
	// nothing listens on the port. Other unreachable classes (no route, a dialer that
	// refused) say nothing about the port.
	Refused  bool
	Port     int
	Status   int
	Redirect bool // a 3xx with a Location
	ToHTTPS  bool // … pointing at https://
}

// WSManProbe is an unauthenticated HEAD of /wsman on the HTTPS port, against a control
// path that cannot exist, over the pinned TLS connection.
type WSManProbe struct {
	Read          Section
	Status        int
	ControlStatus int
}
