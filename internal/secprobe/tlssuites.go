package secprobe

import "crypto/tls"

// Cipher suite groups the TLS probe offers, each alone (functions: no package-level
// mutable state). Offering a weak suite is the point of a probe: it learns whether the
// BMC accepts it. Probe connections carry no application data, so nothing is exposed.

// allSuites is every suite Go implements, secure and insecure (TLS 1.0–1.2).
func allSuites() []uint16 {
	var out []uint16
	for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
		out = append(out, s.ID)
	}
	return out
}

// weakSuites have a broken bulk cipher: RC4 (RFC 7465) or 3DES (SWEET32).
func weakSuites() []uint16 {
	return []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
	}
}

// rsaKexSuites use RSA key exchange: no forward secrecy (a stolen key decrypts recorded
// sessions).
func rsaKexSuites() []uint16 {
	return []uint16{
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA, tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
	}
}

// ecdheSuites are the forward-secret suites of TLS 1.2 and below.
func ecdheSuites() []uint16 {
	return []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
	}
}

// identitySuites are what the app itself offers: Go's defaults, plus RSA key exchange
// AES-GCM when the port needs it (iDRAC8's VNC TLS, quirk idrac8_rsa_kex_tls).
func identitySuites(rsaKex bool) []uint16 {
	if !rsaKex {
		return nil
	}
	return append(ecdheSuites()[:6:6], tls.TLS_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_RSA_WITH_AES_128_GCM_SHA256)
}

// variant is one probe handshake: a version range and the suites offered.
type variant struct {
	name     string
	min, max uint16
	suites   []uint16
}

func variants() []variant {
	return []variant{
		{"TLS 1.0 only", tls.VersionTLS10, tls.VersionTLS10, allSuites()},
		{"TLS 1.1 only", tls.VersionTLS11, tls.VersionTLS11, allSuites()},
		{"TLS 1.2 only", tls.VersionTLS12, tls.VersionTLS12, allSuites()},
		{"TLS 1.3 only", tls.VersionTLS13, tls.VersionTLS13, nil},
		{"RC4 and 3DES suites only", tls.VersionTLS10, tls.VersionTLS12, weakSuites()},
		{"RSA key exchange suites only", tls.VersionTLS10, tls.VersionTLS12, rsaKexSuites()},
		{"ECDHE suites only", tls.VersionTLS10, tls.VersionTLS12, ecdheSuites()},
	}
}
