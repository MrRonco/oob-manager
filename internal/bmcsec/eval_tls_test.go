package bmcsec

import (
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/secprobe"
)

func TestCertExpiry(t *testing.T) {
	cases := []struct {
		name     string
		notAfter time.Time
		res      Result
		want     string
	}{
		{"valid", now.Add(200 * 24 * time.Hour), Pass, "Valid until 2027-05-09 (200 days)."},
		{"soon", now.Add(29*24*time.Hour + time.Hour), Warn, "in 29 days"},
		{"one day", now.Add(36 * time.Hour), Warn, "in 1 day."},
		{"expired", now.Add(-50 * time.Hour), Fail, "Expired on 2026-10-19 (2 days ago)."},
		{"expired today", now.Add(-10 * time.Hour), Fail, "Expired on 2026-10-21 (less than a day ago)."},
		// The warning threshold is strict: 30 whole days left pass, 29 warn.
		{"on the threshold", now.Add(30 * 24 * time.Hour), Pass, "Valid until 2026-11-20 (30 days)."},
		{"under the threshold", now.Add(30*24*time.Hour - time.Second), Warn, "Expires on 2026-11-20, in 29 days."},
	}
	for _, c := range cases {
		p := good()
		p.Web.Cert.NotAfter = c.notAfter
		f := expect(t, p, goodInputs(), "tls.cert_expiry", c.res, c.want)
		if f.Subject != p.Web.Cert.SHA256 {
			t.Errorf("%s: subject %q", c.name, f.Subject)
		}
	}
	p := good()
	p.Web.Cert.NotBefore = now.Add(time.Hour)
	expect(t, p, goodInputs(), "tls.cert_expiry", Fail, "Not valid until")
}

func TestTLSProbeUnusable(t *testing.T) {
	p := good()
	p.Web.PinMatch = false
	for _, id := range []string{"tls.cert_expiry", "tls.cert_issuer", "tls.cert_key", "tls.protocols", "tls.ciphers"} {
		expect(t, p, goodInputs(), id, Unknown, "does not match the pinned fingerprint")
	}
	p.Web = bmc.TLSProbe{Read: bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassUnreachable}, Port: 443}
	expect(t, p, goodInputs(), "tls.cert_expiry", Unknown, "The HTTPS port could not be read (not reachable).")
}

func TestCertIssuer(t *testing.T) {
	p := good()
	p.Web.Cert.SelfSigned = true
	expect(t, p, goodInputs(), "tls.cert_issuer", Info, "Self-signed certificate")
	p.Web.Cert.SubjectCN, p.Web.Cert.Subject = "idrac-SVCTAG1", "CN=idrac-SVCTAG1,OU=Remote Access Group,O=Dell Inc."
	expect(t, p, goodInputs(), "tls.cert_issuer", Warn, "Factory default certificate")
	p.Web.Cert.SubjectCN, p.Web.Cert.SubjectOrgUnit = "bmc", "Remote Access Group"
	expect(t, p, goodInputs(), "tls.cert_issuer", Warn, "Factory default")
	p.Web.Cert.SubjectOrgUnit, p.Web.Cert.SubjectCN = "", "BMC default certificate"
	expect(t, p, goodInputs(), "tls.cert_issuer", Warn, "")
	p.Web.Cert.SelfSigned = false
	expect(t, p, goodInputs(), "tls.cert_issuer", Pass, "Issued by CN=Lab CA.")
}

func TestCertKey(t *testing.T) {
	cases := []struct {
		kind string
		bits int
		sig  string
		res  Result
	}{
		{"RSA", 2048, "SHA256-RSA", Pass},
		{"RSA", 1024, "SHA256-RSA", Fail},
		{"ECDSA", 224, "ECDSA-SHA256", Fail},
		{"Ed25519", 256, "Ed25519", Pass},
		{"RSA", 2048, "SHA1-RSA", Warn},
		{"RSA", 2048, "MD5-RSA", Fail},
		{"unknown", 0, "?", Unknown},
	}
	for _, c := range cases {
		p := good()
		p.Web.Cert.KeyType, p.Web.Cert.KeyBits, p.Web.Cert.Signature = c.kind, c.bits, c.sig
		f := expect(t, p, goodInputs(), "tls.cert_key", c.res, "")
		if c.res != Unknown && f.Evidence[0] == "" {
			t.Errorf("%+v: evidence %v", c, f.Evidence)
		}
	}
}

func TestTLSProtocols(t *testing.T) {
	p := good()
	p.Web.TLS10, p.Web.TLS11 = on(true, "p"), on(true, "p")
	p.Redfish.Protocols.WebTLSPolicy = bmc.FactOf("TLS 1.1 and Higher", "Dell attribute WebServer.1.TLSProtocol")
	f := expect(t, p, goodInputs(), "tls.protocols", Warn, "Accepts TLS 1.0 and TLS 1.1.")
	if f.Subject != "TLS 1.0,TLS 1.1" || f.Evidence[1] != "BMC setting: TLS 1.1 and Higher (Dell attribute WebServer.1.TLSProtocol)." {
		t.Fatalf("finding %+v", f)
	}
	p = good()
	p.Web.TLS11 = bmc.Fact[bool]{}
	expect(t, p, goodInputs(), "tls.protocols", Unknown, "could not be tested")
	p = good()
	p.Web.TLS13 = on(false, "p")
	expect(t, p, goodInputs(), "tls.protocols", Pass, "Does not offer TLS 1.3.")
	p.Web.TLS13 = bmc.Fact[bool]{}
	expect(t, p, goodInputs(), "tls.protocols", Pass, "TLS 1.3 could not be tested.")
}

func TestTLSCiphers(t *testing.T) {
	p := good()
	p.Web.WeakCipher = on(true, "p")
	expect(t, p, goodInputs(), "tls.ciphers", Warn, "RC4 or 3DES")
	p = good()
	p.Web.RSAKeyExchange, p.Web.ForwardSecrecy = on(true, "p"), on(false, "p")
	f := expect(t, p, goodInputs(), "tls.ciphers", Warn, "No forward secrecy")
	if f.Subject != "no-fs" {
		t.Fatalf("subject %q", f.Subject)
	}
	p.Web.ForwardSecrecy = on(true, "p")
	expect(t, p, goodInputs(), "tls.ciphers", Info, "Also accepts RSA key exchange")
	p.Web.ForwardSecrecy = bmc.Fact[bool]{}
	expect(t, p, goodInputs(), "tls.ciphers", Unknown, "could not be completed")
}

func TestVNCCert(t *testing.T) {
	p := good()
	// The VNC server presents the web certificate: one certificate, one finding (the web one).
	p.Web.Cert.NotAfter, p.VNC.Cert.NotAfter = now.Add(-time.Hour), now.Add(-time.Hour)
	f := expect(t, p, goodInputs(), "tls.vnc_cert", Info, "Same certificate as the web port; see Web certificate expiry.")
	if f.Subject != p.VNC.Cert.SHA256 || len(f.Evidence) != 1 {
		t.Fatalf("finding %+v", f)
	}
	p = good()
	p.VNC.Cert.SHA256 = "other"
	p.VNC.Cert.KeyType, p.VNC.Cert.KeyBits = "RSA", 1024
	f = expect(t, p, goodInputs(), "tls.vnc_cert", Fail, "too short")
	if f.Subject != "other" {
		t.Fatalf("subject %q", f.Subject)
	}
	p = good()
	p.VNC.Cert.SHA256, p.VNC.Cert.NotAfter = "other", now.Add(10*24*time.Hour)
	expect(t, p, goodInputs(), "tls.vnc_cert", Warn, "in 10 days")
	p.VNC = bmc.TLSProbe{Read: bmc.Skipped("a console session was open")}
	expect(t, p, goodInputs(), "tls.vnc_cert", Unknown, "Not checked: a console session was open.")
}

func TestSSHAlgorithms(t *testing.T) {
	p := good()
	p.SSH.KeyExchanges, p.SSH.HostKeys = "diffie-hellman-group14-sha1,kex-strict-s-v00@openssh.com", "ssh-rsa"
	p.SSH.Ciphers, p.SSH.MACs = "aes128-ctr,aes256-cbc", "hmac-sha1"
	f := expect(t, p, goodInputs(), "ssh.algorithms", Warn, "Host key algorithms: only ssh-rsa.")
	if f.Subject != "Key exchange,Host key algorithms,MACs" {
		t.Fatalf("subject %q evidence %v", f.Subject, f.Evidence)
	}
	p = good()
	p.SSH.HostKeys = "ssh-ed25519,ssh-rsa"
	p.SSH.MACs = "hmac-sha2-256,hmac-md5"
	expect(t, p, goodInputs(), "ssh.algorithms", Info, "ssh-rsa, hmac-md5")
	p = good()
	p.SSH.Ciphers, p.SSH.MACs = "chacha20-poly1305@openssh.com", "hmac-sha1"
	expect(t, p, goodInputs(), "ssh.algorithms", Pass, "Offers only current algorithms.")
	p.SSH.Ciphers = "3des-cbc,arcfour"
	expect(t, p, goodInputs(), "ssh.algorithms", Warn, "Ciphers: only 3des-cbc, arcfour.")
	p.SSH = bmc.SSHProbe{Read: bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassTimeout}}
	expect(t, p, goodInputs(), "ssh.algorithms", Unknown, "timed out")
}

// TestTLSProbePartialIsExplained: when not every variant was tried, the checks say why
// (a reset, the console guard) instead of "a probe connection failed", and never pass.
func TestTLSProbePartialIsExplained(t *testing.T) {
	p := good()
	none := bmc.Fact[bool]{}
	p.Web.TLS10, p.Web.TLS11, p.Web.TLS12, p.Web.TLS13 = none, none, none, none
	p.Web.WeakCipher, p.Web.RSAKeyExchange, p.Web.ForwardSecrecy = none, none, none
	expect(t, p, goodInputs(), "tls.protocols", Unknown, "TLS 1.0 and 1.1 could not be tested (a probe connection failed).")
	expect(t, p, goodInputs(), "tls.ciphers", Unknown, "Some cipher suite probes could not be completed (a probe connection failed).")
	p.Web.Partial = "the port reset the probe connections"
	expect(t, p, goodInputs(), "tls.protocols", Unknown, "TLS 1.0 and 1.1 could not be tested (the port reset the probe connections).")
	expect(t, p, goodInputs(), "tls.ciphers", Unknown, "(the port reset the probe connections)")
	p = good()
	p.VNC.Cert.SHA256, p.VNC.Partial = "other", "a graphical console session was opened"
	expect(t, p, goodInputs(), "tls.vnc_cert", Pass, "Not every probe connection was made: a graphical console session was opened.")
	p.VNC.Partial = secprobe.PartialIdentityOnly
	expect(t, p, goodInputs(), "tls.vnc_cert", Pass, "Only the certificate was read on this port.")
}

// TestSSHAndHTTPEvidenceSayWhatTheyAre: the SSH and plain-HTTP probes read whatever
// answers on those ports without authentication and are not tied to a pin; the
// evidence says so. A pin mismatch on a TLS port is explained without blaming polling
// (a VNC mismatch does not pause anything).
func TestSSHAndHTTPEvidenceSayWhatTheyAre(t *testing.T) {
	p := good()
	f := expect(t, p, goodInputs(), "ssh.algorithms", Pass, "Server: SSH-2.0-OpenSSH_9.6 (read without authentication from whatever answers on port 22; not tied to the pinned host key).")
	if len(f.Evidence) != 2 {
		t.Fatalf("evidence %v", f.Evidence)
	}
	expect(t, p, goodInputs(), "svc.http", Pass, "Unauthenticated request to whatever answers on port 80; not tied to a pin.")
	p.HTTP = bmc.HTTPProbe{Read: ok(), Port: 8080, Status: 200}
	expect(t, p, goodInputs(), "svc.http", Warn, "Unauthenticated request to whatever answers on port 8080; not tied to a pin.")
	p = good()
	p.VNC.PinMatch = false
	f = expect(t, p, goodInputs(), "tls.vnc_cert", Unknown, "The certificate on port 5901 does not match the pinned fingerprint, so it was not evaluated")
	if ev := strings.Join(f.Evidence, " "); strings.Contains(ev, "pauses polling") || !strings.Contains(ev, "Settings → Servers") {
		t.Fatalf("evidence %q", ev)
	}
}
