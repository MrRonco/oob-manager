package bmcsec

import (
	"fmt"
	"strings"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/secprobe"
)

// certWarnDays: a certificate closer than this to its expiry is a warning.
const certWarnDays = 30

func tlsEntries() []entry {
	return []entry{
		{check: Check{ID: "tls.cert_expiry", Group: GroupTLS, Title: "Web certificate expiry",
			Why: "An expired certificate makes browsers and tools refuse the BMC, or trains people to click through warnings. " +
				"oob-manager pins the key, not the certificate, so polling goes on; a renewal with a new key pauses polling until the new fingerprint is confirmed.",
			Fix:  "Renew the certificate before it expires. If the renewal changes the key, confirm the new fingerprint in Settings → Servers (or update tls_pin_sha256 in config.yaml).",
			Dell: "Upload a new certificate on the web server's SSL/TLS certificate page, or with racadm sslcertupload.",
			Docs: "https://www.rfc-editor.org/rfc/rfc5280#section-4.1.2.5"},
			eval: func(c evalCtx) outcome { return certExpiry(c.p.Web, "the HTTPS port", c.now) }},
		{check: Check{ID: "tls.cert_issuer", Group: GroupTLS, Title: "Web certificate issuer",
			Why: "Browsers cannot check a self-signed or factory default certificate, so people learn to accept certificate warnings, " +
				"which is exactly what someone in the middle of the connection needs.",
			Fix:  "Give the BMC a certificate from your own certificate authority. A new certificate changes the fingerprint oob-manager pins: confirm it in Settings → Servers.",
			Dell: "Create a signing request with racadm sslcsrgen, sign it with your CA and upload it with racadm sslcertupload."},
			eval: certIssuer},
		{check: Check{ID: "tls.cert_key", Group: GroupTLS, Title: "Web certificate key and signature",
			Why:  "A short RSA key can be factored and a SHA-1 or MD5 signature forged; either lets someone impersonate the BMC.",
			Fix:  "Use an RSA key of at least 2048 bits or an ECDSA key of at least 256 bits, signed with SHA-256 or better.",
			Dell: "The key size of a new signing request is the iDRAC.Security.CsrKeySize setting; create it with racadm sslcsrgen.",
			Docs: "https://csrc.nist.gov/pubs/sp/800/131/a/r2/final"},
			eval: func(c evalCtx) outcome { return certKey(c.p.Web, "the HTTPS port") }},
		{check: Check{ID: "tls.protocols", Group: GroupTLS, Title: "TLS versions on the web port",
			Why:  "TLS 1.0 and 1.1 have known weaknesses and were deprecated by RFC 8996; a client that still accepts them can be downgraded.",
			Fix:  "Allow TLS 1.2 and later only.",
			Dell: "Set iDRAC.WebServer.TLSProtocol to TLS 1.2 and Higher (web server settings).",
			Docs: "https://www.rfc-editor.org/rfc/rfc8996"},
			eval: tlsProtocols},
		{check: Check{ID: "tls.ciphers", Group: GroupTLS, Title: "Cipher suites on the web port",
			Why: "RC4 and 3DES can be broken with enough recorded traffic, and RSA key exchange has no forward secrecy: " +
				"whoever later gets the BMC's private key can decrypt recorded sessions, logins included.",
			Fix:  "Allow only ECDHE suites with AES-GCM or ChaCha20, plus TLS 1.3.",
			Dell: "Raise iDRAC.WebServer.SSLEncryptionBitLength; iDRAC9 can also restrict the suites with iDRAC.WebServer.CustomCipherString.",
			Docs: "https://wiki.mozilla.org/Security/Server_Side_TLS"},
			eval: tlsCiphers},
		{check: Check{ID: "tls.vnc_cert", Group: GroupTLS, Title: "VNC port certificate",
			Why: "The VNC port carries the screen and keyboard of the server. An expired or weak certificate there gets replaced " +
				"by people turning VNC encryption off.",
			Fix:  "Renew it together with the web certificate, and keep VNC encryption on.",
			Dell: "The VNC server presents the web server certificate when its SSL encryption is on."},
			applies: func(c evalCtx) bool { return c.in.VNC && c.in.VNCTLS },
			eval:    vncCert},
		sshEntry(),
	}
}

// usable checks that a TLS probe read the pinned BMC; ok false comes with the outcome.
func usable(p bmc.TLSProbe, what string) (outcome, bool) {
	switch {
	case !p.Read.OK():
		return unread(p.Read, what), false
	case !p.PinMatch:
		// Something other than the pinned key answered: the certificate was replaced, or
		// another host sits on the port. (Only the web port's pin also gates polling.)
		return out(Unknown, "", fmt.Sprintf("The certificate on port %d does not match the pinned fingerprint, so it was not evaluated: "+
			"the certificate was replaced, or another host answers on this port. Confirm the new fingerprint in Settings → Servers.", p.Port)), false
	default:
		return outcome{}, true
	}
}

func certExpiry(p bmc.TLSProbe, what string, now time.Time) outcome {
	if o, ok := usable(p, what); !ok {
		return o
	}
	c := p.Cert
	switch {
	case now.Before(c.NotBefore):
		return out(Fail, c.SHA256, "Not valid until "+c.NotBefore.Format(dateFmt)+" (the BMC clock may be wrong).")
	case c.NotAfter.Before(now):
		return out(Fail, c.SHA256, fmt.Sprintf("Expired on %s (%s).", c.NotAfter.Format(dateFmt), agoText(now.Sub(c.NotAfter))))
	}
	days := c.DaysLeft(now)
	if days < certWarnDays {
		return out(Warn, c.SHA256, fmt.Sprintf("Expires on %s, in %s.", c.NotAfter.Format(dateFmt), plural(days, "day", "days")))
	}
	return out(Pass, c.SHA256, fmt.Sprintf("Valid until %s (%s).", c.NotAfter.Format(dateFmt), plural(days, "day", "days")))
}

// agoText is an elapsed time in whole days ("less than a day ago" under one).
func agoText(d time.Duration) string {
	days := int(d / (24 * time.Hour))
	if days < 1 {
		return "less than a day ago"
	}
	return plural(days, "day", "days") + " ago"
}

// vendorDefault recognises a factory certificate: Dell iDRACs ship one issued to
// CN=idrac-<service tag>, OU=Remote Access Group; others say "default" in the name.
func vendorDefault(c bmc.CertFacts) bool {
	cn := strings.ToLower(c.SubjectCN)
	return strings.HasPrefix(cn, "idrac") || strings.Contains(c.SubjectOrgUnit, "Remote Access Group") ||
		strings.Contains(cn, "default")
}

func certIssuer(c evalCtx) outcome {
	if o, ok := usable(c.p.Web, "the HTTPS port"); !ok {
		return o
	}
	cert := c.p.Web.Cert
	switch {
	case cert.SelfSigned && vendorDefault(cert):
		return out(Warn, cert.SHA256, "Factory default certificate, self-signed: "+cert.Subject+".")
	case cert.SelfSigned:
		return out(Info, cert.SHA256, "Self-signed certificate: "+cert.Subject+". oob-manager trusts it by its pinned key; browsers show a warning.")
	default:
		return out(Pass, cert.SHA256, "Issued by "+cert.Issuer+".")
	}
}

func certKey(p bmc.TLSProbe, what string) outcome {
	if o, ok := usable(p, what); !ok {
		return o
	}
	c := p.Cert
	desc := fmt.Sprintf("%s %d-bit key, %s signature.", c.KeyType, c.KeyBits, c.Signature)
	subject := fmt.Sprintf("%s-%d/%s", c.KeyType, c.KeyBits, c.Signature)
	sig := strings.ToUpper(c.Signature)
	switch {
	case c.KeyType == "unknown":
		return out(Unknown, subject, "The key type is not one oob-manager knows.")
	case (c.KeyType == "RSA" && c.KeyBits < 2048) || (c.KeyType == "ECDSA" && c.KeyBits < 256):
		return out(Fail, subject, desc+" The key is too short.")
	case strings.Contains(sig, "MD5"):
		return out(Fail, subject, desc+" MD5 signatures can be forged.")
	case strings.Contains(sig, "SHA1"):
		return out(Warn, subject, desc+" SHA-1 signatures can be forged.")
	default:
		return out(Pass, subject, desc)
	}
}

func tlsProtocols(c evalCtx) outcome {
	p := c.p.Web
	if o, ok := usable(p, "the HTTPS port"); !ok {
		return o
	}
	var old []string
	for _, v := range []struct {
		f    bmc.Fact[bool]
		name string
	}{{p.TLS10, "TLS 1.0"}, {p.TLS11, "TLS 1.1"}} {
		if v.f.Value {
			old = append(old, v.name)
		}
	}
	var ev []string
	if pol := c.p.Redfish.Protocols.WebTLSPolicy; pol.Known {
		ev = append(ev, "BMC setting: "+pol.Value+from(pol.Source)+".")
	}
	ev = append(ev, tls13Note(p.TLS13))
	switch {
	case len(old) > 0:
		return out(Warn, strings.Join(old, ","), append([]string{"Accepts " + strings.Join(old, " and ") + "."}, ev...)...)
	case !p.TLS10.Known || !p.TLS11.Known:
		return out(Unknown, "", append([]string{"TLS 1.0 and 1.1 could not be tested (" + probeWhy(p) + ")."}, ev...)...)
	default:
		return out(Pass, "", append([]string{"Refuses TLS 1.0 and 1.1."}, ev...)...)
	}
}

// probeWhy is why a probe's variants are unknown: its own reason, else a failed
// connection.
func probeWhy(p bmc.TLSProbe) string {
	if p.Partial != "" {
		return p.Partial
	}
	return "a probe connection failed"
}

// partialNote is the evidence line of a port whose variants were not all run.
func partialNote(p bmc.TLSProbe) []string {
	switch p.Partial {
	case "":
		return nil
	case secprobe.PartialIdentityOnly:
		return []string{"Only the certificate was read on this port."}
	default:
		return []string{"Not every probe connection was made: " + p.Partial + "."}
	}
}

func tls13Note(f bmc.Fact[bool]) string {
	switch {
	case !f.Known:
		return "TLS 1.3 could not be tested."
	case f.Value:
		return "Offers TLS 1.3."
	default:
		return "Does not offer TLS 1.3."
	}
}

func tlsCiphers(c evalCtx) outcome {
	p := c.p.Web
	if o, ok := usable(p, "the HTTPS port"); !ok {
		return o
	}
	var warn, facets []string
	if p.WeakCipher.Value {
		warn, facets = append(warn, "Accepts RC4 or 3DES suites."), append(facets, "weak")
	}
	if p.ForwardSecrecy.Known && !p.ForwardSecrecy.Value && p.RSAKeyExchange.Value {
		warn, facets = append(warn, "No forward secrecy: only RSA key exchange suites are accepted at TLS 1.2."), append(facets, "no-fs")
	}
	negotiated := "Negotiated " + p.Negotiated + " with " + p.Cipher + "."
	switch {
	case len(warn) > 0:
		return out(Warn, strings.Join(facets, ","), append(warn, negotiated)...)
	case !p.WeakCipher.Known || !p.RSAKeyExchange.Known || !p.ForwardSecrecy.Known:
		return out(Unknown, "", "Some cipher suite probes could not be completed ("+probeWhy(p)+").", negotiated)
	case p.RSAKeyExchange.Value:
		return out(Info, "rsa-kex", "Also accepts RSA key exchange (no forward secrecy) for old clients.", negotiated)
	default:
		return out(Pass, "", "Only forward-secret suites.", negotiated)
	}
}

// vncCert is the worse of the expiry and the key check of the VNC port's certificate.
// A VNC port that presents the web certificate (iDRACs do) is one certificate: its
// findings and reminders belong to the web certificate checks, and this one is a note.
func vncCert(c evalCtx) outcome {
	const what = "the VNC port"
	p := c.p.VNC
	if p.Read.State == bmc.ReadSkipped && p.Read.Why == NotProbedIDRAC8 {
		// A permanent, by-design skip is a note, not an unknown: it would otherwise count
		// as unknown forever and keep an old acceptance of this check alive.
		return out(Info, "", "Not checked: "+NotProbedIDRAC8+".")
	}
	if o, ok := usable(p, what); !ok {
		return o
	}
	if sameCertificate(c.p) {
		return out(Info, p.Cert.SHA256, append([]string{"Same certificate as the web port; see Web certificate expiry."}, partialNote(p)...)...)
	}
	exp, key := certExpiry(p, what, c.now), certKey(p, what)
	res := exp.result
	if key.result.Rank() > res.Rank() {
		res = key.result
	}
	ev := append(exp.evidence, key.evidence...)
	return out(res, p.Cert.SHA256, append(ev, partialNote(p)...)...)
}
