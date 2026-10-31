package bmcsec

import (
	"fmt"
	"slices"
	"strings"

	"oob-manager/internal/bmc"
)

func sshEntry() entry {
	return entry{check: Check{ID: "ssh.algorithms", Group: GroupTLS, Title: "SSH algorithms",
		Why: "An SSH server with only SHA-1 key exchange, ssh-rsa host key signatures, CBC ciphers or MD5/SHA-1 MACs leaves logins " +
			"and console sessions open to downgrade and forgery; current clients refuse it unless told otherwise.",
		Fix: "Offer curve25519 or ECDH key exchange, Ed25519, ECDSA or rsa-sha2 host keys, and AES-GCM, ChaCha20 or AES-CTR ciphers. " +
			"Firmware updates usually bring them.",
		Dell: "iDRAC8 2.8x offers only ssh-rsa and diffie-hellman-group14-sha1 (oob-manager's idrac8_legacy_ssh quirk exists for it); " +
			"newer iDRAC9 firmware can restrict SSH algorithms (iDRAC.SSHCrypto settings).",
		Docs: "https://www.rfc-editor.org/rfc/rfc9142"},
		applies: func(c evalCtx) bool {
			s := c.p.SSH.Read.State
			return s != bmc.ReadNotTried && s != bmc.ReadSkipped
		},
		eval: sshAlgorithms}
}

// algClass sorts the names of one KEXINIT list into strong and weak.
type algClass struct {
	name         string
	list         string
	strong, weak func(string) bool
}

func sshClasses(p bmc.SSHProbe) []algClass {
	return []algClass{
		{"Key exchange", p.KeyExchanges, strongKex, weakKex},
		{"Host key algorithms", p.HostKeys, strongHostKey, weakHostKey},
		{"Ciphers", p.Ciphers, strongCipher, weakCipher},
		{"MACs", p.MACs, strongMAC, weakMAC},
	}
}

func sshAlgorithms(c evalCtx) outcome {
	p := c.p.SSH
	if !p.Read.OK() {
		return unread(p.Read, "the SSH port")
	}
	ciphers := names(p.Ciphers)
	// MACs only matter when a cipher without its own integrity (not GCM or ChaCha20-Poly1305) can be chosen.
	allAEAD := len(ciphers) > 0 && !slices.ContainsFunc(ciphers, func(n string) bool { return !aeadCipher(n) })
	var warns, facets, also []string
	for _, cl := range sshClasses(p) {
		list := names(cl.list)
		weak := filter(list, cl.weak)
		switch {
		case len(weak) == 0, cl.name == "MACs" && allAEAD:
		case !slices.ContainsFunc(list, cl.strong):
			warns, facets = append(warns, cl.name+": only "+strings.Join(weak, ", ")+"."), append(facets, cl.name)
		default:
			also = append(also, weak...)
		}
	}
	// The probe reads the banner and KEXINIT of whatever answers on the port, before any
	// authentication; unlike the TLS probes it has no pin to tie the answer to the BMC.
	server := fmt.Sprintf("Server: %s (read without authentication from whatever answers on port %d; not tied to the pinned host key).",
		p.Version, p.Port)
	switch {
	case len(warns) > 0:
		return out(Warn, strings.Join(facets, ","), append(warns, server)...)
	case len(also) > 0:
		return out(Info, "", "Also offers old algorithms for old clients: "+strings.Join(also, ", ")+".", server)
	default:
		return out(Pass, "", "Offers only current algorithms.", server)
	}
}

func names(list string) []string {
	var out []string
	for _, n := range strings.Split(list, ",") {
		if n = strings.TrimSpace(n); n != "" {
			out = append(out, n)
		}
	}
	return out
}

func filter(list []string, keep func(string) bool) []string {
	var out []string
	for _, n := range list {
		if keep(n) {
			out = append(out, n)
		}
	}
	return out
}

func strongKex(n string) bool {
	return strings.HasPrefix(n, "curve25519-sha256") || strings.HasPrefix(n, "ecdh-sha2-") ||
		strings.HasPrefix(n, "sntrup761x25519") || strings.HasPrefix(n, "mlkem768x25519") ||
		slices.Contains([]string{"diffie-hellman-group14-sha256", "diffie-hellman-group16-sha512",
			"diffie-hellman-group18-sha512", "diffie-hellman-group-exchange-sha256"}, n)
}

func weakKex(n string) bool {
	return strings.HasPrefix(n, "diffie-hellman-") && strings.HasSuffix(n, "-sha1")
}

func strongHostKey(n string) bool {
	return strings.HasPrefix(n, "ssh-ed25519") || strings.HasPrefix(n, "ssh-ed448") || strings.HasPrefix(n, "ecdsa-sha2-") ||
		strings.HasPrefix(n, "rsa-sha2-") || strings.HasPrefix(n, "sk-")
}

func weakHostKey(n string) bool {
	return strings.HasPrefix(n, "ssh-rsa") || strings.HasPrefix(n, "ssh-dss")
}

func strongCipher(n string) bool {
	return strings.Contains(n, "-gcm") || strings.HasPrefix(n, "chacha20-poly1305") || strings.HasSuffix(n, "-ctr")
}

func weakCipher(n string) bool {
	return strings.HasSuffix(n, "-cbc") || strings.HasPrefix(n, "arcfour") || n == "none" || n == "3des-cbc"
}

func strongMAC(n string) bool {
	return strings.HasPrefix(n, "hmac-sha2-") || strings.HasPrefix(n, "umac-128")
}

func weakMAC(n string) bool {
	return strings.HasPrefix(n, "hmac-md5") || strings.HasPrefix(n, "hmac-sha1") || strings.HasPrefix(n, "umac-64") ||
		strings.HasPrefix(n, "hmac-ripemd") || n == "none"
}

func aeadCipher(n string) bool {
	return strings.Contains(n, "-gcm") || strings.HasPrefix(n, "chacha20-poly1305")
}
