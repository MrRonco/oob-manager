package bmcssh

import (
	"slices"

	"golang.org/x/crypto/ssh"
)

// algorithms returns the negotiation lists: x/crypto/ssh's supported (non-insecure)
// sets, host key algorithms limited to the pinned key's type, plus the legacy minimum
// when the idrac8_legacy_ssh quirk is on.
func algorithms(legacy bool, key ssh.PublicKey) ssh.Algorithms {
	sup := ssh.SupportedAlgorithms()
	a := ssh.Algorithms{KeyExchanges: sup.KeyExchanges, Ciphers: sup.Ciphers, MACs: sup.MACs,
		HostKeys: hostKeyAlgorithms(key.Type())}
	if legacy {
		a.KeyExchanges = append(slices.Clone(a.KeyExchanges), ssh.InsecureKeyExchangeDH14SHA1)
		if key.Type() == ssh.KeyAlgoRSA {
			a.HostKeys = append(a.HostKeys, ssh.KeyAlgoRSA)
		}
	}
	return a
}

// hostKeyAlgorithms are the signature algorithms accepted for a pinned key type. An RSA
// key is accepted with SHA-2 signatures only (ssh-rsa/SHA-1 needs the legacy quirk).
func hostKeyAlgorithms(keyType string) []string {
	if keyType == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{keyType}
}
