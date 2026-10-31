// Package bmcssh is the BMC SSH serial console driver (tech_doc §22). It logs in to a
// Dell iDRAC's SSH service with the operator account, verifies the configured host
// key exactly, requests a PTY and runs exactly one command: `console com2`, the iDRAC
// serial-over-LAN console. There is no shell, no other command and no way to send an
// arbitrary request: a Session only reads, writes, resizes, sends a break and quits.
//
// Algorithms are the x/crypto/ssh "supported" (non-insecure) sets. The
// idrac8_legacy_ssh quirk adds only key exchange diffie-hellman-group14-sha1 and, for
// an RSA host key, the ssh-rsa (SHA-1) signature, which iDRAC8 2.8x needs.
package bmcssh
