package tofu

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// HostKey is a fetched SSH host key.
type HostKey struct {
	Line        string // authorized-key line, the value of ssh_host_key
	Type        string // ssh-ed25519, ecdsa-sha2-nistp256, ssh-rsa …
	Fingerprint string // SHA256:… as ssh-keygen -l prints it
}

// SSHOptions bound a host key fetch. Legacy is the idrac8_legacy_ssh quirk: it also
// offers ssh-rsa (SHA-1) signatures and diffie-hellman-group14-sha1.
type SSHOptions struct {
	Options
	Legacy bool
}

var errGotKey = errors.New("tofu: host key captured")

// FetchSSHHostKey runs the SSH key exchange with addr and aborts in the host key
// callback, before any user authentication: no username or password is ever sent.
func FetchSSHHostKey(ctx context.Context, addr netip.AddrPort, o SSHOptions) (HostKey, error) {
	opts := o.withDefaults()
	conn, err := opts.dial(ctx, addr)
	if err != nil {
		return HostKey{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.HandshakeTimeout))
	var got ssh.PublicKey
	cfg := &ssh.ClientConfig{
		User: "tofu", // never sent: the handshake is aborted before authentication
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			got = key
			return errGotKey
		},
		HostKeyAlgorithms: hostKeyAlgorithms(o.Legacy),
		Timeout:           opts.HandshakeTimeout,
	}
	if o.Legacy {
		cfg.KeyExchanges = append(slices.Clone(ssh.SupportedAlgorithms().KeyExchanges), ssh.InsecureKeyExchangeDH14SHA1)
	}
	_, _, _, err = ssh.NewClientConn(conn, addr.String(), cfg)
	switch {
	case got != nil && errors.Is(err, errGotKey):
		return HostKey{Line: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(got))), Type: got.Type(),
			Fingerprint: ssh.FingerprintSHA256(got)}, nil
	case isTimeout(err):
		return HostKey{}, fail(ClassTimeout)
	default:
		return HostKey{}, fail(ClassNotSSH)
	}
}

// hostKeyAlgorithms: modern keys first; RSA with SHA-2 signatures, and ssh-rsa
// (SHA-1) only with the legacy quirk.
func hostKeyAlgorithms(legacy bool) []string {
	out := []string{ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
		ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	if legacy {
		out = append(slices.Clone(out), ssh.KeyAlgoRSA)
	}
	return out
}
