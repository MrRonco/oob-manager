package bmcssh

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Errors from Open. The BMC's own messages are never put into them.
var (
	// ErrConfig: the host key or the operator login is missing or malformed. Nothing
	// was sent to the BMC.
	ErrConfig = errors.New("bmcssh: serial console not configured")
	// ErrHostKey: the BMC's host key is not the pinned one. The password was not sent.
	ErrHostKey = errors.New("bmcssh: host key does not match ssh_host_key")
	// ErrAuth: the BMC rejected the operator login.
	ErrAuth = errors.New("bmcssh: the BMC rejected the operator login")
	// ErrAlgorithms: no common key exchange, cipher or MAC (an old BMC may need the
	// idrac8_legacy_ssh quirk).
	ErrAlgorithms = errors.New("bmcssh: no common SSH algorithms")
	// ErrRefused: the BMC refused the PTY or the console command.
	ErrRefused = errors.New("bmcssh: the BMC refused the serial console")
)

// pinned accepts exactly the configured key (constant-time comparison of the wire form).
func pinned(want ssh.PublicKey) ssh.HostKeyCallback {
	w := want.Marshal()
	return func(_ string, _ net.Addr, got ssh.PublicKey) error {
		g := got.Marshal()
		if len(g) != len(w) || subtle.ConstantTimeCompare(g, w) != 1 {
			return ErrHostKey
		}
		return nil
	}
}

// classifyHandshake maps an ssh.NewClientConn failure to the package errors.
func classifyHandshake(ctx context.Context, id string, err error) error {
	var neg *ssh.AlgorithmNegotiationError
	switch {
	case errors.Is(err, ErrHostKey):
		return fmt.Errorf("%w (%s)", ErrHostKey, id)
	case errors.As(err, &neg) && neg.What == "host key":
		return fmt.Errorf("%w (%s): the BMC offers no key of the pinned type", ErrHostKey, id)
	case errors.As(err, &neg):
		return fmt.Errorf("%w (%s): %s", ErrAlgorithms, id, neg.What)
	case strings.Contains(err.Error(), "unable to authenticate"):
		return fmt.Errorf("%w (%s)", ErrAuth, id)
	case ctx.Err() != nil:
		return fmt.Errorf("bmcssh: handshake %s: %w", id, ctx.Err())
	default:
		return fmt.Errorf("bmcssh: handshake %s: %w", id, err)
	}
}

// Classify maps an Open error to an audit error class.
func Classify(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, ErrConfig):
		return "config"
	case errors.Is(err, ErrHostKey):
		return "host_key"
	case errors.Is(err, ErrAuth):
		return "bmc_auth"
	case errors.Is(err, ErrAlgorithms):
		return "algorithms"
	case errors.Is(err, ErrRefused):
		return "bmc_protocol"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	default:
		return "unreachable"
	}
}
