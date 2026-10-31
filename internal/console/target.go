package console

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"

	"oob-manager/internal/config"
	"oob-manager/internal/secrets"
)

// Target is one server's graphical console endpoint, built from validated config and
// the secrets file only.
type Target struct {
	ServerID string
	Kind     config.BMCKind
	// Addr is the BMC VNC endpoint, literal IP and port.
	Addr string
	TLS  bool
	pin  []byte
	// Password is the VNC password; zero when the credential is missing.
	Password      secrets.Secret
	SafeEncodings bool
	LowColour     bool
	// RSAKeyExchange allows RSA key-exchange suites on the VNC TLS dial
	// (quirk idrac8_rsa_kex_tls; no forward secrecy).
	RSAKeyExchange bool
}

// HasPassword reports whether a VNC password is available.
func (t Target) HasPassword() bool { return !t.Password.IsZero() }

// TargetFor builds the Target of a server configured with console.graphical vnc.
// password may be zero (the credential is missing from the secrets file): the card
// then says "needs setup" and no connection is attempted.
func TargetFor(s config.Server, password secrets.Secret) (Target, error) {
	if s.Console.Graphical != config.GraphicalVNC {
		return Target{}, fmt.Errorf("console: server %s has no VNC console configured", s.ID)
	}
	v := s.Console.VNC
	t := Target{
		ServerID: s.ID, Kind: s.BMC.Kind, TLS: v.TLSEnabled(), Password: password,
		Addr:           net.JoinHostPort(s.BMC.Address, strconv.Itoa(v.Port)),
		SafeEncodings:  v.Has(config.QuirkIDRAC8SafeEncodings),
		LowColour:      v.Has(config.QuirkIDRAC8LowColour),
		RSAKeyExchange: v.Has(config.QuirkIDRAC8RSAKexTLS),
	}
	if t.TLS {
		pin, err := hex.DecodeString(s.VNCPin())
		if err != nil || len(pin) != 32 {
			return Target{}, fmt.Errorf("console: server %s: invalid VNC TLS pin", s.ID)
		}
		t.pin = pin
	}
	return t, nil
}
