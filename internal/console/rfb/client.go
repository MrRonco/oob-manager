package rfb

import (
	"fmt"
	"io"
	"slices"
)

// ClientHandshake runs the client side of the RFB handshake on rw (the BMC's VNC
// server): version, security (VNC authentication when a password is given, else
// None if offered), ClientInit with shared=0, and returns the ServerInit. The
// password is used only for the DES response and is never written to rw.
func ClientHandshake(rw io.ReadWriter, password []byte) (ServerInit, error) {
	minor, err := readVersion(rw)
	if err != nil {
		return ServerInit{}, err
	}
	if err = writeAll(rw, versionString(minor)); err != nil {
		return ServerInit{}, err
	}
	sec, err := negotiateClient(rw, minor, len(password) > 0)
	if err != nil {
		return ServerInit{}, err
	}
	if err = authenticate(rw, minor, sec, password); err != nil {
		return ServerInit{}, err
	}
	if err = writeAll(rw, []byte{0}); err != nil { // ClientInit: shared-flag 0
		return ServerInit{}, err
	}
	return ReadServerInit(rw)
}

// negotiateClient picks the security type: VNC authentication when we have a password,
// otherwise None. Anything else (Tight, VeNCrypt, …) is refused.
func negotiateClient(rw io.ReadWriter, minor int, havePassword bool) (byte, error) {
	if minor == 3 {
		t, err := readU32(rw)
		switch {
		case err != nil:
			return 0, err
		case t == SecInvalid:
			skipReason(rw)
			return 0, fmt.Errorf("%w: server refused the connection", ErrNoSecurity)
		case t == SecVNCAuth && havePassword, t == SecNone:
			return byte(t), nil
		default:
			return 0, fmt.Errorf("%w: server requires type %d", ErrNoSecurity, t)
		}
	}
	types, err := readSecurityTypes(rw)
	if err != nil {
		return 0, err
	}
	var pick byte
	switch {
	case havePassword && slices.Contains(types, SecVNCAuth):
		pick = SecVNCAuth
	case slices.Contains(types, SecNone):
		pick = SecNone
	default:
		return 0, fmt.Errorf("%w: offered %v", ErrNoSecurity, types)
	}
	return pick, writeAll(rw, []byte{pick})
}

func readSecurityTypes(r io.Reader) ([]byte, error) {
	var n [1]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	if n[0] == 0 {
		skipReason(r)
		return nil, fmt.Errorf("%w: server offered none", ErrNoSecurity)
	}
	if n[0] > maxSecTypes {
		return nil, fmt.Errorf("%w: too many security types", ErrProtocol)
	}
	types := make([]byte, n[0])
	if _, err := io.ReadFull(r, types); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	return types, nil
}

// authenticate performs the chosen security type and reads the SecurityResult where
// the protocol version sends one.
func authenticate(rw io.ReadWriter, minor int, sec byte, password []byte) error {
	if sec == SecVNCAuth {
		var ch [16]byte
		if _, err := io.ReadFull(rw, ch[:]); err != nil {
			return fmt.Errorf("%w: challenge: %w", ErrProtocol, err)
		}
		resp := VNCAuthResponse(ch, password)
		if err := writeAll(rw, resp[:]); err != nil {
			return err
		}
	} else if minor < 8 {
		return nil // 3.3 and 3.7 send no SecurityResult for None
	}
	res, err := readU32(rw)
	if err != nil {
		return err
	}
	if res != 0 {
		if minor == 8 {
			skipReason(rw)
		}
		return ErrAuthFailed
	}
	return nil
}
