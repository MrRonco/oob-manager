package rfb

import (
	"fmt"
	"io"
)

// ServerHandshake runs the server side of the RFB handshake on rw (the browser) and
// offers only security type None: the relay has already authenticated to the BMC. It
// reads and ignores ClientInit and sends si.
func ServerHandshake(rw io.ReadWriter, si ServerInit) error {
	if err := writeAll(rw, versionString(8)); err != nil {
		return err
	}
	minor, err := readVersion(rw)
	if err != nil {
		return err
	}
	if minor == 3 {
		if err := writeAll(rw, []byte{0, 0, 0, SecNone}); err != nil {
			return err
		}
	} else if err := offerNone(rw, minor); err != nil {
		return err
	}
	var clientInit [1]byte
	if _, err := io.ReadFull(rw, clientInit[:]); err != nil {
		return fmt.Errorf("%w: ClientInit: %w", ErrProtocol, err)
	}
	return writeAll(rw, si.Marshal())
}

func offerNone(rw io.ReadWriter, minor int) error {
	if err := writeAll(rw, []byte{1, SecNone}); err != nil {
		return err
	}
	var pick [1]byte
	if _, err := io.ReadFull(rw, pick[:]); err != nil {
		return fmt.Errorf("%w: security choice: %w", ErrProtocol, err)
	}
	if pick[0] != SecNone {
		return fmt.Errorf("%w: client chose security type %d", ErrProtocol, pick[0])
	}
	if minor == 8 {
		return writeAll(rw, []byte{0, 0, 0, 0}) // SecurityResult OK
	}
	return nil
}
