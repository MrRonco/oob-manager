package rfb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// Security types (RFC 6143 §7.1.2).
const (
	SecInvalid = 0
	SecNone    = 1
	SecVNCAuth = 2
)

// Limits on server-supplied lengths.
const (
	MaxNameLen   = 1024
	MaxReasonLen = 1024
	versionLen   = 12
	maxSecTypes  = 32
)

// Errors. Messages never include text supplied by the peer.
var (
	ErrProtocol           = errors.New("rfb: protocol error")
	ErrUnsupportedVersion = errors.New("rfb: unsupported protocol version")
	ErrNoSecurity         = errors.New("rfb: no usable security type")
	ErrAuthFailed         = errors.New("rfb: authentication failed")
)

// ServerInit is the server's description of the framebuffer (RFC 6143 §7.3.2).
type ServerInit struct {
	Width, Height uint16
	PixelFormat   [16]byte
	Name          string
}

// WithName returns a copy with the desktop name replaced.
func (s ServerInit) WithName(name string) ServerInit {
	s.Name = name
	return s
}

// Marshal encodes the message.
func (s ServerInit) Marshal() []byte {
	b := make([]byte, 0, 24+len(s.Name))
	b = binary.BigEndian.AppendUint16(b, s.Width)
	b = binary.BigEndian.AppendUint16(b, s.Height)
	b = append(b, s.PixelFormat[:]...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(s.Name))) //nolint:gosec // G115: names are capped at MaxNameLen
	return append(b, s.Name...)
}

// ReadServerInit decodes a ServerInit, refusing names over MaxNameLen.
func ReadServerInit(r io.Reader) (ServerInit, error) {
	var hdr [24]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return ServerInit{}, fmt.Errorf("%w: ServerInit: %w", ErrProtocol, err)
	}
	n := binary.BigEndian.Uint32(hdr[20:])
	if n > MaxNameLen {
		return ServerInit{}, fmt.Errorf("%w: desktop name too long", ErrProtocol)
	}
	name := make([]byte, n)
	if _, err := io.ReadFull(r, name); err != nil {
		return ServerInit{}, fmt.Errorf("%w: ServerInit name: %w", ErrProtocol, err)
	}
	si := ServerInit{Width: binary.BigEndian.Uint16(hdr[0:]), Height: binary.BigEndian.Uint16(hdr[2:]), Name: string(name)}
	copy(si.PixelFormat[:], hdr[4:20])
	return si, nil
}

// readVersion reads a ProtocolVersion message and returns the minor version the
// session will use: 3 (3.3, also for 3.4–3.6), 7 or 8 (also for anything above 3.8).
func readVersion(r io.Reader) (int, error) {
	var b [versionLen]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrUnsupportedVersion, err)
	}
	return ParseVersion(b[:])
}

// ParseVersion parses "RFB xxx.yyy\n" and maps it to the minor version spoken (3, 7, 8).
func ParseVersion(b []byte) (int, error) {
	if len(b) != versionLen || string(b[:4]) != "RFB " || b[7] != '.' || b[11] != '\n' ||
		!threeDigits(b[4:7]) || !threeDigits(b[8:11]) {
		return 0, ErrUnsupportedVersion
	}
	major, err1 := strconv.Atoi(string(b[4:7]))
	minor, err2 := strconv.Atoi(string(b[8:11]))
	switch {
	case err1 != nil || err2 != nil || major != 3 || minor < 3:
		return 0, ErrUnsupportedVersion
	case minor >= 8:
		return 8, nil
	case minor == 7:
		return 7, nil
	default:
		return 3, nil
	}
}

// threeDigits reports whether b is exactly three ASCII digits. strconv.Atoi alone would
// also accept a sign ("+03", "-01"), which RFC 6143 §7.1.1 does not allow (fuzzing found it).
func threeDigits(b []byte) bool {
	return len(b) == 3 && b[0] >= '0' && b[0] <= '9' && b[1] >= '0' && b[1] <= '9' && b[2] >= '0' && b[2] <= '9'
}

func versionString(minor int) []byte { return fmt.Appendf(nil, "RFB 003.%03d\n", minor) }

// skipReason reads and discards a length-prefixed failure reason (the text is never
// surfaced: it is BMC-controlled).
func skipReason(r io.Reader) {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return
	}
	_, _ = io.CopyN(io.Discard, r, int64(min(binary.BigEndian.Uint32(n[:]), MaxReasonLen)))
}

func readU32(r io.Reader) (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("%w: %w", ErrProtocol, err)
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func writeAll(w io.Writer, b []byte) error {
	if _, err := w.Write(b); err != nil {
		return fmt.Errorf("%w: write: %w", ErrProtocol, err)
	}
	return nil
}
