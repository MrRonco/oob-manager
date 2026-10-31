package rfb

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
)

// Client to server message types (RFC 6143 §7.5). Only these are ever forwarded.
const (
	MsgSetPixelFormat           = 0
	MsgSetEncodings             = 2
	MsgFramebufferUpdateRequest = 3
	MsgKeyEvent                 = 4
	MsgPointerEvent             = 5
	MsgClientCutText            = 6
)

// Limits on browser-supplied messages.
const (
	MaxEncodings      = 64
	DefaultMaxCutText = 64 << 10
	// maxDiscard is the largest oversized ClientCutText that is skipped rather than
	// ending the session.
	maxDiscard = 1 << 20
)

// FilterConfig selects the per-server behaviour.
type FilterConfig struct {
	// SafeEncodings narrows SetEncodings to Raw, CopyRect and DesktopSize (the iDRAC8
	// black-screen workaround).
	SafeEncodings bool
	// ViewOnly drops key, pointer and clipboard input.
	ViewOnly bool
	// MaxCutText caps forwarded clipboard text (default DefaultMaxCutText).
	MaxCutText int
}

// Message is one parsed client message: Forward is the bytes to send to the BMC, nil
// when the message was dropped (Dropped then names why).
type Message struct {
	Type    byte
	Forward []byte
	// Input is true for user input (key, pointer, clipboard): it resets the idle timer.
	Input   bool
	Dropped string
}

// Filter parses the browser's RFB stream after the handshake. Anything that is not an
// allowlisted message type ends the stream with ErrProtocol, because an unknown
// message's length cannot be known and the stream cannot be resynchronised.
type Filter struct {
	r   *bufio.Reader
	cfg FilterConfig
}

// NewFilter reads client messages from r.
func NewFilter(r io.Reader, cfg FilterConfig) *Filter {
	if cfg.MaxCutText <= 0 {
		cfg.MaxCutText = DefaultMaxCutText
	}
	return &Filter{r: bufio.NewReader(r), cfg: cfg}
}

// Next returns the next message. io.EOF means the browser closed cleanly.
func (f *Filter) Next() (Message, error) {
	t, err := f.r.ReadByte()
	if err != nil {
		return Message{}, err
	}
	switch t {
	case MsgSetPixelFormat:
		return f.pixelFormat()
	case MsgSetEncodings:
		return f.encodings()
	case MsgFramebufferUpdateRequest:
		return f.fixed(t, 10, false)
	case MsgKeyEvent:
		return f.fixed(t, 8, true)
	case MsgPointerEvent:
		return f.fixed(t, 6, true)
	case MsgClientCutText:
		return f.cutText()
	default:
		return Message{}, fmt.Errorf("%w: client message type %d is not allowed", ErrProtocol, t)
	}
}

func (f *Filter) read(t byte, n int) ([]byte, error) {
	b := make([]byte, n)
	b[0] = t
	if _, err := io.ReadFull(f.r, b[1:]); err != nil {
		return nil, fmt.Errorf("%w: message %d: %w", ErrProtocol, t, err)
	}
	return b, nil
}

func (f *Filter) fixed(t byte, n int, input bool) (Message, error) {
	b, err := f.read(t, n)
	if err != nil {
		return Message{}, err
	}
	if input && f.cfg.ViewOnly {
		return Message{Type: t, Dropped: "view_only"}, nil
	}
	return Message{Type: t, Forward: b, Input: input}, nil
}

// pixelFormat allows 8, 16 and 32 bits per pixel with a sane depth; anything else
// is dropped (the BMC keeps its current format).
func (f *Filter) pixelFormat() (Message, error) {
	b, err := f.read(MsgSetPixelFormat, 20)
	if err != nil {
		return Message{}, err
	}
	bpp, depth := b[4], b[5]
	if (bpp != 8 && bpp != 16 && bpp != 32) || depth == 0 || depth > bpp {
		return Message{Type: MsgSetPixelFormat, Dropped: "pixel_format"}, nil
	}
	return Message{Type: MsgSetPixelFormat, Forward: b}, nil
}

func (f *Filter) encodings() (Message, error) {
	hdr, err := f.read(MsgSetEncodings, 4)
	if err != nil {
		return Message{}, err
	}
	n := int(binary.BigEndian.Uint16(hdr[2:]))
	if n > MaxEncodings {
		return Message{}, fmt.Errorf("%w: %d encodings", ErrProtocol, n)
	}
	raw := make([]byte, 4*n)
	if _, err := io.ReadFull(f.r, raw); err != nil {
		return Message{}, fmt.Errorf("%w: encodings: %w", ErrProtocol, err)
	}
	encs := make([]int32, n)
	for i := range n {
		encs[i] = int32(binary.BigEndian.Uint32(raw[4*i:])) //nolint:gosec // G115: RFB encodings are signed 32-bit
	}
	return Message{Type: MsgSetEncodings, Forward: marshalEncodings(FilterEncodings(encs, f.cfg.SafeEncodings))}, nil
}

func marshalEncodings(encs []int32) []byte {
	b := []byte{MsgSetEncodings, 0}
	b = binary.BigEndian.AppendUint16(b, uint16(len(encs))) //nolint:gosec // G115: at most MaxEncodings
	for _, e := range encs {
		b = binary.BigEndian.AppendUint32(b, uint32(e)) //nolint:gosec // G115: two's complement on purpose
	}
	return b
}

// cutText forwards clipboard text up to MaxCutText. Larger text up to 1 MiB is read and
// dropped; anything bigger (including the negative lengths of the extended clipboard,
// which the encodings filter never lets the BMC enable) ends the stream.
func (f *Filter) cutText() (Message, error) {
	hdr, err := f.read(MsgClientCutText, 8)
	if err != nil {
		return Message{}, err
	}
	n := binary.BigEndian.Uint32(hdr[4:])
	if n > maxDiscard {
		return Message{}, fmt.Errorf("%w: clipboard length %d", ErrProtocol, n)
	}
	if int(n) > f.cfg.MaxCutText || f.cfg.ViewOnly {
		if _, err := io.CopyN(io.Discard, f.r, int64(n)); err != nil {
			return Message{}, fmt.Errorf("%w: clipboard: %w", ErrProtocol, err)
		}
		reason := "cut_text_too_large"
		if f.cfg.ViewOnly {
			reason = "view_only"
		}
		return Message{Type: MsgClientCutText, Dropped: reason}, nil
	}
	b := make([]byte, 8+int(n))
	copy(b, hdr)
	if _, err := io.ReadFull(f.r, b[8:]); err != nil {
		return Message{}, fmt.Errorf("%w: clipboard: %w", ErrProtocol, err)
	}
	return Message{Type: MsgClientCutText, Forward: b, Input: true}, nil
}
