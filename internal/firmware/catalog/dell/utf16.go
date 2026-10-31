package dell

import (
	"bufio"
	"errors"
	"io"
	"unicode/utf16"
	"unicode/utf8"
)

// errUTF16 is malformed UTF-16: an odd byte count or an unpaired surrogate. A catalog
// that is not well formed is refused, never repaired with U+FFFD.
var errUTF16 = errors.New("malformed UTF-16")

// textReader returns r as UTF-8 and whether it was transcoded: input starting with a
// UTF-16 byte order mark (LE or BE) is transcoded, anything else passes through (and
// must then be UTF-8, which the XML decoder enforces).
func textReader(r io.Reader) (io.Reader, bool, error) {
	br := bufio.NewReaderSize(r, 64<<10)
	bom, err := br.Peek(2)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	switch {
	case len(bom) == 2 && bom[0] == 0xFF && bom[1] == 0xFE:
		_, _ = br.Discard(2)
		return &utf16Reader{src: br, little: true}, true, nil
	case len(bom) == 2 && bom[0] == 0xFE && bom[1] == 0xFF:
		_, _ = br.Discard(2)
		return &utf16Reader{src: br}, true, nil
	default:
		return br, false, nil
	}
}

// utf16Reader transcodes UTF-16 code units to UTF-8.
type utf16Reader struct {
	src    *bufio.Reader
	little bool
	buf    []byte // encoded UTF-8 not yet returned
	err    error
}

func (u *utf16Reader) Read(p []byte) (int, error) {
	for len(u.buf) < len(p) && u.err == nil {
		u.fill()
	}
	n := copy(p, u.buf)
	u.buf = u.buf[n:]
	if n == 0 && u.err != nil {
		return 0, u.err
	}
	return n, nil
}

// fill decodes up to 4 KiB of code units into buf, or sets err.
func (u *utf16Reader) fill() {
	for range 4096 {
		c, ok := u.unit()
		if !ok {
			return
		}
		r := rune(c)
		switch {
		case utf16.IsSurrogate(r) && c < 0xDC00:
			lo, ok := u.unit()
			if !ok {
				u.fail()
				return
			}
			if r = utf16.DecodeRune(r, rune(lo)); r == utf8.RuneError {
				u.err = errUTF16
				return
			}
		case utf16.IsSurrogate(r):
			u.err = errUTF16 // a low surrogate with no high one before it
			return
		}
		u.buf = utf8.AppendRune(u.buf, r)
	}
}

// unit reads one code unit; at the end of the input it sets err (EOF, or errUTF16 for a
// lone trailing byte) and reports false.
func (u *utf16Reader) unit() (uint16, bool) {
	a, err := u.src.ReadByte()
	if err != nil {
		u.err = err
		return 0, false
	}
	b, err := u.src.ReadByte()
	if err != nil {
		u.err = errUTF16
		if !errors.Is(err, io.EOF) {
			u.err = err
		}
		return 0, false
	}
	if u.little {
		return uint16(b)<<8 | uint16(a), true
	}
	return uint16(a)<<8 | uint16(b), true
}

// fail turns a clean end of input in the middle of a surrogate pair into errUTF16.
func (u *utf16Reader) fail() {
	if errors.Is(u.err, io.EOF) {
		u.err = errUTF16
	}
}
