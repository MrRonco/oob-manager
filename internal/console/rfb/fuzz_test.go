package rfb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// FuzzRFBFilter: any browser byte stream either yields allowlisted messages or ends with
// an error. It never panics. Forwarded messages carry their own type byte, stay inside
// the caps, and (except SetEncodings, which is rebuilt) are copied verbatim from the input.
func FuzzRFBFilter(f *testing.F) {
	key := []byte{MsgKeyEvent, 1, 0, 0, 0, 0, 0, 0x61}
	ptr := []byte{MsgPointerEvent, 0, 0, 10, 0, 20}
	fbur := []byte{MsgFramebufferUpdateRequest, 1, 0, 0, 0, 0, 4, 0, 3, 0}
	enc := []byte{MsgSetEncodings, 0, 0, 2, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x21}
	cut := append([]byte{MsgClientCutText, 0, 0, 0, 0, 0, 0, 3}, "abc"...)
	pf := make([]byte, 20)
	pf[4], pf[5] = 32, 24
	f.Add(bytes.Join([][]byte{key, ptr, fbur, enc, cut, pf}, nil), false, false)
	f.Add([]byte{MsgClientCutText, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}, false, false)
	f.Add([]byte{7, 1, 2, 3}, true, true)
	f.Fuzz(func(t *testing.T, in []byte, safe, viewOnly bool) {
		flt := NewFilter(bytes.NewReader(in), FilterConfig{SafeEncodings: safe, ViewOnly: viewOnly, MaxCutText: 64})
		for range len(in) + 1 { // every message consumes at least one byte
			m, err := flt.Next()
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, ErrProtocol) {
					t.Fatalf("unexpected error class: %v", err)
				}
				return
			}
			checkMessage(t, in, m, viewOnly)
		}
		t.Fatal("the filter returned more messages than input bytes")
	})
}

func checkMessage(t *testing.T, in []byte, m Message, viewOnly bool) {
	t.Helper()
	switch m.Type {
	case MsgSetPixelFormat, MsgSetEncodings, MsgFramebufferUpdateRequest, MsgKeyEvent, MsgPointerEvent, MsgClientCutText:
	default:
		t.Fatalf("forwarded a disallowed type %d", m.Type)
	}
	if m.Forward == nil {
		if m.Dropped == "" {
			t.Fatal("a dropped message has no reason")
		}
		return
	}
	if m.Forward[0] != m.Type {
		t.Fatalf("forwarded bytes start with %d, type %d", m.Forward[0], m.Type)
	}
	if viewOnly && m.Input {
		t.Fatal("input forwarded in view-only mode")
	}
	switch m.Type {
	case MsgSetEncodings:
		n := int(binary.BigEndian.Uint16(m.Forward[2:]))
		if n > MaxEncodings || len(m.Forward) != 4+4*n {
			t.Fatalf("encodings out of bounds: n=%d len=%d", n, len(m.Forward))
		}
	case MsgClientCutText:
		if len(m.Forward) > 8+64 {
			t.Fatalf("clipboard over the cap: %d", len(m.Forward))
		}
		fallthrough
	default:
		if !bytes.Contains(in, m.Forward) {
			t.Fatal("forwarded bytes are not a copy of the input")
		}
	}
}

// FuzzRFBServerHandshake: BMC-controlled version, security and ServerInit bytes never
// panic the client side, and a desktop name over MaxNameLen is never accepted.
func FuzzRFBServerHandshake(f *testing.F) {
	si := ServerInit{Width: 800, Height: 600, Name: "idrac"}
	ok38 := append(append([]byte("RFB 003.008\n"), 1, SecNone, 0, 0, 0, 0), si.Marshal()...)
	ok33 := append(append([]byte("RFB 003.003\n"), 0, 0, 0, SecNone), si.Marshal()...)
	f.Add(ok38, []byte(""))
	f.Add(ok33, []byte(""))
	f.Add(append([]byte("RFB 003.008\n"), 1, SecVNCAuth), []byte("pw"))
	f.Add([]byte("RFB 003.008\n\x00\x00\x00\x00\x05abcde"), []byte(""))
	f.Fuzz(func(t *testing.T, srv, password []byte) {
		rw := struct {
			io.Reader
			io.Writer
		}{bytes.NewReader(srv), io.Discard}
		got, err := ClientHandshake(rw, password)
		if err == nil && len(got.Name) > MaxNameLen {
			t.Fatalf("accepted a %d-byte desktop name", len(got.Name))
		}
	})
}

// FuzzParseVersion: only "RFB 003.yyy\n" with yyy >= 3 is accepted, as 3, 7 or 8.
func FuzzParseVersion(f *testing.F) {
	for _, s := range []string{"RFB 003.008\n", "RFB 003.003\n", "RFB 004.000\n", "RFB 003.-01\n", "RFB 003.+07\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := ParseVersion(b)
		if err != nil {
			return
		}
		if v != 3 && v != 7 && v != 8 {
			t.Fatalf("version %d", v)
		}
		if !bytes.HasPrefix(b, []byte("RFB 003.")) {
			t.Fatalf("accepted %q", b)
		}
	})
}

// TestParseVersionRejectsSigns is the regression for the fuzz finding: a sign in either
// number was accepted because strconv.Atoi allows one.
func TestParseVersionRejectsSigns(t *testing.T) {
	for _, s := range []string{"RFB +03.007\n", "RFB 003.+08\n", "RFB -03.008\n", "RFB 0 3.008\n"} {
		if v, err := ParseVersion([]byte(s)); !errors.Is(err, ErrUnsupportedVersion) {
			t.Errorf("%q: got %d, %v", s, v, err)
		}
	}
}
