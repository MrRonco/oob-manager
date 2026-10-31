package rfb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"testing"
)

func setEncodings(encs ...int32) []byte {
	b := []byte{MsgSetEncodings, 0}
	b = binary.BigEndian.AppendUint16(b, uint16(len(encs))) //nolint:gosec // test input
	for _, e := range encs {
		b = binary.BigEndian.AppendUint32(b, uint32(e)) //nolint:gosec // two's complement on purpose
	}
	return b
}

func encodingsOf(t *testing.T, msg []byte) []int32 {
	t.Helper()
	if len(msg) < 4 || msg[0] != MsgSetEncodings {
		t.Fatalf("not a SetEncodings: %v", msg)
	}
	n := int(binary.BigEndian.Uint16(msg[2:]))
	out := make([]int32, n)
	for i := range n {
		out[i] = int32(binary.BigEndian.Uint32(msg[4+4*i:])) //nolint:gosec // two's complement on purpose
	}
	return out
}

func keyEvent(down bool, sym uint32) []byte {
	b := []byte{MsgKeyEvent, 0, 0, 0}
	if down {
		b[1] = 1
	}
	return binary.BigEndian.AppendUint32(b, sym)
}

func cutText(n int) []byte {
	b := binary.BigEndian.AppendUint32([]byte{MsgClientCutText, 0, 0, 0}, uint32(n)) //nolint:gosec // test input
	return append(b, bytes.Repeat([]byte{'x'}, n)...)
}

func pixelFormat(bpp, depth byte) []byte {
	return append([]byte{MsgSetPixelFormat, 0, 0, 0, bpp, depth, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0}, 0, 0, 0)
}

func next(t *testing.T, f *Filter) Message {
	t.Helper()
	m, err := f.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	return m
}

func TestFilterPassesAllowedMessages(t *testing.T) {
	fbur := []byte{MsgFramebufferUpdateRequest, 1, 0, 0, 0, 0, 2, 128, 1, 224}
	ptr := []byte{MsgPointerEvent, 1, 0, 10, 0, 20}
	in := slices.Concat(pixelFormat(32, 24), fbur, keyEvent(true, 0xffe3), ptr, cutText(5))
	f := NewFilter(bytes.NewReader(in), FilterConfig{})
	if m := next(t, f); !bytes.Equal(m.Forward, pixelFormat(32, 24)) || m.Input {
		t.Errorf("SetPixelFormat = %+v", m)
	}
	if m := next(t, f); !bytes.Equal(m.Forward, fbur) || m.Input {
		t.Errorf("FramebufferUpdateRequest = %+v", m)
	}
	if m := next(t, f); !bytes.Equal(m.Forward, keyEvent(true, 0xffe3)) || !m.Input {
		t.Errorf("KeyEvent = %+v", m)
	}
	if m := next(t, f); !bytes.Equal(m.Forward, ptr) || !m.Input {
		t.Errorf("PointerEvent = %+v", m)
	}
	if m := next(t, f); !bytes.Equal(m.Forward, cutText(5)) || !m.Input {
		t.Errorf("ClientCutText = %+v", m)
	}
	if _, err := f.Next(); !errors.Is(err, io.EOF) {
		t.Errorf("end: %v", err)
	}
}

func TestFilterEncodings(t *testing.T) {
	// What noVNC 1.7 typically asks for, plus pseudo-encodings that would enable client
	// messages the filter does not allow (QEMU key, ExtendedDesktopSize, Fence, …).
	browser := []int32{EncTight, EncTightPNG, EncZRLE, EncHextile, EncRaw, EncCopyRect, -26, -256,
		EncDesktopSize, EncLastRect, -258, -308, -312, -313, -309, -1063131698, EncCursor, -316, EncDesktopName}
	f := NewFilter(bytes.NewReader(setEncodings(browser...)), FilterConfig{})
	got := encodingsOf(t, next(t, f).Forward)
	want := []int32{EncTight, EncTightPNG, EncZRLE, EncHextile, EncRaw, EncCopyRect, -26, -256,
		EncDesktopSize, EncLastRect, EncCursor, EncDesktopName}
	if !slices.Equal(got, want) {
		t.Errorf("default filter = %v, want %v", got, want)
	}

	f = NewFilter(bytes.NewReader(setEncodings(browser...)), FilterConfig{SafeEncodings: true})
	if got := encodingsOf(t, next(t, f).Forward); !slices.Equal(got, []int32{EncRaw, EncCopyRect, EncDesktopSize}) {
		t.Errorf("iDRAC8 safe encodings = %v", got)
	}
	// Raw is always present, even if the browser left it out.
	f = NewFilter(bytes.NewReader(setEncodings(EncTight, -258)), FilterConfig{SafeEncodings: true})
	if got := encodingsOf(t, next(t, f).Forward); !slices.Equal(got, []int32{EncRaw}) {
		t.Errorf("raw fallback = %v", got)
	}
}

func TestFilterDropsAndRejects(t *testing.T) {
	f := NewFilter(bytes.NewReader(slices.Concat(cutText(DefaultMaxCutText+1), pixelFormat(24, 24), keyEvent(true, 'a'))),
		FilterConfig{})
	if m := next(t, f); m.Forward != nil || m.Dropped != "cut_text_too_large" {
		t.Errorf("oversized cut text = %+v", m)
	}
	if m := next(t, f); m.Forward != nil || m.Dropped != "pixel_format" {
		t.Errorf("24 bpp pixel format = %+v", m)
	}
	if m := next(t, f); m.Forward == nil {
		t.Error("stream must stay in sync after a dropped message")
	}

	f = NewFilter(bytes.NewReader([]byte{MsgKeyEvent, 1, 0, 0, 0, 0, 0, 'a'}), FilterConfig{ViewOnly: true})
	if m := next(t, f); m.Forward != nil || m.Dropped != "view_only" {
		t.Errorf("view-only key = %+v", m)
	}

	rejects := map[string][]byte{
		"unknown type":       {255, 0, 0, 0},
		"set desktop size":   {251, 0, 0, 0},
		"too many encodings": setEncodings(make([]int32, MaxEncodings+1)...),
		"huge cut text":      binary.BigEndian.AppendUint32([]byte{MsgClientCutText, 0, 0, 0}, 0x80000010),
		"truncated key":      {MsgKeyEvent, 1, 0},
	}
	for name, in := range rejects {
		t.Run(name, func(t *testing.T) {
			_, err := NewFilter(bytes.NewReader(in), FilterConfig{}).Next()
			if err == nil || errors.Is(err, io.EOF) && name != "truncated key" {
				t.Fatalf("err = %v", err)
			}
		})
	}
}
