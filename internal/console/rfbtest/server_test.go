package rfbtest

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"image"
	"image/color"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"oob-manager/internal/console/rfb"
)

func dial(t *testing.T, s *Server) net.Conn {
	t.Helper()
	c, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 250 && !cond(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !cond() {
		t.Fatal("condition not met")
	}
}

func TestSessionRecordsMessagesAndSendsFrames(t *testing.T) {
	s := New(t, Options{})
	c := dial(t, s)
	si, err := rfb.ClientHandshake(c, []byte(Password))
	if err != nil {
		t.Fatal(err)
	}
	if si.Width != DefaultWidth || si.Height != DefaultHeight || si.Name != DefaultName {
		t.Fatalf("ServerInit = %+v", si)
	}
	enc := []byte{rfb.MsgSetEncodings, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 1}
	pf8 := []byte{rfb.MsgSetPixelFormat, 0, 0, 0, 8, 8, 0, 1, 0, 7, 0, 7, 0, 3, 0, 3, 6, 0, 0, 0}
	fbur := []byte{rfb.MsgFramebufferUpdateRequest, 0, 0, 0, 0, 0, 0, 64, 0, 48}
	key := []byte{rfb.MsgKeyEvent, 1, 0, 0, 0, 0, 0xff, 0xe3}
	ptr := []byte{rfb.MsgPointerEvent, 0, 0, 1, 0, 1}
	cut := append([]byte{rfb.MsgClientCutText, 0, 0, 0, 0, 0, 0, 2}, "hi"...)
	for _, m := range [][]byte{enc, pf8, fbur, key, ptr, cut} {
		if _, err := c.Write(m); err != nil {
			t.Fatal(err)
		}
	}
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(c, hdr); err != nil || hdr[0] != 0 || binary.BigEndian.Uint16(hdr[2:]) != 1 {
		t.Fatalf("update header %v %v", hdr, err)
	}
	px := make([]byte, DefaultWidth*DefaultHeight) // 8 bpp
	if _, err := io.ReadFull(c, px); err != nil || px[0] != 7 {
		t.Fatalf("8-bit red pixel = %d, %v", px[0], err)
	}
	waitFor(t, func() bool { return len(s.CutTexts()) == 1 })
	if !slices.Equal(s.MessageTypes(), []byte{2, 0, 3, 4, 5, 6}) {
		t.Errorf("types = %v", s.MessageTypes())
	}
	if e := s.Encodings(); len(e) != 1 || !slices.Equal(e[0], []int32{0, 1}) {
		t.Errorf("encodings = %v", e)
	}
	if k := s.Keys(); len(k) != 1 || !k[0].Down || k[0].Sym != 0xffe3 {
		t.Errorf("keys = %v", k)
	}
	st := s.Stats()
	if st.AuthOK != 1 || st.Active != 1 || st.Updates != 1 || st.Pointers != 1 || s.CutTexts()[0] != "hi" {
		t.Errorf("stats = %+v", st)
	}
	_ = c.Close()
	waitFor(t, func() bool { return s.Stats().Active == 0 })
}

func TestWrongPasswordAndBannerProbe(t *testing.T) {
	s := New(t, Options{Password: "other123"})
	if _, err := rfb.ClientHandshake(dial(t, s), []byte(Password)); !errors.Is(err, rfb.ErrAuthFailed) {
		t.Fatalf("err = %v", err)
	}
	probe := dial(t, s)
	banner := make([]byte, 12)
	if _, err := io.ReadFull(probe, banner); err != nil || string(banner) != "RFB 003.008\n" {
		t.Fatalf("banner %q %v", banner, err)
	}
	_ = probe.Close()
	waitFor(t, func() bool { return s.Stats().Connections == 2 })
	if st := s.Stats(); st.AuthFailures != 1 || st.AuthOK != 0 {
		t.Errorf("stats = %+v", st)
	}
}

func TestTLSAndUnknownMessage(t *testing.T) {
	s := New(t, Options{TLS: true, Width: 8, Height: 8, Name: "tls"})
	if len(s.PinSHA256()) != 64 || s.Port() == 0 {
		t.Fatalf("pin %q port %d", s.PinSHA256(), s.Port())
	}
	raw := dial(t, s)
	c := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // test: pin checked elsewhere
	si, err := rfb.ClientHandshake(c, []byte(Password))
	if err != nil || si.Name != "tls" {
		t.Fatalf("%+v %v", si, err)
	}
	_, _ = c.Write([]byte{250, 0, 0, 0})
	_, err = bufio.NewReader(c).ReadByte()
	if err == nil {
		t.Error("server must hang up after an unknown message")
	}
	s.Close()
}

func TestStartWithoutTB(t *testing.T) {
	s, err := Start(Options{})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
}

func TestFrameInClientPixelFormat(t *testing.T) {
	frame := image.NewRGBA(image.Rect(0, 0, 2, 1))
	frame.Set(0, 0, color.RGBA{R: 0xaa, G: 0xaa, B: 0xaa, A: 0xff}) // text-mode grey
	frame.Set(1, 0, color.RGBA{B: 0xff, A: 0xff})
	s := New(t, Options{Frame: frame})
	c := dial(t, s)
	si, err := rfb.ClientHandshake(c, []byte(Password))
	if err != nil || si.Width != 2 || si.Height != 1 {
		t.Fatalf("ServerInit = %+v, %v", si, err)
	}
	read := func(n int) []byte {
		t.Helper()
		b := make([]byte, 16+n)
		if _, err := io.ReadFull(c, b); err != nil {
			t.Fatal(err)
		}
		return b[16:]
	}
	fbur := []byte{rfb.MsgFramebufferUpdateRequest, 0, 0, 0, 0, 0, 0, 2, 0, 1}
	_, _ = c.Write(fbur)
	if px := read(8); !slices.Equal(px, []byte{0xaa, 0xaa, 0xaa, 0, 0xff, 0, 0, 0}) {
		t.Errorf("32-bit pixels = %x", px)
	}
	// BGR233 as the iDRAC8 quirk asks for: red max 7 shift 0, green 7 shift 3, blue 3 shift 6.
	pf8 := []byte{rfb.MsgSetPixelFormat, 0, 0, 0, 8, 8, 0, 1, 0, 7, 0, 7, 0, 3, 0, 3, 6, 0, 0, 0}
	_, _ = c.Write(append(pf8, fbur...))
	if px := read(2); px[0] != 5|5<<3|2<<6 || px[1] != 3<<6 {
		t.Errorf("8-bit pixels = %08b", px)
	}
}
