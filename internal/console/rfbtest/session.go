package rfbtest

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"

	"oob-manager/internal/console/rfb"
)

func contextBackground() context.Context { return context.Background() }

func readFull(r io.Reader, b []byte) (int, error) { return io.ReadFull(r, b) }

// serve runs one RFB 3.8 session: version, VNC auth, init, then the message loop.
func (s *Server) serve(c net.Conn) {
	if _, err := c.Write([]byte("RFB 003.008\n")); err != nil {
		return
	}
	var ver [12]byte
	if _, err := io.ReadFull(c, ver[:]); err != nil {
		return // a banner probe closes here
	}
	if _, err := c.Write([]byte{1, rfb.SecVNCAuth}); err != nil {
		return
	}
	var pick [1]byte
	if _, err := io.ReadFull(c, pick[:]); err != nil || pick[0] != rfb.SecVNCAuth {
		return
	}
	ok, err := s.checkAuth(c)
	if err != nil {
		return
	}
	if !ok {
		s.update(func(r *record) { r.authFailures++ })
		// SecurityResult failed + reason "Authentication failed" (21 bytes).
		_, _ = c.Write(append([]byte{0, 0, 0, 1, 0, 0, 0, 21}, "Authentication failed"...))
		return
	}
	if _, err := c.Write([]byte{0, 0, 0, 0}); err != nil {
		return
	}
	var clientInit [1]byte
	if _, err := io.ReadFull(c, clientInit[:]); err != nil {
		return
	}
	if _, err := c.Write(s.serverInit().Marshal()); err != nil {
		return
	}
	s.update(func(r *record) { r.authOK++; r.active++ })
	defer s.update(func(r *record) { r.active-- })
	s.loop(bufio.NewReader(c), c)
}

// pixfmt is the client's current pixel format (what the update is encoded in).
type pixfmt struct {
	bpp                             byte
	bigEndian                       bool
	redMax, greenMax, blueMax       uint16
	redShift, greenShift, blueShift byte
}

// truecolour32 is the format the server announces in ServerInit.
var truecolour32 = pixfmt{bpp: 32, redMax: 255, greenMax: 255, blueMax: 255, redShift: 16, greenShift: 8}

// value packs a 16-bit-per-channel colour into the format's pixel value.
func (pf pixfmt) value(r, g, b uint32) uint32 {
	scale := func(c uint32, maxV uint16) uint32 { return (c*uint32(maxV) + 0x7fff) / 0xffff }
	return scale(r, pf.redMax)<<pf.redShift | scale(g, pf.greenMax)<<pf.greenShift | scale(b, pf.blueMax)<<pf.blueShift
}

// appendPixel appends v in the format's byte size and order.
func (pf pixfmt) appendPixel(dst []byte, v uint32) []byte {
	n := max(int(pf.bpp)/8, 1)
	for i := range n {
		shift := 8 * i
		if pf.bigEndian {
			shift = 8 * (n - 1 - i)
		}
		dst = append(dst, byte(v>>shift)) //nolint:gosec // G115: byte extraction
	}
	return dst
}

// loop reads client messages and answers every non-incremental update request with the
// frame (Options.Frame, else solid red) in the client's pixel format.
func (s *Server) loop(r *bufio.Reader, w io.Writer) {
	pf := truecolour32
	for {
		t, err := r.ReadByte()
		if err != nil {
			return
		}
		s.update(func(rec *record) { rec.types = append(rec.types, t) })
		if !s.handle(t, r, w, &pf) {
			return
		}
	}
}

func (s *Server) handle(t byte, r *bufio.Reader, w io.Writer, pf *pixfmt) bool {
	switch t {
	case rfb.MsgSetPixelFormat:
		b := make([]byte, 19)
		if _, err := io.ReadFull(r, b); err != nil {
			return false
		}
		*pf = pixfmt{bpp: b[3], bigEndian: b[5] != 0, redMax: binary.BigEndian.Uint16(b[7:]),
			greenMax: binary.BigEndian.Uint16(b[9:]), blueMax: binary.BigEndian.Uint16(b[11:]),
			redShift: b[13], greenShift: b[14], blueShift: b[15]}
	case rfb.MsgSetEncodings:
		return s.readEncodings(r)
	case rfb.MsgFramebufferUpdateRequest:
		b := make([]byte, 9)
		if _, err := io.ReadFull(r, b); err != nil {
			return false
		}
		if b[0] == 0 {
			return s.sendFrame(w, *pf)
		}
	case rfb.MsgKeyEvent:
		b := make([]byte, 7)
		if _, err := io.ReadFull(r, b); err != nil {
			return false
		}
		s.update(func(rec *record) {
			rec.keys = append(rec.keys, KeyEvent{Down: b[0] != 0, Sym: binary.BigEndian.Uint32(b[3:])})
		})
	case rfb.MsgPointerEvent:
		if _, err := io.CopyN(io.Discard, r, 5); err != nil {
			return false
		}
		s.update(func(rec *record) { rec.pointers++ })
	case rfb.MsgClientCutText:
		return s.readCutText(r)
	default:
		return false // unknown: a real server would desynchronise; stop
	}
	return true
}

func (s *Server) readEncodings(r *bufio.Reader) bool {
	hdr := make([]byte, 3)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return false
	}
	n := int(binary.BigEndian.Uint16(hdr[1:]))
	raw := make([]byte, 4*n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return false
	}
	encs := make([]int32, n)
	for i := range n {
		encs[i] = int32(binary.BigEndian.Uint32(raw[4*i:])) //nolint:gosec // G115: signed encodings
	}
	s.update(func(rec *record) { rec.encodings = append(rec.encodings, encs) })
	return true
}

func (s *Server) readCutText(r *bufio.Reader) bool {
	hdr := make([]byte, 7)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return false
	}
	n := binary.BigEndian.Uint32(hdr[3:])
	if n > 1<<20 {
		return false
	}
	text := make([]byte, n)
	if _, err := io.ReadFull(r, text); err != nil {
		return false
	}
	s.update(func(rec *record) { rec.cutTexts = append(rec.cutTexts, string(text)) })
	return true
}

// sendFrame writes one FramebufferUpdate: a single Raw rectangle covering the screen.
func (s *Server) sendFrame(w io.Writer, pf pixfmt) bool {
	width, height := int(s.opts.Width), int(s.opts.Height)
	msg := []byte{0, 0, 0, 1} // FramebufferUpdate, padding, 1 rectangle
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, s.opts.Width)
	msg = binary.BigEndian.AppendUint16(msg, s.opts.Height)
	msg = binary.BigEndian.AppendUint32(msg, 0) // Raw
	if f := s.opts.Frame; f != nil {
		o := f.Bounds().Min
		for y := range height {
			for x := range width {
				r, g, b, _ := f.At(o.X+x, o.Y+y).RGBA()
				msg = pf.appendPixel(msg, pf.value(r, g, b))
			}
		}
	} else {
		red := pf.appendPixel(nil, uint32(pf.redMax)<<pf.redShift)
		for range width * height {
			msg = append(msg, red...)
		}
	}
	if _, err := w.Write(msg); err != nil {
		return false
	}
	s.update(func(rec *record) { rec.updates++ })
	return true
}
