// Package rfbtest is a fake BMC VNC (RFB 3.8) server for tests and the e2e harness:
// version handshake, VNC authentication with a known password, a tiny solid-colour
// framebuffer, and a record of every client message it received. Production code
// never imports it.
package rfbtest

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"image"
	"net"
	"sync"
	"testing"

	"oob-manager/internal/console/rfb"
)

// Password is the VNC password the fake server accepts unless Options.Password is set.
const Password = "Fx1!vnc8" //nolint:gosec // G101: test fixture, not a credential

// Default framebuffer.
const (
	DefaultWidth  = 64
	DefaultHeight = 48
	DefaultName   = "fake-bmc"
)

// Options configure a Server.
type Options struct {
	Password string
	// TLS wraps the listener in TLS with a generated self-signed certificate.
	TLS bool
	// RSAKeyExchangeOnly (with TLS) emulates an iDRAC8 2.8x VNC port: TLS 1.2, an RSA
	// certificate and only RSA key-exchange AES-GCM suites, no ECDHE.
	RSAKeyExchangeOnly bool
	Width              uint16
	Height             uint16
	Name               string
	// Frame is the screen sent on every full update (the README screenshots); nil sends a
	// solid red frame. Width and Height default to its size.
	Frame image.Image
}

// KeyEvent is one recorded RFB KeyEvent.
type KeyEvent struct {
	Down bool
	Sym  uint32
}

// Server is a running fake VNC server listening on 127.0.0.1.
type Server struct {
	opts Options
	ln   net.Listener
	pin  string
	wg   sync.WaitGroup

	mu    sync.Mutex
	rec   record
	conns map[net.Conn]bool
}

type record struct {
	connections  int
	authOK       int
	authFailures int
	types        []byte
	encodings    [][]int32
	keys         []KeyEvent
	pointers     int
	cutTexts     []string
	updates      int
	active       int
}

// New starts a server; it is closed by t.Cleanup.
func New(t testing.TB, o Options) *Server {
	t.Helper()
	s, err := Start(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// Start starts a server without a testing.TB (the dev harness); call Close.
func Start(o Options) (*Server, error) {
	o = withDefaults(o)
	ln, err := (&net.ListenConfig{}).Listen(contextBackground(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &Server{opts: o, ln: ln, conns: map[net.Conn]bool{}}
	if o.TLS {
		cert, err := selfSigned(o.RSAKeyExchangeOnly)
		if err != nil {
			_ = ln.Close()
			return nil, err
		}
		sum := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
		s.pin = hex.EncodeToString(sum[:])
		s.ln = tls.NewListener(ln, serverTLS(cert, o.RSAKeyExchangeOnly))
	}
	s.wg.Go(s.accept)
	return s, nil
}

func withDefaults(o Options) Options {
	if o.Password == "" {
		o.Password = Password
	}
	if o.Frame != nil && o.Width == 0 && o.Height == 0 {
		b := o.Frame.Bounds()
		o.Width, o.Height = uint16(min(b.Dx(), 4096)), uint16(min(b.Dy(), 4096)) //nolint:gosec // G115: clamped
	}
	if o.Width == 0 {
		o.Width = DefaultWidth
	}
	if o.Height == 0 {
		o.Height = DefaultHeight
	}
	if o.Name == "" {
		o.Name = DefaultName
	}
	return o
}

// Addr is host:port of the listener.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Port is the TCP port of the listener.
func (s *Server) Port() int { return s.ln.Addr().(*net.TCPAddr).Port } //nolint:errcheck,forcetypeassert // always TCP

// PinSHA256 is the SPKI pin of the TLS certificate ("" without TLS).
func (s *Server) PinSHA256() string { return s.pin }

// Close stops the listener and every connection, and waits for them.
func (s *Server) Close() {
	_ = s.ln.Close()
	s.mu.Lock()
	for c := range s.conns {
		_ = c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *Server) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns[c] = true
		s.rec.connections++
		s.mu.Unlock()
		s.wg.Go(func() {
			defer s.drop(c)
			s.serve(c)
		})
	}
}

func (s *Server) drop(c net.Conn) {
	_ = c.Close()
	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
}

func (s *Server) serverInit() rfb.ServerInit {
	return rfb.ServerInit{Width: s.opts.Width, Height: s.opts.Height, Name: s.opts.Name,
		PixelFormat: [16]byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0}}
}

// checkAuth sends a challenge and verifies the DES response.
func (s *Server) checkAuth(c net.Conn) (bool, error) {
	var ch [16]byte
	_, _ = rand.Read(ch[:])
	if _, err := c.Write(ch[:]); err != nil {
		return false, err
	}
	var resp [16]byte
	if _, err := readFull(c, resp[:]); err != nil {
		return false, err
	}
	want := rfb.VNCAuthResponse(ch, []byte(s.opts.Password))
	return subtle.ConstantTimeCompare(resp[:], want[:]) == 1, nil
}
