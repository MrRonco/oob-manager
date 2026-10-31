// Package sshtest is a fake BMC SSH service for tests: an in-process
// golang.org/x/crypto/ssh server that behaves like an iDRAC's `console com2`. It accepts
// one password, answers exec "console com2" (and nothing else), echoes the client's
// input like a host at a login prompt, ends the console on the iDRAC quit key (Ctrl-\)
// and records every request it receives, so tests can prove what the app sent.
package sshtest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Test-only login. The values exist only in tests.
const (
	User     = "oob_op"
	Password = "fake BMC ssh password" //nolint:gosec // G101: test fixture, not a credential
	// Command is the only exec request the fake accepts (the iDRAC serial console).
	Command = "console com2"
	// Banner is written when the console starts (unless Options.Silent).
	Banner  = "Connected to Serial Device 2. To end type: ^\\\r\n"
	quitKey = 0x1c
)

// Options shape the fake.
type Options struct {
	// RSA uses an RSA host key instead of ed25519.
	RSA bool
	// Legacy makes the server offer only what an old iDRAC8 offers: host key algorithm
	// ssh-rsa (SHA-1) and key exchange diffie-hellman-group14-sha1. It implies RSA.
	Legacy bool
	// Silent sends nothing at all (a host whose serial redirection is off).
	Silent bool
	// Transcript is written right after Banner, as if the host had already printed it
	// (the README screenshots: a boot tail and a login prompt). Ignored when Silent.
	Transcript string
	// KeyboardInteractive authenticates with one echo-off prompt instead of "password".
	KeyboardInteractive bool
	// User and Password override the accepted login (default User, Password).
	User, Password string
}

// Request is one channel request the fake received.
type Request struct {
	Type    string
	Payload []byte
}

// Server is a running fake.
type Server struct {
	ln     net.Listener
	signer ssh.Signer
	opts   Options

	mu       sync.Mutex
	requests []Request
	input    []byte
	authN    int
	sessions int
	active   int
	conns    []net.Conn
}

// New starts a fake on 127.0.0.1 and stops it at test cleanup.
func New(t testing.TB, opts Options) *Server {
	t.Helper()
	signer := newSigner(t, opts.RSA || opts.Legacy)
	if opts.Legacy {
		as, ok := signer.(ssh.AlgorithmSigner)
		if !ok {
			t.Fatal("sshtest: RSA signer without algorithm support")
		}
		var err error
		signer, err = ssh.NewSignerWithAlgorithms(as, []string{ssh.KeyAlgoRSA})
		if err != nil {
			t.Fatal(err)
		}
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if opts.User == "" {
		opts.User = User
	}
	if opts.Password == "" {
		opts.Password = Password
	}
	s := &Server{ln: ln, signer: signer, opts: opts}
	go s.accept()
	t.Cleanup(s.Close)
	return s
}

func newSigner(t testing.TB, useRSA bool) ssh.Signer {
	t.Helper()
	var key any
	if useRSA {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	} else {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key = k
	}
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Addr is the listen address (host:port).
func (s *Server) Addr() string { return s.ln.Addr().String() }

// HostKeyLine is the fake's public host key as an authorized-key line (config
// ssh_host_key).
func (s *Server) HostKeyLine() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(s.signer.PublicKey())))
}

// Close stops the listener and drops every connection.
func (s *Server) Close() {
	_ = s.ln.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.conns {
		_ = c.Close()
	}
}

// Requests returns every channel request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// RequestTypes returns the types of Requests, in order.
func (s *Server) RequestTypes() []string {
	var out []string
	for _, r := range s.Requests() {
		out = append(out, r.Type)
	}
	return out
}

// Input returns every byte the client sent on console channels.
func (s *Server) Input() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.input...)
}

// AuthAttempts counts password (or keyboard-interactive) attempts, right or wrong.
func (s *Server) AuthAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authN
}

// Sessions counts console sessions started (exec "console com2" accepted).
func (s *Server) Sessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions
}

// Active counts console sessions still open.
func (s *Server) Active() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}
