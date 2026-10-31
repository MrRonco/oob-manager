//go:build e2e

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/tlspin/tlspintest"
)

// The GELF inputs every stack can ship to (TEST-NET-1, listed in the stack's
// audit.gelf.allowed_networks); dialGELF sends them to local receivers. GELF shipping
// itself is off until a test (or the Playwright spec) turns it on in the browser.
const (
	gelfPlainAddr = "192.0.2.30:12201"
	gelfTLSAddr   = "192.0.2.31:6514"
	// gelfName is the DNS name the TLS input's certificate carries (with its IP).
	gelfName = "gelf.example.test"
)

// gelfInput is a local GELF receiver (plain TCP, or TLS with a CA-issued certificate
// sent with its chain). It keeps every frame's action (audit rows) or short message.
type gelfInput struct {
	addr string
	pair tlspintest.Pair // the TLS input's certificates (zero for plain)
	mu   sync.Mutex
	seen []string
}

func newGELFInput(t *testing.T, withTLS bool) *gelfInput {
	t.Helper()
	g := &gelfInput{}
	var ln net.Listener
	var err error
	if withTLS {
		g.pair = tlspintest.IssuedFor(t, gelfName, "192.0.2.31")
		ln, err = tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{g.pair.TLS()}, MinVersion: tls.VersionTLS12})
	} else {
		ln, err = (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	g.addr = ln.Addr().String()
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go g.read(c)
		}
	}()
	return g
}

func (g *gelfInput) read(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		frame, err := br.ReadBytes(0)
		if err != nil {
			return
		}
		var m map[string]any
		if json.Unmarshal(frame[:len(frame)-1], &m) != nil {
			continue
		}
		s, _ := m["_action"].(string)
		if s == "" {
			s, _ = m["short_message"].(string)
		}
		g.mu.Lock()
		g.seen = append(g.seen, s)
		g.mu.Unlock()
	}
}

func (g *gelfInput) has(sub string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, s := range g.seen {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func (g *gelfInput) count(sub string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, s := range g.seen {
		if strings.Contains(s, sub) {
			n++
		}
	}
	return n
}

// dialGELF reaches the local receivers for the two configured GELF addresses; anything
// else is refused (the destination policy has already checked the address).
func (s *stack) dialGELF(ctx context.Context, network, addr string) (net.Conn, error) {
	switch addr {
	case gelfPlainAddr:
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, s.gelfPlain.addr)
	case gelfTLSAddr:
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, network, s.gelfTLS.addr)
	}
	return nil, errors.New("e2e: unexpected GELF dial to " + addr)
}

// gelfYAML lets the stack ship to TEST-NET-1 (the default allows only private ranges).
const gelfYAML = "audit: { gelf: { allowed_networks: [192.0.2.0/24] } }\n"
