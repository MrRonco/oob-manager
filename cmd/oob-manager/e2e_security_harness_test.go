//go:build e2e

package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// plainHTTP is every fake BMC's port 80: like an iDRAC it redirects to HTTPS. It records
// the methods it was sent, so the security checks can be shown to send HEAD/GET only.
type plainHTTP struct {
	srv     *httptest.Server
	mu      sync.Mutex
	methods []string
}

func newPlainHTTP(t *testing.T) *plainHTTP {
	t.Helper()
	p := &plainHTTP{}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.methods = append(p.methods, r.Method)
		p.mu.Unlock()
		// The address the probe dialled, as an iDRAC names itself in the redirect.
		host, _, _ := strings.Cut(r.Host, ":")
		w.Header().Set("Location", "https://"+host+"/")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *plainHTTP) seen() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.methods...)
}

// dialCounter counts dials per address; the zero value is ready to use.
type dialCounter struct {
	mu sync.Mutex
	n  map[string]int
}

func (d *dialCounter) add(addr string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.n == nil {
		d.n = map[string]int{}
	}
	d.n[addr]++
}

func (d *dialCounter) count(addr string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.n[addr]
}

// probeTargets maps each BMC address and port the security checks may probe (TEST-NET) to
// its fake: 443 the mock BMC, 22 its SSH console, 80 the plain-HTTP fake, 5901 the
// R730XD's VNC server (an iDRAC8: the checks must never dial it, assertSecurityReadOnly).
func (s *stack) probeTargets() map[string]string {
	host := func(u string) string { return strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://") }
	m := map[string]string{"192.0.2.10:5901": s.vnc.Addr()}
	for _, srv := range e2eServers() {
		m[srv.address+":443"] = host(s.mocks[srv.id].URL())
		m[srv.address+":22"] = s.ssh[srv.id].Addr()
		m[srv.address+":80"] = host(s.plain.srv.URL)
	}
	m[extraAddress+":443"] = host(s.extra.URL())
	m[extraAddress+":22"] = s.extraSSH.Addr()
	m[extraAddress+":80"] = host(s.plain.srv.URL)
	return m
}

// dialProbe sends the security checks' handshake probes to the fakes; anything else is
// refused, so no real network is ever dialled.
func (s *stack) dialProbe(ctx context.Context, network, addr string) (net.Conn, error) {
	s.probeDials.add(addr)
	to, ok := s.probeTargets()[addr]
	if !ok {
		return nil, fmt.Errorf("e2e: unexpected security probe dial to %s", addr)
	}
	return (&net.Dialer{}).DialContext(ctx, network, to)
}
