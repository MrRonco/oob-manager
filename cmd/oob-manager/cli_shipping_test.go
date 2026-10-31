package main

import (
	"bufio"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// gelfCapture is a GELF TCP input that keeps every NUL-terminated frame it receives.
type gelfCapture struct {
	mu     sync.Mutex
	frames []string
}

func newGELFCapture(t *testing.T) (*gelfCapture, string) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	g := &gelfCapture{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				for {
					f, err := r.ReadString(0)
					if err != nil {
						return
					}
					g.mu.Lock()
					g.frames = append(g.frames, f)
					g.mu.Unlock()
				}
			}()
		}
	}()
	return g, ln.Addr().String()
}

func (g *gelfCapture) has(sub string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, f := range g.frames {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}

// TestCLIAuditRowsReachTheLogServer: audit rows written by CLI commands (bootstrap-admin,
// admin-recover) are shipped to the GELF target before the command exits, so the
// break-glass row leaves the box and drill 7's head comparison holds (review H2-M1).
func TestCLIAuditRowsReachTheLogServer(t *testing.T) {
	g, addr := newGELFCapture(t)
	d := newDeployment(t, testGELFAddr)
	withGELF := func(e *env) { e.gelfDial = gelfDialTo(addr) }
	bootstrapIn(t, d, withGELF)
	if !g.has("admin.bootstrap") {
		t.Fatal("the bootstrap-admin audit row did not reach the log server")
	}
	var out, errOut syncBuffer
	e := cliEnv(context.Background(), strings.NewReader(""), &out, &errOut)
	withGELF(&e)
	if rc := run([]string{"oob-manager", "admin-recover", "-config", d.configPath, "-username", "admin", "-yes"}, e); rc != 0 {
		t.Fatalf("admin-recover: %d %s", rc, errOut.String())
	}
	if !g.has("admin.recover") {
		t.Fatal("the admin-recover audit row did not reach the log server")
	}
}

// TestCLIShippingFailureOnlyWarns: an unreachable log server delays the command by at
// most the flush timeout and never fails it.
func TestCLIShippingFailureOnlyWarns(t *testing.T) {
	d := newDeployment(t, testGELFAddr)
	bootstrapIn(t, d, func(e *env) {
		e.gelfDial = func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }
	})
	var out, errOut syncBuffer
	e := cliEnv(context.Background(), strings.NewReader(""), &out, &errOut)
	e.gelfDial = func(context.Context, string, string) (net.Conn, error) { return nil, net.ErrClosed }
	start := time.Now()
	if rc := run([]string{"oob-manager", "admin-recover", "-config", d.configPath, "-username", "admin", "-yes"}, e); rc != 0 {
		t.Fatalf("admin-recover failed because shipping failed: %d %s", rc, errOut.String())
	}
	if took := time.Since(start); took > cliShipFlush+5*time.Second {
		t.Fatalf("took %s", took)
	}
	if !strings.Contains(errOut.String(), "log server") {
		t.Errorf("no warning about the log server: %s", errOut.String())
	}
}
