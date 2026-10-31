package ui

import (
	"context"
	"errors"
	"net"
	"sync"

	"oob-manager/internal/bmc"
	"oob-manager/internal/console"
	"oob-manager/internal/secrets"
)

type fakeConsoles struct {
	mu       sync.Mutex
	status   map[string]console.Status
	issueErr error
	grants   []console.Grant
	serveErr error
	served   []servedCall
}

type servedCall struct {
	ticket, server string
	session        [32]byte
	check          console.Watchdog
}

func newFakeConsoles() *fakeConsoles {
	return &fakeConsoles{status: map[string]console.Status{
		"r730xd": {Configured: true, HasPassword: true, TLS: true, Probe: console.Probe{State: console.ProbeOK}},
	}}
}

func (f *fakeConsoles) Status(id string) console.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status[id]
}

func (f *fakeConsoles) Issue(g console.Grant) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issueErr != nil {
		return "", f.issueErr
	}
	f.grants = append(f.grants, g)
	return "tkt-" + g.ServerID, nil
}

// Serve plays a tiny RFB-ish exchange: it writes "hello" and echoes one read back.
func (f *fakeConsoles) Serve(_ context.Context, ticket, id string, session [32]byte, conn net.Conn, check console.Watchdog) error {
	f.mu.Lock()
	f.served = append(f.served, servedCall{ticket: ticket, server: id, session: session, check: check})
	err := f.serveErr
	f.mu.Unlock()
	defer conn.Close()
	if err != nil {
		return err
	}
	if _, err = conn.Write([]byte("hello")); err != nil {
		return err
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		return err
	}
	_, err = conn.Write(buf[:n])
	return err
}

func (f *fakeConsoles) lastGrant() (console.Grant, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.grants) == 0 {
		return console.Grant{}, false
	}
	return f.grants[len(f.grants)-1], true
}

func (f *fakeConsoles) calls() []servedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]servedCall(nil), f.served...)
}

type fakeKVM struct {
	mu        sync.Mutex
	available map[string]bool
	err       error
	launches  int
}

func (f *fakeKVM) Available(id string) bool { return f.available[id] }

func (f *fakeKVM) Launch(context.Context, string) (secrets.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return secrets.Secret{}, f.err
	}
	f.launches++
	return secrets.New("https://192.0.2.11/console?tempPassword=Tmp-pass-1&tempUsername=tmpkvm1&username=oob_op"), nil
}

var errFakeBMC = errors.New("x: " + string(bmc.ClassTimeout))

// withKVMCapability marks a fake fleet server as offering GetKVMSession.
func withKVMCapability(v ServerView) ServerView {
	f := v.Capabilities.Flags()
	f.KVMLaunch = true
	v.Capabilities = bmc.NewCapabilities(bmc.CapabilityParams{Flags: f})
	v.HasCapabilities = true
	return v
}
