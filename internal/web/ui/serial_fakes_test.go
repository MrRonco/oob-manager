package ui

import (
	"context"
	"sync"

	"oob-manager/internal/console"
)

type fakeSerial struct {
	mu       sync.Mutex
	status   map[string]console.SerialStatus
	issueErr error
	grants   []console.Grant
	serveErr error
	served   []servedCall
}

func newFakeSerial() *fakeSerial {
	return &fakeSerial{status: map[string]console.SerialStatus{
		"r730xd": {Configured: true, Transport: "bmcssh", Supported: true, HasLogin: true, HasHostKey: true, Legacy: true},
	}}
}

func (f *fakeSerial) Status(id string) console.SerialStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status[id]
}

func (f *fakeSerial) setStatus(id string, st console.SerialStatus) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status[id] = st
}

func (f *fakeSerial) Issue(g console.Grant) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.issueErr != nil {
		return "", f.issueErr
	}
	f.grants = append(f.grants, g)
	return "stk-" + g.ServerID, nil
}

// ServeSerial plays a tiny session: "connected", one output chunk, then it echoes one
// browser message back with the same type.
func (f *fakeSerial) ServeSerial(ctx context.Context, ticket, id string, session [32]byte, p console.SerialPeer,
	check console.Watchdog) error {
	f.mu.Lock()
	f.served = append(f.served, servedCall{ticket: ticket, server: id, session: session, check: check})
	err := f.serveErr
	f.mu.Unlock()
	if err != nil {
		return err
	}
	if err = p.Write(ctx, console.MessageText, []byte(`{"type":"connected"}`)); err != nil {
		return err
	}
	if err = p.Write(ctx, console.MessageBinary, []byte("login: ")); err != nil {
		return err
	}
	typ, b, err := p.Read(ctx)
	if err != nil {
		return err
	}
	return p.Write(ctx, typ, b)
}

func (f *fakeSerial) lastGrant() (console.Grant, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.grants) == 0 {
		return console.Grant{}, false
	}
	return f.grants[len(f.grants)-1], true
}

func (f *fakeSerial) calls() []servedCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]servedCall(nil), f.served...)
}
