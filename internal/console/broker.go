package console

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// takeoverWait bounds how long a takeover waits for the old session to close (the BMC
// accepts one VNC session, so the old TCP connection must be gone first).
const takeoverWait = 5 * time.Second

// ErrInUse is returned when a server already has an active console.
var ErrInUse = errors.New("console: in use")

// InUseError carries who holds the console.
type InUseError struct{ Active Active }

func (e *InUseError) Error() string {
	return fmt.Sprintf("console: in use by %s since %s", e.Active.Username, e.Active.Since.UTC().Format(time.RFC3339))
}

// Unwrap makes errors.Is(err, ErrInUse) work.
func (e *InUseError) Unwrap() error { return ErrInUse }

// Active describes the console session holding a server.
type Active struct {
	SessionID string
	ServerID  string
	UserID    string
	Username  string
	Since     time.Time
}

// endReason is the cause a session's context is cancelled with; it becomes the audit
// "reason" of console.vnc.stop.
type endReason string

func (r endReason) Error() string { return string(r) }

// End reasons.
const (
	reasonBrowserClosed endReason = "browser_closed"
	reasonBMCClosed     endReason = "bmc_closed"
	reasonProtocol      endReason = "protocol"
	reasonIdle          endReason = "idle_timeout"
	reasonMax           endReason = "max_session"
	reasonTakenOver     endReason = "taken_over"
	reasonShutdown      endReason = "shutdown"
	reasonSession       endReason = "session_ended"
	reasonStepUp        endReason = "stepup_expired"
	reasonForbidden     endReason = "forbidden"
	// reasonConfigChanged: the server's console settings, address or credentials changed
	// (or it was removed) in Settings → Servers.
	reasonConfigChanged endReason = "config_changed"
)

type slot struct {
	info   Active
	cancel context.CancelCauseFunc
	done   chan struct{}
}

// broker enforces one active console per server.
type broker struct {
	mu    sync.Mutex
	slots map[string]*slot
}

func newBroker() *broker { return &broker{slots: map[string]*slot{}} }

func (b *broker) active(serverID string) (Active, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s, ok := b.slots[serverID]; ok {
		return s.info, true
	}
	return Active{}, false
}

// claim takes the server's slot for info. With takeover it ends the current holder
// and waits for it to release; otherwise a held slot is an *InUseError. The returned
// context is cancelled (with an endReason cause) by a takeover or shutdown; release
// must be called when the session ends.
func (b *broker) claim(parent context.Context, info Active, takeover bool) (context.Context, func(), *Active, error) {
	var prev *Active
	for range 3 {
		b.mu.Lock()
		cur, held := b.slots[info.ServerID]
		if !held {
			ctx, cancel := context.WithCancelCause(parent)
			s := &slot{info: info, cancel: cancel, done: make(chan struct{})}
			b.slots[info.ServerID] = s
			b.mu.Unlock()
			return ctx, b.releaser(s), prev, nil
		}
		b.mu.Unlock()
		if !takeover {
			return nil, nil, nil, &InUseError{Active: cur.info}
		}
		was := cur.info
		prev = &was
		cur.cancel(reasonTakenOver)
		select {
		case <-cur.done:
		case <-time.After(takeoverWait):
		case <-parent.Done():
			return nil, nil, nil, parent.Err()
		}
	}
	return nil, nil, nil, &InUseError{Active: *prev}
}

func (b *broker) releaser(s *slot) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			s.cancel(context.Canceled)
			b.mu.Lock()
			if b.slots[s.info.ServerID] == s {
				delete(b.slots, s.info.ServerID)
			}
			b.mu.Unlock()
			close(s.done)
		})
	}
}

// end cancels the session on serverID (if any) with reason and waits (bounded) for it
// to release.
func (b *broker) end(serverID string, reason endReason, wait time.Duration) {
	b.mu.Lock()
	s, ok := b.slots[serverID]
	b.mu.Unlock()
	if !ok {
		return
	}
	s.cancel(reason)
	select {
	case <-s.done:
	case <-time.After(wait):
	}
}

// endAll cancels every session with reason and waits (bounded) for them to release.
func (b *broker) endAll(reason endReason, wait time.Duration) {
	b.mu.Lock()
	all := make([]*slot, 0, len(b.slots))
	for _, s := range b.slots {
		all = append(all, s)
	}
	b.mu.Unlock()
	deadline := time.After(wait)
	for _, s := range all {
		s.cancel(reason)
	}
	for _, s := range all {
		select {
		case <-s.done:
		case <-deadline:
			return
		}
	}
}
