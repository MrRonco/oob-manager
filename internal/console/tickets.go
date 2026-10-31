package console

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// Ticket limits.
const (
	DefaultTicketTTL = 30 * time.Second
	maxTickets       = 64
	ticketBytes      = 32
)

// Ticket errors.
var (
	ErrTicketInvalid = errors.New("console: ticket is invalid, expired or already used")
	ErrTooManyTicket = errors.New("console: too many outstanding tickets")
)

// Grant is what a ticket authorizes: one WebSocket for one server, for the user and
// browser session that asked for it.
type Grant struct {
	ServerID string
	UserID   string
	Username string
	Role     string
	SrcIP    string
	// Session is a hash of the session cookie value the ticket was issued to; the WS
	// upgrade must present the same session.
	Session  [32]byte
	Takeover bool
}

type ticketEntry struct {
	grant   Grant
	expires time.Time
}

// tickets is a small in-memory store of single-use tickets, keyed by SHA-256 of the
// ticket so the raw value is never kept.
type tickets struct {
	mu  sync.Mutex
	now func() time.Time
	ttl time.Duration
	m   map[[32]byte]ticketEntry
}

func newTickets(now func() time.Time, ttl time.Duration) *tickets {
	return &tickets{now: now, ttl: ttl, m: map[[32]byte]ticketEntry{}}
}

// issue mints a ticket for g, valid for the TTL.
func (t *tickets) issue(g Grant) (string, error) {
	var raw [ticketBytes]byte
	_, _ = rand.Read(raw[:]) // crypto/rand.Read never fails (Go 1.24+)
	key := sha256.Sum256(raw[:])
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sweepLocked()
	if len(t.m) >= maxTickets {
		return "", ErrTooManyTicket
	}
	t.m[key] = ticketEntry{grant: g, expires: t.now().Add(t.ttl)}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// redeem consumes a ticket. It succeeds once, before expiry, for the same server and
// browser session it was issued to; any attempt (even a failing one) burns it.
func (t *tickets) redeem(raw, serverID string, session [32]byte) (Grant, error) {
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil || len(b) != ticketBytes {
		return Grant{}, ErrTicketInvalid
	}
	key := sha256.Sum256(b)
	t.mu.Lock()
	defer t.mu.Unlock()
	e, ok := t.m[key]
	delete(t.m, key)
	switch {
	case !ok, t.now().After(e.expires), e.grant.ServerID != serverID,
		subtle.ConstantTimeCompare(e.grant.Session[:], session[:]) != 1:
		return Grant{}, ErrTicketInvalid
	}
	return e.grant, nil
}

func (t *tickets) sweepLocked() {
	now := t.now()
	for k, e := range t.m {
		if now.After(e.expires) {
			delete(t.m, k)
		}
	}
}

// SessionHash is the binding a ticket keeps for a session cookie value. The domain keeps
// the pre-rename project name (oob-console): tickets are in memory only, but no hash or
// key label changed with the rename (TestSessionHashDomainIsPinned).
func SessionHash(cookie string) [32]byte {
	return sha256.Sum256([]byte("oob-console/console-ticket/v1\x00" + cookie))
}
