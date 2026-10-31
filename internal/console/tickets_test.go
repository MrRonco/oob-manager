package console

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }
func newClock() *fakeClock               { return &fakeClock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)} }

func TestTicketSingleUseAndBound(t *testing.T) {
	clk := newClock()
	ts := newTickets(clk.now, DefaultTicketTTL)
	sess := SessionHash("cookie-a")
	g := Grant{ServerID: "r1", UserID: "u1", Username: "admin", Session: sess}
	raw, err := ts.issue(g)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ts.redeem(raw, "r1", sess)
	if err != nil || got.UserID != "u1" {
		t.Fatalf("redeem = %+v, %v", got, err)
	}
	if _, err := ts.redeem(raw, "r1", sess); !errors.Is(err, ErrTicketInvalid) {
		t.Fatalf("replay: %v", err)
	}

	cases := map[string]func(raw string) error{
		"other server":  func(raw string) error { _, err := ts.redeem(raw, "r2", sess); return err },
		"other session": func(raw string) error { _, err := ts.redeem(raw, "r1", SessionHash("cookie-b")); return err },
		"expired": func(raw string) error {
			clk.add(DefaultTicketTTL + time.Second)
			_, err := ts.redeem(raw, "r1", sess)
			return err
		},
	}
	for name, try := range cases {
		t.Run(name, func(t *testing.T) {
			raw, _ := ts.issue(g)
			if err := try(raw); !errors.Is(err, ErrTicketInvalid) {
				t.Fatalf("err = %v", err)
			}
			if _, err := ts.redeem(raw, "r1", sess); !errors.Is(err, ErrTicketInvalid) {
				t.Fatal("a failed redemption must burn the ticket")
			}
		})
	}
	for _, bad := range []string{"", "!!!", "c2hvcnQ"} {
		if _, err := ts.redeem(bad, "r1", sess); !errors.Is(err, ErrTicketInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func TestTicketStoreIsBounded(t *testing.T) {
	clk := newClock()
	ts := newTickets(clk.now, DefaultTicketTTL)
	for range maxTickets {
		if _, err := ts.issue(Grant{ServerID: "r1"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ts.issue(Grant{ServerID: "r1"}); !errors.Is(err, ErrTooManyTicket) {
		t.Fatalf("err = %v", err)
	}
	clk.add(time.Minute) // all expired: swept on the next issue
	if _, err := ts.issue(Grant{ServerID: "r1"}); err != nil {
		t.Fatal(err)
	}
}

// TestSessionHashDomainIsPinned: the domain keeps the pre-rename project name
// (oob-console). Tickets live in memory only, but the label is left as it was so the
// rename changes no hash or key anywhere.
func TestSessionHashDomainIsPinned(t *testing.T) {
	if SessionHash("cookie") != sha256.Sum256([]byte("oob-console/console-ticket/v1\x00cookie")) {
		t.Fatal("console ticket session-hash domain changed")
	}
}
