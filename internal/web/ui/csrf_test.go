package ui

import (
	"strings"
	"testing"
	"time"
)

func testSigner(now *time.Time) csrfSigner {
	return csrfSigner{key: []byte(strings.Repeat("k", 32)), ttl: time.Hour, now: func() time.Time { return *now }}
}

func TestCSRFRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := testSigner(&now)
	tok := c.issue(formLogin, "pre:abc")
	if !c.verify(tok, formLogin, "pre:abc") {
		t.Fatal("fresh token rejected")
	}
}

func TestCSRFRejects(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := testSigner(&now)
	tok := c.issue(formLogin, "pre:abc")
	cases := map[string]func() bool{
		"other form":    func() bool { return c.verify(tok, formLogout, "pre:abc") },
		"other binding": func() bool { return c.verify(tok, formLogin, "pre:xyz") },
		"empty":         func() bool { return c.verify("", formLogin, "pre:abc") },
		"garbage":       func() bool { return c.verify("!!!not-base64", formLogin, "pre:abc") },
		"truncated":     func() bool { return c.verify(tok[:10], formLogin, "pre:abc") },
		"tampered":      func() bool { return c.verify(flipLast(tok), formLogin, "pre:abc") },
		"empty binding": func() bool { return c.verify(c.issue(formLogin, ""), formLogin, "") },
		"other key": func() bool {
			o := c
			o.key = []byte(strings.Repeat("x", 32))
			return o.verify(tok, formLogin, "pre:abc")
		},
	}
	for name, fn := range cases {
		if fn() {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestCSRFExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	c := testSigner(&now)
	tok := c.issue(formTOTP, "sess:x")
	now = now.Add(time.Hour + time.Second)
	if c.verify(tok, formTOTP, "sess:x") {
		t.Fatal("expired token accepted")
	}
	now = time.Unix(1_800_000_000, 0).Add(-2 * time.Minute)
	if c.verify(tok, formTOTP, "sess:x") {
		t.Fatal("token from the future accepted")
	}
}

func flipLast(s string) string {
	b := []byte(s)
	if b[len(b)-1] == 'A' {
		b[len(b)-1] = 'B'
	} else {
		b[len(b)-1] = 'A'
	}
	return string(b)
}
