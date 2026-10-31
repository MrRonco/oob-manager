package tofu

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestProofRoundTripAndBinding(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	p, err := NewProver([]byte(strings.Repeat("k", 32)), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	c := Claim{Session: "sess-1", Purpose: "/settings/servers", Kind: KindTLS, Addr: "192.0.2.12", Port: 443, Value: strings.Repeat("ab", 32)}
	proof := p.Sign(c)
	if err := p.Verify(c, proof); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(Claim) Claim{
		"other session": func(c Claim) Claim { c.Session = "sess-2"; return c },
		"other purpose": func(c Claim) Claim { c.Purpose = "/settings/servers/other/pin"; return c },
		"other kind":    func(c Claim) Claim { c.Kind = KindVNC; return c },
		"other address": func(c Claim) Claim { c.Addr = "192.0.2.13"; return c },
		"other port":    func(c Claim) Claim { c.Port = 8443; return c },
		"other value":   func(c Claim) Claim { c.Value = strings.Repeat("cd", 32); return c },
	} {
		if err := p.Verify(mut(c), proof); !errors.Is(err, ErrProof) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, bad := range []string{"", "x", "123", "1.zz", proof + "0", "-5." + strings.Repeat("0", 64)} {
		if err := p.Verify(c, bad); !errors.Is(err, ErrProof) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	now = now.Add(ProofTTL + time.Second)
	if err := p.Verify(c, proof); !errors.Is(err, ErrProofExpired) {
		t.Fatalf("expired: %v", err)
	}
	if _, err := NewProver([]byte("short"), nil); err == nil {
		t.Fatal("short key accepted")
	}
}

func TestProofFromTheFuture(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	p, _ := NewProver([]byte(strings.Repeat("k", 32)), func() time.Time { return now })
	c := Claim{Session: "s", Kind: KindSSH, Addr: "192.0.2.12", Port: 22, Value: "ssh-ed25519 AAAA"}
	proof := p.Sign(c)
	now = now.Add(-time.Minute)
	if err := p.Verify(c, proof); !errors.Is(err, ErrProof) {
		t.Fatalf("future proof: %v", err)
	}
}
