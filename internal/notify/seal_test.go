package notify

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func testSealer(t *testing.T) *Sealer {
	t.Helper()
	s, err := NewSealer(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSealRoundTripAndBinding(t *testing.T) {
	s := testSealer(t)
	tg := target(KindPushover, DefaultPushoverURL)
	blob, err := s.Seal(tg, sec("app-token-value", "user-key-value", ""))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("app-token-value")) {
		t.Fatal("plaintext in the sealed blob")
	}
	got, err := s.Open(tg, blob)
	if err != nil || got.Token.Reveal() != "app-token-value" || got.User.Reveal() != "user-key-value" || !got.Password.IsZero() {
		t.Fatalf("open: %v", err)
	}
	moved := []func(Target) Target{
		func(t Target) Target { t.ID = "other"; return t },
		func(t Target) Target { t.Kind = KindGotify; return t },
		func(t Target) Target { t.URL = "https://evil.example.net/1/messages.json"; return t },
	}
	for i, mv := range moved {
		if _, err := s.Open(mv(tg), blob); !errors.Is(err, ErrUnseal) {
			t.Errorf("case %d: secrets opened for a different id/kind/url", i)
		}
	}
	tampered := bytes.Clone(blob)
	tampered[len(tampered)-1] ^= 1
	if _, err := s.Open(tg, tampered); !errors.Is(err, ErrUnseal) {
		t.Error("tampered blob opened")
	}
	if _, err := s.Open(tg, blob[:5]); !errors.Is(err, ErrUnseal) {
		t.Error("short blob opened")
	}
	other, _ := NewSealer(bytes.Repeat([]byte{8}, 32))
	if _, err := other.Open(tg, blob); !errors.Is(err, ErrUnseal) {
		t.Error("opened with another key")
	}
	if _, err := NewSealer([]byte("short")); err == nil {
		t.Error("short key accepted")
	}
}

func TestSecretsNeverFormat(t *testing.T) {
	s := sec("tok-123", "usr-456", "pw-789")
	for _, out := range []string{fmtAll(s), fmtAll(TargetView{HasSecret: true})} {
		for _, leak := range []string{"tok-123", "usr-456", "pw-789"} {
			if strings.Contains(out, leak) {
				t.Fatalf("secret printed: %s", out)
			}
		}
	}
}
