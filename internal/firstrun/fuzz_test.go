package firstrun

import (
	"strings"
	"testing"
	"time"
)

// FuzzSetupCode: only the real code (in any case, with or without spaces and dashes)
// claims the setup; any other input is refused and leaves it claimable.
func FuzzSetupCode(f *testing.F) {
	f.Add("ABCD-EFGH", false)
	f.Add("", true)
	f.Add("    ", false)
	f.Fuzz(func(t *testing.T, guess string, useReal bool) {
		now := time.Unix(1792000000, 0)
		s, code, err := NewSetup(func() time.Time { return now }, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if useReal {
			guess = strings.ToLower(code) // the real code, as typed in lower case
		}
		want := normalise(guess) == normalise(code)
		if got := s.Claim(guess); got != want {
			t.Fatalf("Claim(%q) = %v, want %v", guess, got, want)
		}
		if !want && !s.Claim(code) {
			t.Fatal("a refused guess blocked the real code")
		}
	})
}
