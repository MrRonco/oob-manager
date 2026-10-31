package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestNewTOTPEnrollment(t *testing.T) {
	e, err := NewTOTPEnrollment("oob-manager", "morgan")
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Secret) < 32 {
		t.Fatalf("secret too short: %d base32 chars (want >= 160 bits)", len(e.Secret))
	}
	for _, want := range []string{"otpauth://totp/", "issuer=oob-manager", "period=30", "digits=6"} {
		if !strings.Contains(e.URL, want) {
			t.Errorf("URL %q missing %q", e.URL, want)
		}
	}
	if strings.Contains(e.String(), e.Secret) {
		t.Fatal("String() leaks the secret")
	}
	if _, err := NewTOTPEnrollment("", "morgan"); err == nil {
		t.Fatal("empty issuer accepted")
	}
}

func codeAt(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, at, totpValidateOpts())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestMatchTOTP(t *testing.T) {
	e, _ := NewTOTPEnrollment("oob", "u")
	now := time.Unix(1_800_000_000, 0)
	step := now.Unix() / 30
	cases := []struct {
		name     string
		code     string
		lastStep int64
		wantStep int64
		wantOK   bool
	}{
		{"current", codeAt(t, e.Secret, now), 0, step, true},
		{"previous step (skew)", codeAt(t, e.Secret, now.Add(-30*time.Second)), 0, step - 1, true},
		{"next step (skew)", codeAt(t, e.Secret, now.Add(30*time.Second)), 0, step + 1, true},
		{"too old", codeAt(t, e.Secret, now.Add(-90*time.Second)), 0, 0, false},
		{"replay same step", codeAt(t, e.Secret, now), step, 0, false},
		{"replay older step", codeAt(t, e.Secret, now.Add(-30*time.Second)), step, 0, false},
		{"not digits", "12a456", 0, 0, false},
		{"too short", "12345", 0, 0, false},
		{"too long", "1234567", 0, 0, false},
		{"unicode digits", "١٢٣٤٥٦", 0, 0, false},
		{"empty", "", 0, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := matchTOTP(e.Secret, tc.code, now, tc.lastStep)
			if ok != tc.wantOK || got != tc.wantStep {
				t.Fatalf("matchTOTP = %d, %v; want %d, %v", got, ok, tc.wantStep, tc.wantOK)
			}
		})
	}
}

func TestMatchTOTPBadSecret(t *testing.T) {
	if _, ok := matchTOTP("not base32 !!", "123456", time.Now(), 0); ok {
		t.Fatal("bad secret matched")
	}
}
