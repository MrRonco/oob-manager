package auth

import (
	"crypto/subtle"
	"errors"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// TOTP parameters: RFC 6238 defaults that every authenticator app supports.
const (
	totpPeriod     = 30
	totpDigits     = 6
	totpSkewSteps  = 1  // accept one step either side for clock drift
	totpSecretSize = 20 // 160-bit secret (RFC 4226 recommendation)
)

// TOTPEnrollment is what the user scans. Secret is base32. Both fields are secrets:
// show them once, never log them.
type TOTPEnrollment struct {
	Secret string
	URL    string // otpauth:// provisioning URI (for a QR code)
}

// String redacts the enrollment so it cannot leak through %v or slog.
func (TOTPEnrollment) String() string { return "TOTPEnrollment{[redacted]}" }

// NewTOTPEnrollment creates a fresh random secret for account under issuer.
func NewTOTPEnrollment(issuer, account string) (TOTPEnrollment, error) {
	if issuer == "" || account == "" {
		return TOTPEnrollment{}, errors.New("auth: TOTP issuer and account are required")
	}
	k, err := totp.Generate(totp.GenerateOpts{
		Issuer: issuer, AccountName: account, Period: totpPeriod,
		SecretSize: totpSecretSize, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		return TOTPEnrollment{}, err
	}
	return TOTPEnrollment{Secret: k.Secret(), URL: k.URL()}, nil
}

func totpValidateOpts() totp.ValidateOpts {
	return totp.ValidateOpts{Period: totpPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
}

// matchTOTP checks code against the steps around now that are strictly after lastStep,
// and returns the matching step. The caller must then record it with
// UserRepo.AdvanceTOTPStep (compare-and-set) before treating the code as accepted.
// Every candidate is compared in constant time; the loop never exits early.
func matchTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	if !wellFormedCode(code) {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	var matched int64
	for s := cur - totpSkewSteps; s <= cur+totpSkewSteps; s++ {
		want, err := totp.GenerateCodeCustom(secret, time.Unix(s*totpPeriod, 0), totpValidateOpts())
		if err != nil {
			return 0, false
		}
		eq := subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1
		if eq && s > lastStep && matched == 0 {
			matched = s
		}
	}
	return matched, matched != 0
}

func wellFormedCode(code string) bool {
	if len(code) != totpDigits {
		return false
	}
	for i := range len(code) {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}
