package console

import (
	"unicode"

	"oob-manager/internal/config"
	"oob-manager/internal/console/rfb"
	"oob-manager/internal/secrets"
)

// PasswordWarnings checks a VNC password against what the protocol and iDRAC accept.
// It never returns the password or any part of it.
func PasswordWarnings(kind config.BMCKind, pw secrets.Secret) []string {
	if pw.IsZero() {
		return nil
	}
	b := pw.Bytes()
	defer clear(b)
	var out []string
	switch {
	case len(b) > rfb.VNCAuthKeyLen:
		out = append(out, "The VNC password is longer than 8 characters; VNC authentication uses only the first 8.")
	case len(b) < rfb.VNCAuthKeyLen:
		out = append(out, "The VNC password is shorter than 8 characters; use exactly 8 random characters.")
	}
	if kind == config.KindIDRAC9 && !complexEnough(string(b[:min(len(b), rfb.VNCAuthKeyLen)])) {
		out = append(out, "iDRAC9 requires the VNC password to contain upper and lower case letters, a digit and a special character.")
	}
	return out
}

func complexEnough(s string) bool {
	var up, low, digit, special bool
	for _, r := range s {
		switch {
		case unicode.IsUpper(r):
			up = true
		case unicode.IsLower(r):
			low = true
		case unicode.IsDigit(r):
			digit = true
		default:
			special = true
		}
	}
	return up && low && digit && special
}
