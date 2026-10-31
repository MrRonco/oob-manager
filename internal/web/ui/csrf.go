package ui

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"net/http"
	"time"
)

// Form names: a token issued for one form is useless on another.
const (
	formLogin  = "login"
	formTOTP   = "totp"
	formLogout = "logout"
	formEnroll = "enroll"
	formReveal = "reveal"
)

// csrfField is the hidden input carrying the token.
const csrfField = "csrf_token"

// preCookieName holds the random value that pre-session forms (login, enrolment) are
// bound to. __Host- for the same reasons as the session cookie.
const preCookieName = "__Host-oob_pre"

// csrfClockSkew tolerates a token issued slightly "in the future" by a stepped clock.
const csrfClockSkew = time.Minute

// csrfSigner issues synchronizer tokens of the HMAC kind (OWASP CSRF cheat sheet): the
// token is ts ‖ HMAC-SHA256(key, form ‖ binding ‖ ts), where binding is the session
// cookie value (or the pre-session cookie value). A token is only valid for that form,
// that session and ttl, so a token leaked from one session cannot be replayed in another
// and nothing has to be stored server-side.
type csrfSigner struct {
	key []byte
	ttl time.Duration
	now func() time.Time
}

func (c csrfSigner) mac(form, binding string, ts int64) []byte {
	m := hmac.New(sha256.New, c.key)
	var buf [8]byte
	for _, part := range []string{form, binding} {
		binary.BigEndian.PutUint64(buf[:], uint64(len(part))) // #nosec G115 -- lengths are non-negative
		m.Write(buf[:])
		m.Write([]byte(part))
	}
	binary.BigEndian.PutUint64(buf[:], uint64(ts)) // #nosec G115 -- bit pattern only
	m.Write(buf[:])
	return m.Sum(nil)
}

// issue returns a token for form bound to binding.
func (c csrfSigner) issue(form, binding string) string {
	ts := c.now().Unix()
	out := make([]byte, 8, 8+sha256.Size)
	binary.BigEndian.PutUint64(out, uint64(ts)) // #nosec G115 -- bit pattern only
	out = append(out, c.mac(form, binding, ts)...)
	return base64.RawURLEncoding.EncodeToString(out)
}

// verify checks token for form and binding in constant time. An empty binding never
// verifies: every form must be tied to a cookie.
func (c csrfSigner) verify(token, form, binding string) bool {
	if binding == "" || token == "" {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != 8+sha256.Size {
		return false
	}
	ts := int64(binary.BigEndian.Uint64(raw[:8])) // #nosec G115 -- bit pattern only
	issued := time.Unix(ts, 0)
	now := c.now()
	if now.Sub(issued) > c.ttl || issued.Sub(now) > csrfClockSkew {
		return false
	}
	return hmac.Equal(raw[8:], c.mac(form, binding, ts))
}

// randomToken returns 256 random bits, base64url. crypto/rand.Read never fails (Go 1.24+).
func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// preCookie returns the pre-session cookie value, minting and setting one if absent.
func preCookie(w http.ResponseWriter, r *http.Request, ttl time.Duration) string {
	if c, err := r.Cookie(preCookieName); err == nil && len(c.Value) == 43 {
		return c.Value
	}
	v := randomToken()
	http.SetCookie(w, &http.Cookie{
		Name: preCookieName, Value: v, Path: "/", MaxAge: int(ttl.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
	return v
}

// clearPreCookie drops the pre-session cookie once a session exists, so no value set
// before sign-in (by anyone) survives it (plan 06 §3.1 fixation checklist). A later
// pre-session page mints a fresh one.
func clearPreCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: preCookieName, Value: "", Path: "/", MaxAge: -1,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

// preBinding is the CSRF binding for pre-session forms ("" when there is no cookie).
func preBinding(r *http.Request) string {
	c, err := r.Cookie(preCookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	return "pre:" + c.Value
}

// sessionBinding is the CSRF binding for forms of a (pending or full) session.
func sessionBinding(token string) string {
	if token == "" {
		return ""
	}
	return "sess:" + token
}
