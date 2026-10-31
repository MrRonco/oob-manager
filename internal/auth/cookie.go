package auth

import (
	"net/http"
	"strings"
	"time"
)

// SessionCookieName uses the __Host- prefix: the browser only accepts it with Secure,
// Path=/ and no Domain, so a sibling host cannot plant or overwrite it.
const SessionCookieName = "__Host-oob_sid"

// SessionCookie builds the session cookie for token. maxAge should be the session's
// remaining absolute lifetime.
func SessionCookie(token string, maxAge time.Duration) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(maxAge.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// ClearSessionCookie deletes the session cookie (logout).
func ClearSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// SessionTokenFromRequest returns the session cookie value, if any.
func SessionTokenFromRequest(r *http.Request) (string, bool) {
	c, err := r.Cookie(SessionCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}

// BearerToken extracts an RFC 6750 bearer token from the Authorization header.
func BearerToken(r *http.Request) (string, bool) {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return "", false
	}
	return tok, true
}
