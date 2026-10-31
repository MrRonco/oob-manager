package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionCookieFlags(t *testing.T) {
	c := SessionCookie("tok", 12*time.Hour)
	if c.Name != "__Host-oob_sid" || c.Value != "tok" || c.Path != "/" || c.Domain != "" {
		t.Fatalf("cookie identity wrong: %+v", c)
	}
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie flags wrong: %+v", c)
	}
	if c.MaxAge != int((12 * time.Hour).Seconds()) {
		t.Fatalf("MaxAge = %d", c.MaxAge)
	}
	if err := c.Valid(); err != nil {
		t.Fatal(err)
	}
}

func TestClearSessionCookie(t *testing.T) {
	c := ClearSessionCookie()
	if c.Name != SessionCookieName || c.MaxAge >= 0 || c.Value != "" || !c.Secure {
		t.Fatalf("clear cookie wrong: %+v", c)
	}
}

func TestSessionTokenFromRequest(t *testing.T) {
	r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
	if _, ok := SessionTokenFromRequest(r); ok {
		t.Fatal("token found on bare request")
	}
	r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: "abc", Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	if v, ok := SessionTokenFromRequest(r); !ok || v != "abc" {
		t.Fatalf("got %q %v", v, ok)
	}
}

func TestBearerToken(t *testing.T) {
	cases := []struct {
		header string
		want   string
		ok     bool
	}{
		{"", "", false},
		{"Basic abc", "", false},
		{"Bearer ", "", false},
		{"Bearer oobk_x", "oobk_x", true},
		{"bearer oobk_x", "oobk_x", true},
	}
	for _, tc := range cases {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		if tc.header != "" {
			r.Header.Set("Authorization", tc.header)
		}
		got, ok := BearerToken(r)
		if got != tc.want || ok != tc.ok {
			t.Errorf("BearerToken(%q) = %q %v", tc.header, got, ok)
		}
	}
}
