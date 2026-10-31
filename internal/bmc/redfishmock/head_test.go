package redfishmock

import (
	"bytes"
	"net/http"
	"testing"
)

func TestHeadIsAReadNotAWrite(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac9-r240"))
	if code, body := get(t, s, http.MethodHead, "/redfish/v1/Systems/System.Embedded.1", true); code != http.StatusOK || len(body) != 0 {
		t.Fatalf("HEAD fixture: %d %q", code, body)
	}
	if code, _ := get(t, s, http.MethodHead, "/redfish/v1/Systems/System.Embedded.1", false); code != http.StatusUnauthorized {
		t.Fatalf("HEAD needs auth like GET: %d", code)
	}
	if code, _ := get(t, s, http.MethodHead, "/wsman", false); code != http.StatusNotFound {
		t.Fatalf("no WS-Management unless enabled: %d", code)
	}
	if s.OtherWrites() != 0 {
		t.Fatalf("HEAD counted as a write: %d", s.OtherWrites())
	}
	if n := s.Heads(); n != 3 {
		t.Fatalf("Heads = %d", n)
	}
}

func TestWithWSMan(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac9-r240"), WithWSMan())
	if code, _ := get(t, s, http.MethodHead, "/wsman", false); code != http.StatusUnauthorized {
		t.Fatalf("WS-Management answers 401 without credentials: %d", code)
	}
	if code, _ := get(t, s, http.MethodHead, "/oob-manager-absent", false); code != http.StatusNotFound {
		t.Fatalf("other paths outside Redfish: %d", code)
	}
	if code, _ := get(t, s, http.MethodGet, "/wsman", false); code != http.StatusUnauthorized {
		t.Fatalf("GET /wsman: %d", code)
	}
	if s.OtherWrites() != 0 {
		t.Fatalf("writes %d", s.OtherWrites())
	}
}

func TestQuietHandshakesKeepsOtherLines(t *testing.T) {
	var b bytes.Buffer
	q := quietHandshakes{&b}
	for _, line := range []string{"http: TLS handshake error from 127.0.0.1:1: EOF\n", "http: panic serving 127.0.0.1:1: boom\n"} {
		if n, err := q.Write([]byte(line)); err != nil || n != len(line) {
			t.Fatalf("write %d %v", n, err)
		}
	}
	if b.String() != "http: panic serving 127.0.0.1:1: boom\n" {
		t.Fatalf("kept %q", b.String())
	}
}
