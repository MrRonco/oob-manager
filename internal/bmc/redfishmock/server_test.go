package redfishmock

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func client() *http.Client {
	// Test-only: the mock's cert is self-signed; production code pins instead.
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test client
	}, Timeout: 5 * time.Second}
}

func get(t *testing.T, s *Server, method, path string, auth bool) (int, []byte) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, s.URL()+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if auth {
		req.SetBasicAuth(User, Password)
	}
	resp, err := client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestServesFixtureByPath(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac8-r730xd"))
	code, body := get(t, s, http.MethodGet, "/redfish/v1/Chassis/System.Embedded.1/Thermal?$select=Fans", true)
	if code != 200 || !strings.Contains(string(body), "System Board Fan1 RPM") {
		t.Fatalf("code %d body %.80s", code, body)
	}
	code, _ = get(t, s, http.MethodGet, "/redfish/v1/", true)
	if code != 200 {
		t.Fatalf("root with slash: %d", code)
	}
}

func TestSynthesisesTopLevelCollections(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac9-r240"))
	code, body := get(t, s, http.MethodGet, "/redfish/v1/Systems", true)
	if code != 200 {
		t.Fatalf("code %d", code)
	}
	var col struct {
		Members []struct {
			ID string `json:"@odata.id"`
		}
	}
	if err := json.Unmarshal(body, &col); err != nil {
		t.Fatal(err)
	}
	if len(col.Members) != 1 || col.Members[0].ID != "/redfish/v1/Systems/System.Embedded.1" {
		t.Fatalf("members: %+v", col.Members)
	}
	if code, _ := get(t, s, http.MethodGet, "/redfish/v1/Fabrics", true); code != 404 {
		t.Fatalf("collection with no members must 404, got %d", code)
	}
}

func TestAuthMethodsAndOverrides(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac8-r730xd"),
		WithOverlay("/redfish/v1/Extra", `{"Id":"x"}`),
		WithMissing("/redfish/v1/Chassis/System.Embedded.1/Power"),
		WithStatus("/redfish/v1/Managers/iDRAC.Embedded.1", 503),
		WithDelay("/redfish/v1/Systems/System.Embedded.1", 50*time.Millisecond),
	)
	if code, _ := get(t, s, http.MethodGet, "/redfish/v1", false); code != 200 {
		t.Fatalf("root must be open: %d", code)
	}
	if code, _ := get(t, s, http.MethodGet, "/redfish/v1/Systems", false); code != 401 {
		t.Fatalf("no auth: %d", code)
	}
	if code, _ := get(t, s, http.MethodPost, "/redfish/v1", true); code != 405 {
		t.Fatalf("POST: %d", code)
	}
	if code, b := get(t, s, http.MethodGet, "/redfish/v1/Extra", true); code != 200 || !strings.Contains(string(b), `"x"`) {
		t.Fatalf("overlay: %d", code)
	}
	if code, _ := get(t, s, http.MethodGet, "/redfish/v1/Chassis/System.Embedded.1/Power", true); code != 404 {
		t.Fatalf("missing: %d", code)
	}
	if code, _ := get(t, s, http.MethodGet, "/redfish/v1/Managers/iDRAC.Embedded.1", true); code != 503 {
		t.Fatalf("status: %d", code)
	}
	start := time.Now()
	get(t, s, http.MethodGet, "/redfish/v1/Systems/System.Embedded.1", true)
	if time.Since(start) < 50*time.Millisecond {
		t.Fatal("delay not applied")
	}
	if code, _ := get(t, s, http.MethodGet, "/redfish/v1/../../etc/passwd", true); code != 404 {
		t.Fatalf("traversal: %d", code)
	}

	reqs := s.Requests()
	if len(reqs) != 8 || reqs[2].Method != http.MethodPost {
		t.Fatalf("requests: %+v", reqs)
	}
	if s.NonGET() != 1 {
		t.Fatalf("NonGET = %d", s.NonGET())
	}
	if len(s.PinSHA256()) != 64 {
		t.Fatalf("pin %q", s.PinSHA256())
	}
}

func TestPathToFile(t *testing.T) {
	cases := map[string]string{
		"/redfish/v1":  "root.json",
		"/redfish/v1/": "root.json",
		"/redfish/v1/Chassis/System.Embedded.1/Power": "Chassis_System.Embedded.1_Power.json",
		"/other":             "",
		"/redfish/v1/a/../b": "",
	}
	for in, want := range cases {
		if got := pathToFile(in); got != want {
			t.Errorf("pathToFile(%q) = %q, want %q", in, got, want)
		}
	}
}
