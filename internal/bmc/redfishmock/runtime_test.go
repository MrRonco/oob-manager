package redfishmock

import (
	"net/http"
	"testing"
)

func TestRuntimeOverlayAndDown(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac9-r240"))
	c := s.ts.Client()
	get := func(path string, auth bool) int {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, s.URL()+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if auth {
			req.SetBasicAuth(User, Password)
		}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	const sys = "/redfish/v1/Systems/System.Embedded.1"
	if b, ok := s.Fixture(sys); !ok || len(b) == 0 {
		t.Fatal("fixture not found")
	}
	if _, ok := s.Fixture("/nope"); ok {
		t.Fatal("unknown fixture found")
	}
	s.SetOverlay(sys, `{"Id":"x"}`)
	if get(sys, false) != http.StatusUnauthorized || get(sys, true) != http.StatusOK {
		t.Fatal("overlay auth")
	}
	s.ClearOverlay(sys)
	s.SetDown(true)
	if get("/redfish/v1", false) != http.StatusServiceUnavailable {
		t.Fatal("down root answered")
	}
	s.SetDown(false)
	if get("/redfish/v1", false) != http.StatusOK {
		t.Fatal("up again")
	}
}
