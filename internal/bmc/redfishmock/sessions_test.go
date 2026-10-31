package redfishmock

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

type reqOpts struct {
	token string
	basic bool
	body  string
}

// reply is a fully read response (no body left to close).
type reply struct {
	StatusCode int
	Header     http.Header
}

func do(t *testing.T, s *Server, method, path string, o reqOpts) (reply, []byte) {
	t.Helper()
	var body io.Reader
	if o.body != "" {
		body = strings.NewReader(o.body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, s.URL()+path, body)
	if err != nil {
		t.Fatal(err)
	}
	if o.basic {
		req.SetBasicAuth(User, Password)
	}
	if o.token != "" {
		req.Header.Set("X-Auth-Token", o.token)
	}
	resp, err := client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return reply{StatusCode: resp.StatusCode, Header: resp.Header}, b
}

func login(t *testing.T, s *Server, collection string) (token, location string) {
	t.Helper()
	resp, b := do(t, s, http.MethodPost, collection, reqOpts{body: `{"UserName":"` + User + `","Password":"` + Password + `"}`})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create session: %d %s", resp.StatusCode, b)
	}
	var doc struct {
		ID string `json:"@odata.id"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || doc.ID != resp.Header.Get("Location") {
		t.Fatalf("session body %s vs Location %q", b, resp.Header.Get("Location"))
	}
	return resp.Header.Get("X-Auth-Token"), resp.Header.Get("Location")
}

func TestSessionLifecycle(t *testing.T) {
	for fixture, coll := range map[string]string{
		"idrac8-r730xd": "/redfish/v1/Sessions",
		"idrac9-r240":   "/redfish/v1/SessionService/Sessions",
	} {
		t.Run(fixture, func(t *testing.T) {
			s := New(t, FixtureDir(t, fixture))
			if s.SessionsURI() != coll {
				t.Fatalf("SessionsURI = %q", s.SessionsURI())
			}
			tok, loc := login(t, s, coll)
			if len(tok) < 32 || !strings.HasPrefix(loc, coll+"/") || s.LiveSessions() != 1 {
				t.Fatalf("token %q location %q live %d", tok, loc, s.LiveSessions())
			}
			if resp, _ := do(t, s, http.MethodGet, "/redfish/v1/Systems", reqOpts{token: tok}); resp.StatusCode != 200 {
				t.Fatalf("GET with token: %d", resp.StatusCode)
			}
			if resp, _ := do(t, s, http.MethodGet, "/redfish/v1/Systems", reqOpts{token: "bogus"}); resp.StatusCode != 401 {
				t.Fatalf("GET with a bogus token: %d", resp.StatusCode)
			}
			if resp, _ := do(t, s, http.MethodDelete, loc, reqOpts{}); resp.StatusCode != 401 {
				t.Fatalf("DELETE without token: %d", resp.StatusCode)
			}
			if resp, _ := do(t, s, http.MethodDelete, loc, reqOpts{token: tok}); resp.StatusCode != http.StatusNoContent {
				t.Fatalf("DELETE: %d", resp.StatusCode)
			}
			if resp, _ := do(t, s, http.MethodGet, "/redfish/v1/Systems", reqOpts{token: tok}); resp.StatusCode != 401 {
				t.Fatalf("deleted token still accepted: %d", resp.StatusCode)
			}
			st := s.SessionStats()
			if st.Created != 1 || st.Deleted != 1 || st.TokenGETs != 1 || st.BasicGETs != 0 || s.LiveSessions() != 0 {
				t.Fatalf("stats %+v", st)
			}
			if s.OtherWrites() != 0 {
				t.Fatalf("session calls counted as other writes: %d", s.OtherWrites())
			}
		})
	}
}

func TestSessionFailuresAndOptions(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac9-r240"), WithTokenOnly())
	coll := s.SessionsURI()
	if resp, _ := do(t, s, http.MethodPost, coll, reqOpts{body: `{"UserName":"` + User + `","Password":"nope"}`}); resp.StatusCode != 401 {
		t.Fatalf("bad password: %d", resp.StatusCode)
	}
	if resp, _ := do(t, s, http.MethodPost, coll, reqOpts{body: `not json`}); resp.StatusCode != 400 {
		t.Fatalf("bad body: %d", resp.StatusCode)
	}
	if resp, _ := do(t, s, http.MethodGet, "/redfish/v1/Systems", reqOpts{basic: true}); resp.StatusCode != 401 {
		t.Fatalf("token-only mock accepted basic auth: %d", resp.StatusCode)
	}
	tok, _ := login(t, s, coll)
	s.ExpireSessions()
	if resp, _ := do(t, s, http.MethodGet, "/redfish/v1/Systems", reqOpts{token: tok}); resp.StatusCode != 401 {
		t.Fatalf("expired token: %d", resp.StatusCode)
	}
	if resp, _ := do(t, s, http.MethodDelete, coll+"/999", reqOpts{token: tok}); resp.StatusCode != 401 {
		t.Fatalf("DELETE with expired token: %d", resp.StatusCode)
	}
	tok2, _ := login(t, s, coll)
	if resp, _ := do(t, s, http.MethodDelete, coll+"/999", reqOpts{token: tok2}); resp.StatusCode != 404 {
		t.Fatalf("DELETE unknown session: %d", resp.StatusCode)
	}
	if resp, _ := do(t, s, http.MethodPatch, "/redfish/v1/Systems", reqOpts{token: tok2}); resp.StatusCode != 405 {
		t.Fatalf("PATCH: %d", resp.StatusCode)
	}
	if s.OtherWrites() != 2 {
		t.Fatalf("other writes = %d, want 2 (DELETE unknown + PATCH)", s.OtherWrites())
	}

	off := New(t, FixtureDir(t, "idrac8-r730xd"), WithoutSessions())
	if resp, _ := do(t, off, http.MethodPost, "/redfish/v1/Sessions", reqOpts{body: `{}`}); resp.StatusCode != 405 {
		t.Fatalf("sessions disabled: %d", resp.StatusCode)
	}
}

func TestRequestRecordsAuthKind(t *testing.T) {
	s := New(t, FixtureDir(t, "idrac9-r240"))
	tok, _ := login(t, s, s.SessionsURI())
	do(t, s, http.MethodGet, "/redfish/v1", reqOpts{})
	do(t, s, http.MethodGet, "/redfish/v1/Systems", reqOpts{basic: true})
	do(t, s, http.MethodGet, "/redfish/v1/Systems", reqOpts{token: tok})
	var kinds []string
	for _, r := range s.Requests() {
		kinds = append(kinds, r.Auth)
	}
	if strings.Join(kinds, ",") != "none,none,basic,token" {
		t.Fatalf("auth kinds %v", kinds)
	}
}
