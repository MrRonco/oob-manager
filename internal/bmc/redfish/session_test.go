package redfish

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/secrets"
)

// fastReauth keeps the 401 backoff short in tests.
func fastReauth() Option { return withReauthBackoff(time.Millisecond) }

func TestSessionIsCreatedOnceAndReused(t *testing.T) {
	for _, fx := range []string{idrac8, idrac9} {
		t.Run(fx, func(t *testing.T) {
			s := mockFor(t, fx, redfishmock.WithTokenOnly())
			d := driverFor(t, s)
			if _, err := d.Probe(testCtx(t)); err != nil {
				t.Fatalf("Probe: %v", err)
			}
			if _, err := d.Snapshot(testCtx(t)); err != nil {
				t.Fatalf("Snapshot: %v", err)
			}
			st := s.SessionStats()
			if st.Created != 1 || st.BasicGETs != 0 || st.TokenGETs < 5 || s.LiveSessions() != 1 {
				t.Fatalf("stats %+v live %d", st, s.LiveSessions())
			}
			for _, r := range s.Requests() {
				if r.Method == http.MethodGet && r.Path != serviceRoot && r.Auth != redfishmock.AuthToken {
					t.Fatalf("GET %s sent with auth %q", r.Path, r.Auth)
				}
				if r.Method == http.MethodPost && r.Path != s.SessionsURI() {
					t.Fatalf("POST to %s", r.Path)
				}
			}
			assertNoWrites(t, s)
		})
	}
}

func TestConcurrentRequestsShareOneSession(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithTokenOnly(), redfishmock.WithDelay(sessionsPath9, 50*time.Millisecond))
	d := driverFor(t, s)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			var v map[string]any
			errs <- d.GetJSON(testCtx(t), "/redfish/v1/Systems", &v)
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if st := s.SessionStats(); st.Created != 1 {
		t.Fatalf("created %d sessions for concurrent requests", st.Created)
	}
}

const sessionsPath9 = "/redfish/v1/SessionService/Sessions"

func TestExpiredSessionIsRecreatedOncePerRequest(t *testing.T) {
	s := mockFor(t, idrac8, redfishmock.WithTokenOnly())
	d := driverFor(t, s, fastReauth())
	if _, err := d.Probe(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	s.ExpireSessions()
	if _, err := d.Snapshot(testCtx(t)); err != nil {
		t.Fatalf("Snapshot after BMC expired the session: %v", err)
	}
	if st := s.SessionStats(); st.Created != 2 || s.LiveSessions() != 1 {
		t.Fatalf("stats %+v live %d", st, s.LiveSessions())
	}
}

func TestPersistent401IsNotRetriedInALoop(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithTokenOnly(),
		redfishmock.WithStatus("/redfish/v1/Systems", http.StatusUnauthorized))
	d := driverFor(t, s, fastReauth())
	var v map[string]any
	err := d.GetJSON(testCtx(t), "/redfish/v1/Systems", &v)
	if !errors.Is(err, bmc.ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
	var gets, posts int
	for _, r := range s.Requests() {
		switch {
		case r.Method == http.MethodGet && r.Path == "/redfish/v1/Systems":
			gets++
		case r.Method == http.MethodPost:
			posts++
		}
	}
	if gets != 2 || posts != 2 {
		t.Fatalf("one request must give at most one re-login: %d GETs, %d logins", gets, posts)
	}
}

func TestReauthBackoffHonoursContext(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithStatus("/redfish/v1/Systems", http.StatusUnauthorized))
	d := driverFor(t, s, withReauthBackoff(time.Hour))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var v map[string]any
	start := time.Now()
	err := d.GetJSON(ctx, "/redfish/v1/Systems", &v)
	if !errors.Is(err, bmc.ErrTimeout) || time.Since(start) > 5*time.Second {
		t.Fatalf("backoff ignored the deadline: %v after %v", err, time.Since(start))
	}
}

func TestBadPasswordFailsLoginWithoutLeaking(t *testing.T) {
	s := mockFor(t, idrac8)
	cfg := configFor(s)
	cfg.Password = "wrong-secret"
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.Probe(testCtx(t))
	if !errors.Is(err, bmc.ErrAuth) || strings.Contains(err.Error(), "wrong-secret") {
		t.Fatalf("want ErrAuth without the password, got %v", err)
	}
}

func TestNoSessionServiceIsUnsupported(t *testing.T) {
	s := mockFor(t, idrac8, redfishmock.WithoutSessions())
	d := driverFor(t, s)
	_, err := d.Probe(testCtx(t))
	if !errors.Is(err, bmc.ErrUnsupported) || !strings.Contains(err.Error(), "basic") {
		t.Fatalf("want ErrUnsupported naming the basic fallback, got %v", err)
	}
	noLink := mockFor(t, idrac9, redfishmock.WithOverlay(serviceRoot, `{"Systems":{"@odata.id":"/redfish/v1/Systems"}}`))
	if _, err := driverFor(t, noLink).Probe(testCtx(t)); !errors.Is(err, bmc.ErrUnsupported) {
		t.Fatalf("root without Links.Sessions: %v", err)
	}
}

func TestBasicAuthFallback(t *testing.T) {
	s := mockFor(t, idrac8, redfishmock.WithoutSessions())
	cfg := configFor(s)
	cfg.Auth = AuthBasic
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Snapshot(testCtx(t)); err != nil {
		t.Fatalf("Snapshot over basic auth: %v", err)
	}
	if st := s.SessionStats(); st.Created != 0 || st.TokenGETs != 0 || st.BasicGETs == 0 {
		t.Fatalf("stats %+v", st)
	}
	if err := d.Close(testCtx(t)); err != nil || s.NonGET() != 0 {
		t.Fatalf("basic mode must never write: close %v, non-GET %d", err, s.NonGET())
	}
}

func TestCloseDeletesOurSession(t *testing.T) {
	s := mockFor(t, idrac9)
	d := driverFor(t, s)
	if _, err := d.Probe(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(testCtx(t)); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if st := s.SessionStats(); st.Deleted != 1 || s.LiveSessions() != 0 {
		t.Fatalf("stats %+v live %d", st, s.LiveSessions())
	}
	var del []string
	for _, r := range s.Requests() {
		if r.Method == http.MethodDelete {
			del = append(del, r.Path+" "+r.Auth)
		}
	}
	if len(del) != 1 || del[0] != sessionsPath9+"/1 token" {
		t.Fatalf("DELETEs %v", del)
	}
	if err := d.Close(testCtx(t)); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	var v map[string]any
	if err := d.GetJSON(testCtx(t), "/redfish/v1/Systems", &v); !errors.Is(err, bmc.ErrInvalidConfig) {
		t.Fatalf("closed driver must refuse requests: %v", err)
	}
	if s.SessionStats().Created != 1 {
		t.Fatal("closed driver created a new session")
	}
}

func TestCloseWithoutSessionSendsNothing(t *testing.T) {
	s := mockFor(t, idrac9)
	if err := driverFor(t, s).Close(testCtx(t)); err != nil || len(s.Requests()) != 0 {
		t.Fatalf("close %v, requests %+v", err, s.Requests())
	}
}

func TestCloseToleratesAnExpiredSession(t *testing.T) {
	s := mockFor(t, idrac8)
	d := driverFor(t, s)
	if _, err := d.Probe(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	s.ExpireSessions()
	if err := d.Close(testCtx(t)); err != nil {
		t.Fatalf("a session the BMC already dropped is not a close error: %v", err)
	}
}

func TestSetCredentialsLogsOutAndUsesNewOnes(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithTokenOnly())
	cfg := configFor(s)
	cfg.Password = "old-wrong"
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Probe(testCtx(t)); !errors.Is(err, bmc.ErrAuth) {
		t.Fatalf("old password: %v", err)
	}
	if err := d.SetCredentials(testCtx(t), redfishmock.User, secrets.New(redfishmock.Password)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Probe(testCtx(t)); err != nil {
		t.Fatalf("new password: %v", err)
	}
	if err := d.SetCredentials(testCtx(t), redfishmock.User, secrets.New(redfishmock.Password)); err != nil {
		t.Fatal(err)
	}
	if st := s.SessionStats(); st.Deleted != 1 || s.LiveSessions() != 0 {
		t.Fatalf("credential change must delete the old session: %+v", st)
	}
	if err := d.SetCredentials(testCtx(t), "", secrets.New("x")); !errors.Is(err, bmc.ErrInvalidConfig) {
		t.Fatalf("empty username: %v", err)
	}
}

func TestSessionURIValidation(t *testing.T) {
	coll := "/redfish/v1/Sessions"
	cases := map[string]string{
		"/redfish/v1/Sessions/7":                       "/redfish/v1/Sessions/7",
		"https://192.0.2.10/redfish/v1/Sessions/7":     "/redfish/v1/Sessions/7",
		"https://192.0.2.10:443/redfish/v1/Sessions/7": "/redfish/v1/Sessions/7",
		"/redfish/v1/Sessions/7/":                      "/redfish/v1/Sessions/7",
		"https://evil.example/redfish/v1/Sessions/7":   "",
		"/redfish/v1/Systems/7":                        "",
		"/redfish/v1/Sessions":                         "",
		"/redfish/v1/Sessions/7/x":                     "",
		"/redfish/v1/Sessions/../Systems":              "",
		"/redfish/v1/Sessions/7?x=1":                   "",
		"":                                             "",
	}
	for in, want := range cases {
		if got := ownSessionURI("192.0.2.10", coll, in); got != want {
			t.Errorf("ownSessionURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestLocationFallsBackToBody(t *testing.T) {
	if got := sessionURIFrom("192.0.2.10", "/redfish/v1/Sessions", "", []byte(`{"@odata.id":"/redfish/v1/Sessions/3"}`)); got != "/redfish/v1/Sessions/3" {
		t.Fatalf("body fallback = %q", got)
	}
	if got := sessionURIFrom("192.0.2.10", "/redfish/v1/Sessions", "", []byte(`junk`)); got != "" {
		t.Fatalf("junk body = %q", got)
	}
}

// TestMethodAllowlist: GET anywhere; POST only to the discovered sessions collection;
// DELETE only to our own session URI. Everything else is refused before the network.
func TestMethodAllowlist(t *testing.T) {
	s := mockFor(t, idrac9)
	d := driverFor(t, s)
	send := func(method, path string) error {
		req, _ := http.NewRequestWithContext(t.Context(), method, s.URL()+path, nil)
		resp, err := d.httpClient.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		return err
	}
	refused := func(method, path string) {
		t.Helper()
		if err := send(method, path); !errors.Is(err, bmc.ErrMethodNotAllowed) {
			t.Fatalf("%s %s: want ErrMethodNotAllowed, got %v", method, path, err)
		}
	}
	// Before discovery not even the sessions collection may be POSTed to.
	refused(http.MethodPost, sessionsPath9)
	if _, err := d.Probe(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	own := d.sess.Load().uri
	before := len(s.Requests())
	for _, c := range []struct{ method, path string }{
		{http.MethodPost, "/redfish/v1/Sessions"},
		{http.MethodPost, sessionsPath9 + "/1"},
		{http.MethodPost, sessionsPath9 + "?x=1"},
		{http.MethodPost, "/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset"},
		{http.MethodDelete, sessionsPath9},
		{http.MethodDelete, sessionsPath9 + "/2"},
		{http.MethodDelete, own + "?x=1"},
		{http.MethodDelete, "/redfish/v1/Systems/System.Embedded.1"},
		{http.MethodPatch, own},
		{http.MethodPut, own},
		{http.MethodHead, own},
		{http.MethodOptions, "/redfish/v1"},
	} {
		refused(c.method, c.path)
	}
	if len(s.Requests()) != before {
		t.Fatalf("refused request reached the server: %+v", s.Requests()[before:])
	}
	if err := send(http.MethodDelete, own); err != nil {
		t.Fatalf("DELETE of our own session must pass the guard: %v", err)
	}
}

func TestTokenIsASecret(t *testing.T) {
	s := mockFor(t, idrac9)
	d := driverFor(t, s)
	if _, err := d.Probe(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	sess := d.sess.Load()
	if out := fmt.Sprintf("%v %+v %#v", sess.token, *sess, sess.token); strings.Contains(out, sess.token.Reveal()) {
		t.Fatalf("token printed: %s", out)
	}
}
