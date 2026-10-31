// Package redfishmock serves recorded Redfish fixtures from an httptest TLS server.
// It is a test helper only; production code never imports it.
//
// Path mapping: /redfish/v1 -> root.json; /redfish/v1/A/B -> A_B.json (query ignored).
// Top-level collections that were not captured (e.g. /redfish/v1/Systems) are synthesised
// from the captured member files (Systems_<id>.json) so drivers can walk the service root.
//
// Auth: the service root is open; everything else needs Basic auth or an X-Auth-Token from
// a session created by POST to the root's Links.Sessions (sessions.go). DELETE of a
// session is the only other write served (plus the opt-in Dell actions, the power and
// BMC restart actions and the fan floor PATCH of fanfloor.go); HEAD is a read (head.go); any other non-GET answers 405 and is
// counted by OtherWrites.
package redfishmock

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test credentials the mock accepts via HTTP Basic auth and session login.
const (
	User     = "oob_ro"
	Password = "fixture-only-password"
	// OperatorUser/OperatorPassword is the second account (Dell OEM actions such as
	// GetKVMSession need an operator-capable account).
	OperatorUser     = "oob_op"
	OperatorPassword = "fixture-only-operator" //nolint:gosec // G101: test fixture
)

const servicePrefix = "/redfish/v1"

// Request is one request the mock received.
type Request struct {
	Method string
	Path   string
	Auth   string // AuthNone, AuthBasic or AuthToken
}

// Option customises a Server before it starts.
type Option func(*config)

type config struct {
	overlay map[string]string
	missing map[string]bool
	status  map[string]int
	delay   map[string]time.Duration

	tokenOnly  bool
	noSessions bool
	kvm        bool
	power      bool
	transition time.Duration
	fanFloor   bool
	wsman      bool
	// managerReset serves Manager.Reset (managerreset.go); downtime is how long the BMC
	// then answers 503.
	managerReset bool
	downtime     time.Duration
	// extra are further fixture directories (extra.go).
	extra []string
	// logShift moves log entry times, logReplace rewrites their text (old, new pairs;
	// timeshift.go).
	logShift   time.Duration
	logReplace []string
}

// WithOverlay serves body for path, overriding or adding to the fixtures (synthetic data).
func WithOverlay(path, body string) Option {
	return func(c *config) { c.overlay[path] = body }
}

// WithMissing makes path answer 404 even if a fixture exists.
func WithMissing(path string) Option {
	return func(c *config) { c.missing[path] = true }
}

// WithStatus makes path answer with the given HTTP status and an empty JSON object.
func WithStatus(path string, code int) Option {
	return func(c *config) { c.status[path] = code }
}

// WithDelay delays responses for path ("*" = every path) by d, or until the client gives up.
func WithDelay(path string, d time.Duration) Option {
	return func(c *config) { c.delay[path] = d }
}

// Server is a running mock BMC.
type Server struct {
	dir string
	cfg config
	ts  *httptest.Server

	mu    sync.Mutex
	reqs  []Request
	sess  sessionStore
	kvm   kvmStats
	power powerSim
	fan   fanFloorState
	mgr   managerResetSim
	rt    runtimeState
}

// New starts a TLS mock serving fixtures from dir; it is closed via t.Cleanup.
func New(t testing.TB, dir string, opts ...Option) *Server {
	t.Helper()
	cfg := config{
		overlay: map[string]string{},
		missing: map[string]bool{},
		status:  map[string]int{},
		delay:   map[string]time.Duration{},
	}
	for _, o := range opts {
		o(&cfg)
	}
	s := &Server{dir: dir, cfg: cfg, sess: sessionStore{live: map[string]string{}, users: map[string]string{}}}
	s.power.state = s.fixturePowerState()
	s.fan.Current = FanFloorAuto
	s.ts = httptest.NewUnstartedServer(http.HandlerFunc(s.handle))
	s.ts.Config.ErrorLog = log.New(quietHandshakes{os.Stderr}, "", log.LstdFlags)
	s.ts.StartTLS()
	t.Cleanup(s.ts.Close)
	return s
}

// URL is the https base URL of the mock.
func (s *Server) URL() string { return s.ts.URL }

// PinSHA256 is the hex SHA-256 of the mock certificate's SubjectPublicKeyInfo.
func (s *Server) PinSHA256() string {
	sum := sha256.Sum256(s.ts.Certificate().RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// Requests returns a copy of every request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.reqs...)
}

// NonGET counts requests whose method was not GET.
func (s *Server) NonGET() int {
	n := 0
	for _, r := range s.Requests() {
		if r.Method != http.MethodGet {
			n++
		}
	}
	return n
}

func (s *Server) record(r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reqs = append(s.reqs, Request{Method: r.Method, Path: r.URL.Path, Auth: authKind(r)})
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.record(r)
	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == "" {
		path = r.URL.Path
	}
	if d, ok := s.delayFor(path); ok {
		select {
		case <-time.After(d):
		case <-r.Context().Done():
			// The client gave up: drop the connection. A plain return would let net/http
			// send an implicit empty 200, which a slow client could read as a bad body.
			panic(http.ErrAbortHandler)
		}
	}
	if s.serveManagerDown(w) || s.serveRuntime(w, r, path) || s.serveOutside(w, r, path) {
		return
	}
	if r.Method == http.MethodHead {
		s.serveHead(w, r, path)
		return
	}
	if r.Method != http.MethodGet {
		s.handleWrite(w, r, path)
		return
	}
	// The Redfish service root is unauthenticated by spec; everything else needs auth.
	if path != servicePrefix && !s.authorised(r) {
		writeJSON(w, http.StatusUnauthorized, []byte(`{}`))
		return
	}
	code, body := s.lookup(path)
	writeJSON(w, code, s.rewriteLogs(s.patchManager(path, s.patchSystem(path, body))))
}

func (s *Server) delayFor(path string) (time.Duration, bool) {
	if d, ok := s.cfg.delay[path]; ok {
		return d, true
	}
	d, ok := s.cfg.delay["*"]
	return d, ok
}

// SetStatus makes path answer with code from now on (a BMC whose answers change after
// the driver discovered it); an empty JSON object is the body.
func (s *Server) SetStatus(path string, code int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cfg.status[path] = code
}

func (s *Server) status(path string) (int, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code, ok := s.cfg.status[path]
	return code, ok
}

func (s *Server) lookup(path string) (int, []byte) {
	if code, ok := s.status(path); ok {
		return code, []byte(`{}`)
	}
	if s.cfg.missing[path] {
		return http.StatusNotFound, []byte(`{}`)
	}
	if body, ok := s.cfg.overlay[path]; ok {
		return http.StatusOK, []byte(body)
	}
	if body, ok := s.kvmDoc(path); ok {
		return http.StatusOK, body
	}
	if body, ok := s.fanFloorDoc(path); ok {
		return http.StatusOK, body
	}
	name := pathToFile(path)
	if name == "" {
		return http.StatusNotFound, []byte(`{}`)
	}
	if b, ok := s.extraFixture(name); ok {
		return http.StatusOK, b
	}
	if b, err := readFixture(s.dir, name); err == nil {
		return http.StatusOK, b
	}
	if b := s.synthCollection(path); b != nil {
		return http.StatusOK, b
	}
	return http.StatusNotFound, []byte(`{}`)
}

// synthCollection builds /redfish/v1/<X> from files named <X>_<id>.json.
func (s *Server) synthCollection(path string) []byte {
	rest := strings.TrimPrefix(path, servicePrefix+"/")
	if rest == path || strings.Contains(rest, "/") {
		return nil
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil
	}
	type ref struct {
		ID string `json:"@odata.id"`
	}
	var members []ref
	for _, e := range entries {
		id, ok := strings.CutPrefix(strings.TrimSuffix(e.Name(), ".json"), rest+"_")
		if ok && id != "" && !strings.Contains(id, "_") {
			members = append(members, ref{ID: path + "/" + id})
		}
	}
	if len(members) == 0 {
		return nil
	}
	b, _ := json.Marshal(map[string]any{
		"@odata.id":           path,
		"Name":                rest + " Collection (synthesised by redfishmock)",
		"Members":             members,
		"Members@odata.count": len(members),
	})
	return b
}

// pathToFile maps a Redfish path to a fixture file name, or "" if it is not mappable.
func pathToFile(path string) string {
	path = strings.TrimSuffix(path, "/")
	if path == servicePrefix {
		return "root.json"
	}
	rest, ok := strings.CutPrefix(path, servicePrefix+"/")
	if !ok || rest == "" {
		return ""
	}
	for _, seg := range strings.Split(rest, "/") {
		if seg == "" || seg == "." || seg == ".." || strings.Contains(seg, `\`) {
			return ""
		}
	}
	return strings.ReplaceAll(rest, "/", "_") + ".json"
}

func writeJSON(w http.ResponseWriter, code int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body) //nolint:gosec // G705: test mock serving JSON fixtures as application/json, never HTML
}

// readFixture reads name inside dir through os.Root, so no path can escape the
// fixture directory even if pathToFile were to let one through.
func readFixture(dir, name string) ([]byte, error) {
	f, err := os.OpenInRoot(dir, name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// FixtureDir returns testdata/redfish/<name> under the module root.
func FixtureDir(t testing.TB, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata", "redfish", name)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above working directory")
		}
		dir = parent
	}
}
