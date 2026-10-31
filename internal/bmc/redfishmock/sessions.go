package redfishmock

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// Auth kinds recorded per request.
const (
	AuthNone  = "none"
	AuthBasic = "basic"
	AuthToken = "token"
)

// WithTokenOnly makes the mock refuse HTTP Basic auth, so every authenticated request
// must carry a session token (asserts that a driver really uses its session).
func WithTokenOnly() Option {
	return func(c *config) { c.tokenOnly = true }
}

// WithoutSessions makes the mock behave like a BMC without a SessionService: POST to the
// sessions collection answers 405 and only Basic auth works.
func WithoutSessions() Option {
	return func(c *config) { c.noSessions = true }
}

// SessionStats counts session activity.
type SessionStats struct {
	Created   int // successful POSTs to the sessions collection
	Deleted   int // successful DELETEs of a session
	Rejected  int // requests refused with 401 (bad password, bad or expired token)
	TokenGETs int // authenticated GETs that used X-Auth-Token
	BasicGETs int // authenticated GETs that used Basic auth
}

type sessionStore struct {
	next   int
	live   map[string]string // token -> session URI
	users  map[string]string // token -> user name
	stats  SessionStats
	writes int // non-GET requests other than session create/delete
}

// SessionsURI is the sessions collection the service root links to (Links.Sessions).
func (s *Server) SessionsURI() string {
	code, body := s.lookup(servicePrefix)
	if code != http.StatusOK {
		return ""
	}
	var root struct {
		Links struct {
			Sessions struct {
				ID string `json:"@odata.id"`
			}
		}
	}
	if json.Unmarshal(body, &root) != nil {
		return ""
	}
	return strings.TrimSuffix(root.Links.Sessions.ID, "/")
}

// LiveSessions is the number of sessions that exist right now.
func (s *Server) LiveSessions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sess.live)
}

// SessionStats returns a copy of the session counters.
func (s *Server) SessionStats() SessionStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sess.stats
}

// OtherWrites counts non-GET requests that were neither a session login nor a session
// logout: anything a read-only driver must never send.
func (s *Server) OtherWrites() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sess.writes
}

// ExpireSessions invalidates every token, as a BMC does when its session timeout passes.
func (s *Server) ExpireSessions() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sess.live = map[string]string{}
	s.sess.users = map[string]string{}
}

func authKind(r *http.Request) string {
	if r.Header.Get("X-Auth-Token") != "" {
		return AuthToken
	}
	if _, _, ok := r.BasicAuth(); ok {
		return AuthBasic
	}
	return AuthNone
}

// authorised checks the request's credentials and counts how it authenticated.
func (s *Server) authorised(r *http.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ok, kind := false, authKind(r)
	switch kind {
	case AuthToken:
		_, ok = s.sess.live[r.Header.Get("X-Auth-Token")]
	case AuthBasic:
		u, p, _ := r.BasicAuth()
		ok = !s.cfg.tokenOnly && u == User && p == Password
	}
	switch {
	case !ok:
		s.sess.stats.Rejected++
	case r.Method != http.MethodGet:
	case kind == AuthToken:
		s.sess.stats.TokenGETs++
	default:
		s.sess.stats.BasicGETs++
	}
	return ok
}

// handleWrite serves POST to the sessions collection and DELETE of a session; every
// other non-GET request is counted as a forbidden write and answered 405.
func (s *Server) handleWrite(w http.ResponseWriter, r *http.Request, path string) {
	coll := s.SessionsURI()
	switch {
	case !s.cfg.noSessions && coll != "" && r.Method == http.MethodPost && path == coll:
		s.createSession(w, r, coll)
	case !s.cfg.noSessions && coll != "" && r.Method == http.MethodDelete && strings.HasPrefix(path, coll+"/"):
		s.deleteSession(w, r, path)
	case s.cfg.kvm && r.Method == http.MethodPost && path == KVMActionPath:
		s.getKVMSession(w, r)
	case s.cfg.power && r.Method == http.MethodPost && path == ResetActionPath:
		s.reset(w, r)
	case s.cfg.managerReset && r.Method == http.MethodPost && path == ManagerResetPath:
		s.managerReset(w, r)
	case s.cfg.fanFloor && r.Method == http.MethodPatch && path == FanFloorAttrsPath:
		s.patchFanFloor(w, r)
	default:
		s.countWrite()
		writeJSON(w, http.StatusMethodNotAllowed, []byte(`{}`))
	}
}

func (s *Server) countWrite() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sess.writes++
}

func (s *Server) createSession(w http.ResponseWriter, r *http.Request, coll string) {
	var login struct {
		UserName string
		Password string
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
	if err != nil || json.Unmarshal(body, &login) != nil {
		writeJSON(w, http.StatusBadRequest, []byte(`{}`))
		return
	}
	s.mu.Lock()
	if !validLogin(login.UserName, login.Password) {
		s.sess.stats.Rejected++
		s.mu.Unlock()
		writeJSON(w, http.StatusUnauthorized, []byte(`{}`))
		return
	}
	s.sess.next++
	id := strconv.Itoa(s.sess.next)
	uri := coll + "/" + id
	tok := newToken()
	s.sess.live[tok] = uri
	s.sess.users[tok] = login.UserName
	s.sess.stats.Created++
	s.mu.Unlock()
	w.Header().Set("X-Auth-Token", tok)
	w.Header().Set("Location", uri)
	doc, _ := json.Marshal(map[string]string{"@odata.id": uri, "Id": id, "UserName": login.UserName})
	writeJSON(w, http.StatusCreated, doc)
}

func (s *Server) deleteSession(w http.ResponseWriter, r *http.Request, path string) {
	if !s.authorised(r) {
		writeJSON(w, http.StatusUnauthorized, []byte(`{}`))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for tok, uri := range s.sess.live {
		if uri == path {
			delete(s.sess.live, tok)
			delete(s.sess.users, tok)
			s.sess.stats.Deleted++
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	s.sess.writes++
	writeJSON(w, http.StatusNotFound, []byte(`{}`))
}

func newToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
