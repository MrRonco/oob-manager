package ui

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"oob-manager/internal/auth"
)

// Pending submissions (audit R2-03). A change posted after the step-up window lapsed used
// to be thrown away by the step-up interstitial. It is now kept while the user confirms a
// fresh code on /stepup and replayed once, as if it had just been sent:
//
//   - kept in memory only, sealed (AES-256-GCM under a key derived from the CSRF key), so
//     a password typed into a credential form never sits in clear anywhere, and never
//     reaches a log or the audit trail;
//   - bound to the session that posted it (another session cannot resume it);
//   - for the step-up window plus one minute, at most maxPending entries of at most
//     maxPendingBytes each and at most maxPendingPerSession per session (the oldest goes
//     first, a session's own oldest when it is at its cap);
//   - single use: the replay re-issues the CSRF token for the rotated session and runs
//     the normal route, which re-checks authz with the fresh step-up and the rate limit.

const (
	maxPending           = 64           // stashed forms per process
	maxPendingPerSession = 4            // per session binding: one session cannot evict the others' forms
	maxPendingBytes      = maxFormBytes // a parsed form came from a body of at most this size
	pendingGrace         = time.Minute  // on top of the step-up window
	resumeIDBytes        = 16
	// resumePurpose keeps the pre-rename project name (oob-console): no HKDF label changed
	// with the rename (TestResumePurposeIsPinned).
	resumePurpose = "oob-console/ui-resume/v1"
)

// resumeIDPattern is the shape of a stash id (128 random bits, hex).
var resumeIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

// pendingForm is one kept submission: the route it was posted to, the CSRF form name to
// re-issue, and the fields (without the old token).
type pendingForm struct {
	Path   string
	Form   string
	Values url.Values
}

type pendingEntry struct {
	binding    string
	path, form string
	expires    time.Time
	sealed     []byte
}

// pendingStore keeps sealed pendingForms by id.
type pendingStore struct {
	sealer auth.Sealer
	now    func() time.Time
	mu     sync.Mutex
	m      map[string]pendingEntry
	order  []string // insertion order, for eviction
}

// newPendingStore derives the sealing key from key (the CSRF key, itself derived from
// the app keys) so the stash never holds a form in clear.
func newPendingStore(key []byte, now func() time.Time) (*pendingStore, error) {
	k, err := hkdf.Key(sha256.New, key, nil, resumePurpose, 32)
	if err != nil {
		return nil, err
	}
	sealer, err := auth.NewAESGCMSealer(k)
	if err != nil {
		return nil, err
	}
	return &pendingStore{sealer: sealer, now: now, m: map[string]pendingEntry{}}, nil
}

func (p *pendingStore) aad(binding, path, form string) []byte {
	return []byte(binding + "|" + path + "|" + form)
}

// put keeps f for the session binding and returns its id; ok is false when the form is
// too large or cannot be sealed.
func (p *pendingStore) put(binding string, f pendingForm, ttl time.Duration) (string, bool) {
	values := url.Values{}
	for k, vs := range f.Values {
		if k != csrfField {
			values[k] = vs
		}
	}
	body := values.Encode()
	if len(body) > maxPendingBytes || binding == "" || f.Path == "" || f.Form == "" {
		return "", false
	}
	sealed, err := p.sealer.Seal([]byte(body), p.aad(binding, f.Path, f.Form))
	if err != nil {
		return "", false
	}
	id := randomHex(resumeIDBytes)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.evict(binding)
	p.m[id] = pendingEntry{binding: binding, path: f.Path, form: f.Form, expires: p.now().Add(ttl), sealed: sealed}
	p.order = append(p.order, id)
	return id, true
}

// evict makes room for one more form of binding: it drops expired entries, then the
// binding's own oldest while that session is at its cap, then the oldest overall while
// the store is full. Called with mu held.
func (p *pendingStore) evict(binding string) {
	now := p.now()
	kept := p.order[:0:0]
	for _, id := range p.order {
		if e, ok := p.m[id]; ok && now.Before(e.expires) {
			kept = append(kept, id)
		} else {
			delete(p.m, id)
		}
	}
	kept = p.capSession(kept, binding)
	for len(kept) >= maxPending {
		delete(p.m, kept[0])
		kept = kept[1:]
	}
	p.order = kept
}

// capSession drops binding's oldest entries from order (oldest first) until the session
// has room for one more. Called with mu held.
func (p *pendingStore) capSession(order []string, binding string) []string {
	n := 0
	for _, id := range order {
		if p.m[id].binding == binding {
			n++
		}
	}
	kept := order[:0:0]
	for _, id := range order {
		if n >= maxPendingPerSession && p.m[id].binding == binding {
			delete(p.m, id)
			n--
			continue
		}
		kept = append(kept, id)
	}
	return kept
}

// get returns the live entry for id and binding (not consumed).
func (p *pendingStore) get(id, binding string) (pendingEntry, bool) {
	e, ok := p.m[id]
	if !ok || !p.now().Before(e.expires) || subtle.ConstantTimeCompare([]byte(e.binding), []byte(binding)) != 1 {
		return pendingEntry{}, false
	}
	return e, true
}

// has reports whether a kept form can be resumed by the session binding.
func (p *pendingStore) has(id, binding string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.get(id, binding)
	return ok
}

// keptPath is the route of the kept form id for the session binding ("" when none).
func (p *pendingStore) keptPath(id, binding string) (string, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	e, ok := p.get(id, binding)
	return e.path, ok
}

// take consumes the kept form for id and the session binding.
func (p *pendingStore) take(id, binding string) (pendingForm, bool) {
	p.mu.Lock()
	e, ok := p.get(id, binding)
	if ok {
		delete(p.m, id)
	}
	p.mu.Unlock()
	if !ok {
		return pendingForm{}, false
	}
	body, err := p.sealer.Open(e.sealed, p.aad(binding, e.path, e.form))
	if err != nil {
		return pendingForm{}, false
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return pendingForm{}, false
	}
	return pendingForm{Path: e.path, Form: e.form, Values: values}, true
}

func (p *pendingStore) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.m)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // never fails (Go 1.24+)
	return hex.EncodeToString(b)
}

// validResume returns id when it has the shape of a stash id, "" otherwise.
func validResume(id string) string {
	if resumeIDPattern.MatchString(id) {
		return id
	}
	return ""
}

// stepUpURL is the step-up page for a change refused for a stale step-up. A posted form
// is kept and resumed after the code (the resume parameter).
func (s *server) stepUpURL(r *http.Request, sess session, back string) string {
	q := url.Values{"next": {back}}
	if r.Method == http.MethodPost && len(r.PostForm) > 0 {
		f := pendingForm{Path: r.URL.Path, Form: formSettings, Values: r.PostForm}
		if id, ok := s.pending.put(sessionBinding(sess.token), f, s.stepUpWindow()+pendingGrace); ok {
			q.Set("resume", id)
		}
	}
	return "/stepup?" + q.Encode()
}

// replay runs a kept form through its own route for the rotated session token: a fresh
// CSRF token, the new session cookie, the browser's other cookies and address, and the
// request's context. The route does its own checks and writes the response.
func (s *server) replay(w http.ResponseWriter, r *http.Request, f pendingForm, token string) {
	f.Values.Set(csrfField, s.csrf.issue(f.Form, sessionBinding(token)))
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, localPath(f.Path, "/"), strings.NewReader(f.Values.Encode()))
	if err != nil {
		s.errorPage(w, r, http.StatusInternalServerError, "The kept form could not be resumed. Enter it again.")
		return
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", r.UserAgent())
	req.RemoteAddr = r.RemoteAddr
	for _, c := range r.Cookies() {
		if c.Name != auth.SessionCookieName {
			req.AddCookie(c)
		}
	}
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: token, Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode})
	s.mux.ServeHTTP(w, req)
}
