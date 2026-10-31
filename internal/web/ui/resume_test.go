package ui

import (
	"bytes"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Audit R2-03: a form submitted after the step-up window lapsed was thrown away by the
// step-up interstitial. The submission is now kept (sealed, bound to the session, for the
// step-up window plus a minute) and replayed once the code is confirmed.

func TestPendingStoreSealsBindsAndExpires(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)}
	st, err := newPendingStore([]byte(strings.Repeat("k", 32)), clk.Now)
	must(t, err)
	form := pendingForm{Path: "/settings/servers/edge1/credentials/readonly", Form: formSettings,
		Values: url.Values{"password": {"hunter2"}, "username": {"svc_ro"}, csrfField: {"old-token"}}}
	id, ok := st.put("sess:a", form, 2*time.Minute)
	if !ok || !resumeIDPattern.MatchString(id) {
		t.Fatalf("put: %q %v", id, ok)
	}
	st.mu.Lock()
	raw := st.m[id]
	st.mu.Unlock()
	for _, clear := range []string{"hunter2", "svc_ro", "username", "old-token"} {
		if bytes.Contains(raw.sealed, []byte(clear)) {
			t.Fatalf("the stash holds %q in clear", clear)
		}
	}
	if !st.has(id, "sess:a") || st.has(id, "sess:b") || st.has("nope", "sess:a") {
		t.Fatal("has: wrong session or id answered")
	}
	if _, taken := st.take(id, "sess:b"); taken {
		t.Fatal("another session took the form")
	}
	got, ok := st.take(id, "sess:a")
	if !ok || got.Path != form.Path || got.Form != formSettings || got.Values.Get("password") != "hunter2" ||
		got.Values.Get("username") != "svc_ro" || got.Values.Has(csrfField) {
		t.Fatalf("take: %+v %v", got, ok)
	}
	if _, ok := st.take(id, "sess:a"); ok {
		t.Fatal("a stash was replayed twice")
	}
	// Expiry.
	id, _ = st.put("sess:a", form, 2*time.Minute)
	clk.Advance(2*time.Minute + time.Second)
	if _, ok := st.take(id, "sess:a"); ok {
		t.Fatal("an expired form was replayed")
	}
	// Bounds: an oversized form is refused; the oldest entry goes when the store is full.
	big := pendingForm{Path: "/x", Form: formSettings, Values: url.Values{"impact": {strings.Repeat("a", maxPendingBytes)}}}
	if _, ok := st.put("sess:a", big, time.Minute); ok {
		t.Fatal("an oversized form was kept")
	}
	first, _ := st.put("sess:a", form, time.Minute)
	for i := range maxPending {
		st.put("sess:"+strconv.Itoa(i), form, time.Minute) // many sessions: the process-wide bound
	}
	if st.has(first, "sess:a") || st.count() != maxPending {
		t.Fatalf("eviction: first kept %v, count %d", st.has(first, "sess:a"), st.count())
	}
}

// resumeFrom parses the step-up redirect of a refused change: its next and resume id.
func resumeFrom(t *testing.T, r *httpResult, wantNext string) (string, string) {
	t.Helper()
	loc := r.status(t, http.StatusSeeOther).rec.Header().Get("Location")
	u, err := url.Parse(loc)
	must(t, err)
	id := u.Query().Get("resume")
	if u.Path != "/stepup" || u.Query().Get("next") != wantNext || !resumeIDPattern.MatchString(id) {
		t.Fatalf("Location = %q, want /stepup?next=%s&resume=<id>", loc, wantNext)
	}
	return loc, id
}

func TestStepUpExpiryKeepsTheForm(t *testing.T) {
	e := newServersEnv(t, "")
	c := e.adminClient()
	e.clock.Advance(6 * time.Minute) // the login's step-up has lapsed
	fields := url.Values{"id": {"kept1"}, "name": {"Kept one"}, "kind": {"idrac9"}, "address": {"192.0.2.14"}, "port": {"443"},
		"pin": {spkiA}}
	loc, id := resumeFrom(t, result(c.submit("/settings/servers/new", "/settings/servers/fingerprint", fields)), "/settings/servers/new")
	if _, ok := e.reg.Current().Entry("kept1"); ok {
		t.Fatal("created before the step-up")
	}
	if !e.auditContains("stepup_required") {
		t.Fatal("the refusal was not audited")
	}
	page := result(c.get(loc)).status(t, http.StatusOK)
	page.contains(t, `name="resume" value="`+id+`"`, "Your form is kept", "Add server").lacks(t, spkiA, "Kept one")

	// The code confirms the step-up and the kept form runs as if it had just been sent.
	r := result(c.submit(loc, "/stepup", url.Values{"code": {e.code(e.secret)}, "next": {"/settings/servers/new"}, "resume": {id}}))
	r.status(t, http.StatusSeeOther).location(t, "/settings/servers/kept1?done=server-created")
	if x, ok := e.reg.Current().Entry("kept1"); !ok || x.Server.TLSPinSHA256 != spkiA || x.Server.Name != "Kept one" {
		t.Fatalf("not created from the kept form: %+v", x)
	}
	// Single use: a stale id only returns to next.
	e.clock.Advance(6 * time.Minute)
	stale := "/stepup?next=%2Fsettings%2Fservers%2Fnew&resume=" + id
	result(c.get(stale)).status(t, http.StatusOK).lacks(t, "Your form is kept", `name="resume"`)
	result(c.submit(stale, "/stepup", url.Values{"code": {e.code(e.secret)}, "next": {"/settings/servers/new"}, "resume": {id}})).
		status(t, http.StatusSeeOther).location(t, "/settings/servers/new")
}

// TestStepUpExpiryReplaysASecretForm: a password typed into a credential form survives
// the step-up (sealed in memory, never in the audit log or a page) and is stored.
func TestStepUpExpiryReplaysASecretForm(t *testing.T) {
	e := newServersEnv(t, "")
	c := e.adminClient()
	e.fetchAndConfirm(t, c, "edge1", "192.0.2.12").status(t, http.StatusSeeOther)
	e.clock.Advance(6 * time.Minute)
	page := "/settings/servers/edge1"
	loc, id := resumeFrom(t, result(c.submit(page, page+"/credentials/readonly",
		url.Values{"rev": {"1"}, "username": {"svc_ro"}, "password": {roSecret}})), page)
	result(c.get(loc)).contains(t, "Your form is kept").lacks(t, roSecret, "svc_ro")
	r := result(c.submit(loc, "/stepup", url.Values{"code": {e.code(e.secret)}, "next": {page}, "resume": {id}}))
	r.status(t, http.StatusSeeOther).location(t, page+"?done=server-credential#credentials")
	result(c.submit(page, page+"/enable", url.Values{"rev": {"2"}})).status(t, http.StatusSeeOther)
	if x, _ := e.reg.Current().Entry("edge1"); !x.Active() {
		t.Fatalf("not active after the replayed credential: %+v", x)
	}
	if e.auditContains(roSecret) {
		t.Fatal("password in the audit log")
	}
}

// A kept form belongs to the session that posted it: another session's code cannot run it.
func TestKeptFormIsBoundToItsSession(t *testing.T) {
	e := newServersEnv(t, "")
	c := e.adminClient()
	e.clock.Advance(6 * time.Minute)
	fields := url.Values{"id": {"kept2"}, "name": {"Kept two"}, "kind": {"idrac9"}, "address": {"192.0.2.14"}, "port": {"443"}, "pin": {spkiA}}
	_, id := resumeFrom(t, result(c.submit("/settings/servers/new", "/settings/servers/fingerprint", fields)), "/settings/servers/new")
	other := e.client("192.0.2.11")
	other.login("morgan", e.secret)
	e.clock.Advance(6 * time.Minute)
	stepup := "/stepup?next=%2Fsettings%2Fservers%2Fnew&resume=" + id
	result(other.get(stepup)).status(t, http.StatusOK).lacks(t, "Your form is kept")
	result(other.submit(stepup, "/stepup", url.Values{"code": {e.code(e.secret)}, "next": {"/settings/servers/new"}, "resume": {id}})).
		status(t, http.StatusSeeOther).location(t, "/settings/servers/new")
	if _, ok := e.reg.Current().Entry("kept2"); ok {
		t.Fatal("another session replayed the form")
	}
}

// TestPendingStoreCapsEachSession (review R6): one session can keep at most
// maxPendingPerSession forms (its oldest goes first), so it cannot flush the shared stash
// and evict the forms other admins are keeping across their step-up.
func TestPendingStoreCapsEachSession(t *testing.T) {
	clk := &clock{t: time.Date(2026, 10, 21, 9, 0, 0, 0, time.UTC)}
	st, err := newPendingStore([]byte(strings.Repeat("k", 32)), clk.Now)
	must(t, err)
	form := pendingForm{Path: "/settings/general", Form: formSettings, Values: url.Values{"instance_name": {"x"}}}
	other, _ := st.put("sess:b", form, time.Minute)
	var mine []string
	for range maxPending + 10 {
		id, ok := st.put("sess:a", form, time.Minute)
		if !ok {
			t.Fatal("put refused")
		}
		mine = append(mine, id)
	}
	if !st.has(other, "sess:b") {
		t.Fatal("one session's forms evicted another session's kept form")
	}
	if st.count() != maxPendingPerSession+1 {
		t.Fatalf("count = %d, want %d", st.count(), maxPendingPerSession+1)
	}
	for i, id := range mine {
		if kept := i >= len(mine)-maxPendingPerSession; st.has(id, "sess:a") != kept {
			t.Fatalf("form %d of %d: kept %v, want %v (the newest are kept)", i, len(mine), !kept, kept)
		}
	}
}

// TestResumePurposeIsPinned: the HKDF label keeps the pre-rename project name
// (oob-console). Stashed forms live in memory only, but the label is left as it was so
// the rename changes no derived key anywhere.
func TestResumePurposeIsPinned(t *testing.T) {
	if resumePurpose != "oob-console/ui-resume/v1" {
		t.Fatalf("resume HKDF label changed: %q", resumePurpose)
	}
}
