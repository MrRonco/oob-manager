//go:build e2e

package main

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/store"
)

var tofuHidden = regexp.MustCompile(`name="(value|proof)" value="([^"]*)"`)

// confirmTOFU posts the confirm form of a fingerprint page with its hidden fields.
func confirmTOFU(t *testing.T, b browser, p page, action string, fields url.Values) page {
	t.Helper()
	if p.status != http.StatusOK {
		t.Fatalf("fingerprint page: %d %s", p.status, p.body)
	}
	form := url.Values{"csrf_token": {formCSRF(t, p, action)}}
	for k, v := range fields {
		form[k] = v
	}
	for _, m := range tofuHidden.FindAllStringSubmatch(p.body, -1) {
		form.Set(m[1], html.UnescapeString(m[2])) // as a browser submits it (a host key holds + and /)
	}
	return b.post(action, form)
}

func revOf(t *testing.T, p page) string {
	t.Helper()
	m := regexp.MustCompile(`name="rev" value="([0-9]+)"`).FindStringSubmatch(p.body)
	if m == nil {
		t.Fatalf("no rev on the page (%d)", p.status)
	}
	return m[1]
}

// apiServers is /api/v1/servers as the read-only token sees it.
func apiServers(t *testing.T, b browser, s *stack) string {
	t.Helper()
	p := b.do(http.MethodGet, "/api/v1/servers", s.token, nil)
	if p.status != http.StatusOK {
		t.Fatalf("api: %d", p.status)
	}
	return p.body
}

// checkServers drives slice S3 through the real stack: a BMC that is not in
// config.yaml is added in the browser (TOFU fingerprint, sealed credentials, SSH host
// key), enabled and polled without a restart; tested; moved (credentials dropped);
// removed. The mock is reached only through the harness dialer.
func checkServers(t *testing.T) {
	s := startStack(t, "127.0.0.1:0")
	b := browser{t: t, base: s.base, c: s.client(t)}
	login(t, b, s)
	expectPage(t, b.get("/settings/servers"), "Storage node R730XD", "config.yaml", "Add server")
	fields := url.Values{"id": {extraID}, "name": {"Edge node R650"}, "tags": {"lab"}, "kind": {"idrac9"},
		"address": {extraAddress}, "port": {"443"}}
	fp := b.submit("/settings/servers/new", "/settings/servers/fingerprint", fields)
	expectPage(t, fp, "Confirm the HTTPS certificate", extraAddress+":443")
	if !strings.Contains(fp.body, s.extra.PinSHA256()[:4]+" "+s.extra.PinSHA256()[4:8]) {
		t.Fatal("the fetched fingerprint is not the mock's")
	}
	if n := len(s.extra.Requests()); n != 0 {
		t.Fatalf("the fingerprint fetch sent %d HTTP requests", n)
	}
	expectRedirect(t, confirmTOFU(t, b, fp, "/settings/servers", fields), "/settings/servers/"+extraID+"?done=server-created")
	base := "/settings/servers/" + extraID
	setCred := func(slot, user, pass string) {
		p := b.get(base)
		expectRedirect(t, b.submit(base, base+"/credentials/"+slot, url.Values{"rev": {revOf(t, p)}, "username": {user},
			"password": {pass}}), base+"?done=server-credential#credentials")
	}
	setCred("readonly", redfishmock.User, redfishmock.Password)
	setCred("operator", redfishmock.OperatorUser, redfishmock.OperatorPassword)
	p := b.get(base)
	expectRedirect(t, b.submit(base, base+"/features", url.Values{"rev": {revOf(t, p)}, "fan_mode": {"none"},
		"serial": {"bmcssh"}, "graphical": {"none"}, "ssh_port": {"22"}, "vnc_port": {"5901"}}), base+"?done=server-saved#features")
	p = b.get(base)
	hk := b.submit(base, base+"/pin/fetch", url.Values{"rev": {revOf(t, p)}, "kind": {"ssh"}})
	expectPage(t, hk, "Confirm the SSH host key", "SHA256:")
	expectRedirect(t, confirmTOFU(t, b, hk, base+"/pin", url.Values{"rev": {revOf(t, p)}, "kind": {"ssh"}}),
		base+"?done=server-pin#fingerprints")
	if s.extraSSH.AuthAttempts() != 0 {
		t.Fatal("the host key fetch tried to log in")
	}
	p = b.get(base)
	expectPage(t, p, "Set · v1", "Set · v2", "Enable server")
	expectRedirect(t, b.submit(base, base+"/enable", url.Values{"rev": {revOf(t, p)}}), base+"?done=server-enabled#review")
	waitFor(t, "the added server is polled without a restart", func() bool {
		return strings.Count(apiServers(t, b, s), `"reachable":true`) == len(e2eServers())+1
	})
	expectPage(t, b.get("/"), "Edge node R650")
	expectPage(t, b.get("/servers/"+extraID), "Serial console")
	// Test connection: read-only, in the background.
	expectRedirect(t, b.submit(base, base+"/test", nil), base+"?done=server-test#test")
	waitFor(t, "test finished", func() bool { return strings.Contains(b.get(base).body, "Passed ") })
	expectPage(t, b.get(base), "Looks like idrac9, as configured.", "matches the confirmed key")
	// Move: credentials are deleted and the server leaves the fleet.
	p = b.get(base)
	expectRedirect(t, b.submit(base, base+"/connection/fingerprint", url.Values{"rev": {revOf(t, p)}, "kind": {"idrac9"},
		"address": {"192.0.2.13"}, "port": {"443"}, "pin": {s.extra.PinSHA256()}}), base+"?done=server-moved#connection")
	expectPage(t, b.get(base), "Not set", "Disabled")
	waitFor(t, "the moved server leaves the fleet", func() bool {
		return !strings.Contains(apiServers(t, b, s), `"id":"`+extraID+`"`)
	})
	// Remove (typed id).
	del := base + "/delete"
	expectRedirect(t, b.submit(del, del, url.Values{"confirm": {"yes"}, "typed": {extraID}}), "/settings/servers?done=server-deleted")
	if strings.Contains(b.get("/settings/servers").body, "Edge node R650") {
		t.Fatal("removed server still listed")
	}
	if code := s.stop(); code != 0 {
		t.Fatalf("serve exit %d", code)
	}
	assertNoPlaintext(t, s, redfishmock.Password, redfishmock.OperatorPassword)
	assertAudited(t, s.dbPath, "admin.server.fingerprint", "admin.server.create", "admin.server.credential",
		"admin.server.pin", "admin.server.update", "admin.server.enable", "admin.server.test", "admin.server.delete")
}

// assertNoPlaintext: no BMC password in the app log or anywhere in the database file.
func assertNoPlaintext(t *testing.T, s *stack, secrets ...string) {
	t.Helper()
	f, err := os.Open(s.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	raw, _ := io.ReadAll(f)
	wal, _ := os.ReadFile(s.dbPath + "-wal")
	for _, sec := range secrets {
		if strings.Contains(string(raw), sec) || strings.Contains(string(wal), sec) || strings.Contains(s.errOut.String(), sec) {
			t.Fatalf("a BMC password is stored or logged in clear")
		}
	}
	db, err := store.Open(context.Background(), s.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	recs, _ := db.AuditSearch().Search(context.Background(), store.AuditFilter{Limit: 1000})
	for _, r := range recs {
		for _, sec := range secrets {
			if strings.Contains(r.ParamsJSON, sec) {
				t.Fatalf("password in audit row %s", r.Action)
			}
		}
	}
}
