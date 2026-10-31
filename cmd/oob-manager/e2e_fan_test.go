//go:build e2e

package main

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc/redfishmock"
)

var leaseIDLine = regexp.MustCompile(`(?m)^lease_id=([0-9a-f]{32})$`)

// fanYAML: the R730XD (iDRAC8) hands its fans to a host script (host-lease, lease files
// in the stack directory); the R240 (iDRAC9) raises the BMC's minimum fan speed.
func fanYAML(id string) string {
	if id == "r730xd" {
		return "    fan: { mode: host-lease, safe_min_pct: 30, max_lease: 2h }\n"
	}
	return "    fan: { mode: redfish-floor, safe_min_pct: 41, max_lease: 2h }\n"
}

// startLease reviews and confirms a lease through the UI (the login's step-up is fresh).
func startLease(t *testing.T, b browser, id, pct string) {
	t.Helper()
	ops := b.get("/servers/" + id + "/fan")
	action := "/servers/" + id + "/fan/lease"
	form := url.Values{"csrf_token": {formCSRF(t, ops, action)}, "pct": {pct}, "minutes": {"30"}}
	review := b.post(action, form)
	expectPage(t, review, "Start a fan lease on", "Fans run at least at "+pct+" %", "Step-up fresh")
	form.Set("csrf_token", formCSRF(t, review, action))
	form.Set("confirm", "yes")
	expectRedirect(t, b.post(action, form), "/servers/"+id+"/fan?fan=started")
}

func endLease(t *testing.T, b browser, id string) {
	t.Helper()
	ops := b.get("/servers/" + id + "/fan")
	action := "/servers/" + id + "/fan/lease/end"
	expectRedirect(t, b.post(action, url.Values{"csrf_token": {formCSRF(t, ops, action)}}),
		"/servers/"+id+"/fan?fan=ended")
}

// checkFans: the lease lifecycle in both modes, end to end against the mocks.
func checkFans(t *testing.T, b browser, s *stack) {
	t.Run("host lease", func(t *testing.T) { checkHostLease(t, b, s) })
	t.Run("redfish floor", func(t *testing.T) { checkRedfishFloor(t, b, s) })
	t.Run("hostile input", func(t *testing.T) {
		ops := b.get("/servers/r730xd/fan")
		form := url.Values{"csrf_token": {formCSRF(t, ops, "/servers/r730xd/fan/lease")}, "pct": {"101"},
			"minutes": {"30"}, "confirm": {"yes"}}
		if p := b.post("/servers/r730xd/fan/lease", form); p.status != http.StatusUnprocessableEntity {
			t.Fatalf("pct 101: %d", p.status)
		}
		if _, err := os.Stat(filepath.Join(s.dir, "r730xd.lease")); !os.IsNotExist(err) {
			t.Fatal("a refused request wrote a lease file")
		}
	})
}

func checkHostLease(t *testing.T, b browser, s *stack) {
	expectPage(t, b.get("/servers/r730xd/fan"), "<strong>Owner:</strong> Host fan curve", "Review lease",
		"has not reported yet")
	startLease(t, b, "r730xd", "55")
	raw, err := os.ReadFile(filepath.Join(s.dir, "r730xd.lease"))
	if err != nil {
		t.Fatal(err)
	}
	m := leaseIDLine.FindStringSubmatch(string(raw))
	if m == nil || !strings.Contains(string(raw), "server=r730xd\n") || !strings.Contains(string(raw), "pct=55\n") {
		t.Fatalf("lease file: %q", raw)
	}
	expectPage(t, b.get("/servers/r730xd/fan"), "Pending", "waiting for confirmation", "End now")

	// The host script's acknowledgement (what deploy/host/fan-lease-reader.sh writes).
	ack := "version=1\nserver=r730xd\nlease_id=" + m[1] + "\nowner=lease\napplied_pct=55\nreported_at=" +
		strconv.FormatInt(time.Now().Unix(), 10) + "\nreason=ok\n"
	if err := os.WriteFile(filepath.Join(s.dir, "r730xd.ack"), []byte(ack), 0o600); err != nil { //nolint:gosec // G703: the stack's temp dir
		t.Fatal(err)
	}
	p := b.get("/servers/r730xd/fan")
	expectPage(t, p, "Applied", "Lease by "+e2eUser+": at least 55 %", "55 %")
	if strings.Contains(p.body, "waiting for confirmation") {
		t.Error("lease still pending after the host's ack")
	}
	endLease(t, b, "r730xd")
	if _, err := os.Stat(filepath.Join(s.dir, "r730xd.lease")); !os.IsNotExist(err) {
		t.Fatalf("lease file left after End now: %v", err)
	}
	expectPage(t, b.get("/servers/r730xd/fan?fan=ended"), "Lease ended.", "Review lease")
}

func checkRedfishFloor(t *testing.T, b browser, s *stack) {
	mock := s.mocks["r240"]
	expectPage(t, b.get("/servers/r240/fan"), "BMC automatic", "Review lease")
	startLease(t, b, "r240", "50")
	if st := mock.FanFloorStats(); len(st.Patches) != 1 || st.Patches[0] != 50 {
		t.Fatalf("after start: %+v", st)
	}
	expectPage(t, b.get("/servers/r240/fan"), "Applied", "Lease by "+e2eUser+": at least 50 %")
	endLease(t, b, "r240")
	if st := mock.FanFloorStats(); len(st.Patches) != 2 || st.Patches[1] != redfishmock.FanFloorAuto || st.Current != redfishmock.FanFloorAuto {
		t.Fatalf("original not restored: %+v", st)
	}
}

// fanFloorLogins counts the operator logins of the fan floor client (one per read and
// per PATCH), for the shutdown session accounting.
func fanFloorLogins(m *redfishmock.Server) int {
	n := len(m.FanFloorStats().Patches)
	for _, r := range m.Requests() {
		if r.Method == http.MethodGet && r.Path == redfishmock.FanFloorAttrsPath {
			n++
		}
	}
	return n
}
