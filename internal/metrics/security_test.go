package metrics

import (
	"context"
	"strconv"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
)

func postureState(id string) fleet.ServerState {
	s := healthyState()
	s.ID = id
	ok := bmc.SectionOf(nil)
	s.Posture = bmc.Posture{
		Web: bmc.TLSProbe{Read: ok, Port: 443, PinMatch: true, Cert: bmc.CertFacts{NotAfter: t0.Add(30 * 24 * time.Hour)}},
		VNC: bmc.TLSProbe{Read: ok, Port: 5901, PinMatch: true, Cert: bmc.CertFacts{NotAfter: t0.Add(10 * 24 * time.Hour)}},
	}
	s.HasPosture = true
	return s
}

// TestSecurityFamilies: counts per result from the security hook (every result present,
// zeros included) and the certificate expiry of each usable probe.
func TestSecurityFamilies(t *testing.T) {
	unpinned := postureState("unpinned")
	unpinned.Posture.Web.PinMatch = false
	unpinned.Posture.VNC = bmc.TLSProbe{}
	states := []fleet.ServerState{postureState("storage"), unpinned, neverPolled()}
	cfg := Config{Fleet: staticFleet{states: states}, Now: func() time.Time { return t0 },
		Security: func(id string) (SecurityCounts, bool) {
			if id != "storage" {
				return SecurityCounts{}, false
			}
			return SecurityCounts{Pass: 20, Info: 4, Warn: 3, Fail: 1, Unknown: 1, CantRead: 2, Accepted: 1}, true
		}}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Render(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	exp := func(d time.Duration) string { return strconv.FormatFloat(float64(t0.Add(d).Unix()), 'g', -1, 64) }
	for _, want := range []string{
		`oob_security_checks{server="storage",result="fail"} 1`,
		`oob_security_checks{server="storage",result="warn"} 3`,
		`oob_security_checks{server="storage",result="cant-read"} 2`,
		`oob_security_checks{server="storage",result="unknown"} 1`,
		`oob_security_checks{server="storage",result="info"} 4`,
		`oob_security_checks{server="storage",result="pass"} 20`,
		`oob_security_checks{server="storage",result="accepted"} 1`,
		`oob_tls_cert_expiry_timestamp_seconds{server="storage",port="443"} ` + exp(30*24*time.Hour),
		`oob_tls_cert_expiry_timestamp_seconds{server="storage",port="5901"} ` + exp(10*24*time.Hour),
	} {
		if !strings.Contains(text, want+"\n") {
			t.Errorf("missing %q", want)
		}
	}
	for _, absent := range []string{`oob_security_checks{server="unpinned"`, `oob_tls_cert_expiry_timestamp_seconds{server="unpinned"`} {
		if strings.Contains(text, absent) {
			t.Errorf("unexpected %q", absent)
		}
	}
	if strings.Contains(text, `oob_tls_cert_expiry_timestamp_seconds{server="new"`) {
		t.Error("a server without posture reports a certificate")
	}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if !strings.HasPrefix(line, "#") && !parseSampleLine(line) {
			t.Fatalf("invalid sample line %q", line)
		}
	}
}

// TestNoSecuritySource: without the hook the counts are left out; certificate expiry
// still comes from the fleet's posture.
func TestNoSecuritySource(t *testing.T) {
	c, err := New(Config{Fleet: staticFleet{states: []fleet.ServerState{postureState("storage")}}, Now: func() time.Time { return t0 }})
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.Render(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "oob_security_checks") || !strings.Contains(string(out), "oob_tls_cert_expiry_timestamp_seconds") {
		t.Fatalf("scrape:\n%s", out)
	}
}
