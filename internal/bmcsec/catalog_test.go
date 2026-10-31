package bmcsec

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"oob-manager/internal/bmc"
)

func TestCatalogIsComplete(t *testing.T) {
	seen := map[string]bool{}
	idPattern := regexp.MustCompile(`^[a-z]+\.[a-z0-9_]+$`)
	for _, c := range Catalog() {
		if !idPattern.MatchString(c.ID) || len(c.ID) > 64 || seen[c.ID] {
			t.Errorf("bad or duplicate id %q", c.ID)
		}
		seen[c.ID] = true
		if c.Title == "" || c.Why == "" || c.Fix == "" || !slices.Contains(Groups(), c.Group) {
			t.Errorf("%s: title, why, fix and a known group are required: %+v", c.ID, c)
		}
		if c.Docs != "" && !strings.HasPrefix(c.Docs, "https://") {
			t.Errorf("%s: docs must be an https link: %q", c.ID, c.Docs)
		}
		if strings.HasPrefix(c.Dell, "iDRAC:") {
			t.Errorf("%s: the page labels the hint \"Dell iDRAC:\" already: %q", c.ID, c.Dell)
		}
	}
	if len(seen) != 31 {
		t.Fatalf("%d checks, want 31", len(seen))
	}
}

// TestCatalogTextIsGenericAndUSEnglish: the project is public (CLAUDE.md rule 12), so the
// check texts name no private address, platform or server model, and the UI copy is US
// English.
func TestCatalogTextIsGenericAndUSEnglish(t *testing.T) {
	bad := regexp.MustCompile(`(?i)\b(licence|colour|behaviour|organis|cancelled)|\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d+\.|\bunraid\b|r730|r240`)
	for _, c := range Catalog() {
		for _, s := range []string{c.Title, c.Why, c.Fix, c.Dell, c.Docs} {
			if m := bad.FindString(s); m != "" {
				t.Errorf("%s: %q in %q", c.ID, m, s)
			}
		}
	}
}

func TestAllGoodPosture(t *testing.T) {
	want := map[string]Result{
		"tls.cert_expiry": Pass, "tls.cert_issuer": Pass, "tls.cert_key": Pass, "tls.protocols": Pass, "tls.ciphers": Pass,
		"tls.vnc_cert": Info, "ssh.algorithms": Pass, // the VNC port presents the web certificate: a note, not a second finding
		"svc.ipmi": Pass, "svc.ipmi_cipher0": Pass, "svc.snmp": Pass, "svc.telnet": Pass, "svc.http": Pass, "svc.ssh": Info,
		"svc.vnc": Pass, "svc.virtual_media": Pass, "svc.ssdp": Pass, "svc.wsman": Pass, "svc.ntp": Pass, "svc.clock": Pass,
		"svc.syslog":   Pass,
		"acct.enabled": Info, "acct.default_names": Pass, "acct.ipmi_sol": Pass, "acct.policy": Pass, "acct.admins": Info,
		"fw.bmc": Pass, "fw.bios": Info, "fw.license": Pass,
		"net.ip_filter": Pass, "net.dhcp": Pass, "net.ipv6": Pass,
	}
	r := evalOf(good(), goodInputs())
	if len(r.Findings) != len(want) {
		t.Fatalf("%d findings, want %d", len(r.Findings), len(want))
	}
	for _, f := range r.Findings {
		if want[f.Check.ID] != f.Result || len(f.Evidence) == 0 {
			t.Errorf("%s = %s %v, want %s", f.Check.ID, f.Result, f.Evidence, want[f.Check.ID])
		}
	}
	if c := r.Counts(); c.Problems() != 0 || c.Total() != 31 || c.Info != 5 || c.Pass != 26 {
		t.Fatalf("counts %+v", c)
	}
	if r.ServerID != "srv" || !r.CheckedAt.Equal(good().Started) || r.Took != 3e9 {
		t.Fatalf("report meta %+v", r)
	}
}

func TestReportOrderFollowsTheCatalog(t *testing.T) {
	r := evalOf(good(), goodInputs())
	var got []string
	for _, f := range r.Findings {
		got = append(got, f.Check.ID)
	}
	var want []string
	for _, c := range Catalog() {
		want = append(want, c.ID)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("order %v", got)
	}
}

func TestChecksThatDoNotApplyAreLeftOut(t *testing.T) {
	in := goodInputs()
	in.VNC = false
	p := good()
	p.SSH = bmc.SSHProbe{Read: bmc.Skipped("SSH is off")}
	r := evalOf(p, in)
	for _, id := range []string{"tls.vnc_cert", "ssh.algorithms"} {
		if _, found := r.Finding(id); found {
			t.Errorf("%s should not apply", id)
		}
	}
	if len(r.Findings) != 29 {
		t.Fatalf("%d findings", len(r.Findings))
	}
}

func TestDellHintsOnlyForDell(t *testing.T) {
	in := goodInputs()
	in.Kind = "redfish"
	for _, f := range evalOf(good(), in).Findings {
		if f.Check.Dell != "" {
			t.Fatalf("%s: Dell hint on a generic Redfish BMC", f.Check.ID)
		}
	}
	if f := find(t, evalOf(good(), goodInputs()), "svc.ipmi"); f.Check.Dell == "" {
		t.Fatal("iDRAC servers get the Dell hint")
	}
}

func TestEmptyPostureIsUnknownNotPass(t *testing.T) {
	r := evalOf(bmc.Posture{}, Inputs{Kind: "redfish"})
	for _, f := range r.Findings {
		if f.Result != Unknown {
			t.Errorf("%s = %s %v: nothing was read, so nothing may pass", f.Check.ID, f.Result, f.Evidence)
		}
	}
}

func TestSubjectIsCapped(t *testing.T) {
	p := good()
	p.Redfish.Firmware.BMCVersion = strings.Repeat("9", 500)
	if f := find(t, evalOf(p, goodInputs()), "fw.bmc"); len(f.Subject) != maxSubject {
		t.Fatalf("subject length %d", len(f.Subject))
	}
}
