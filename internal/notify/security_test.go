package notify

import (
	"slices"
	"strings"
	"testing"
	"time"
)

var secNow = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func TestSecurityEvent(t *testing.T) {
	e := SecurityEvent(SecurityChange{ServerID: "r1", ServerName: "Rack one", Open: 3,
		New: []SecurityFinding{{Title: "IPMI over LAN", Result: "Warning"}, {Title: "Telnet", Result: "Fail", Fail: true}}}, secNow)
	if e.Class != ClassSecurity || e.Severity != SeverityWarning || e.Recovery || e.Key != "security/r1" || e.Count != 2 ||
		e.ServerID != "r1" || e.ServerName != "Rack one" || e.ID == "" || !e.At.Equal(secNow) {
		t.Fatalf("event %+v", e)
	}
	if e.Title != "Rack one: 2 new BMC security findings" ||
		e.Message != "New: IPMI over LAN (Warning); Telnet (Fail). 3 findings are open on this BMC; see its Security tab." {
		t.Fatalf("text %q / %q", e.Title, e.Message)
	}
	if len(e.Detail) != 0 {
		t.Fatal("no BMC text in a security event")
	}
	one := SecurityEvent(SecurityChange{ServerID: "r1", ServerName: "R", Open: 1, New: []SecurityFinding{{Title: "SNMP v1 and v2c", Result: "Warning"}}}, secNow)
	if one.Severity != SeverityWarning || one.Title != "R: new BMC security finding" ||
		!strings.Contains(one.Message, "1 finding is open") {
		t.Fatalf("single %+v", one)
	}
	var many []SecurityFinding
	for i := range 8 {
		many = append(many, SecurityFinding{Title: "Check " + string(rune('A'+i)), Result: "Warning"})
	}
	if e := SecurityEvent(SecurityChange{ServerName: "R", New: many, Open: 8}, secNow); !strings.Contains(e.Message, "Check E (Warning) and 3 more.") {
		t.Fatalf("capped list %q", e.Message)
	}
}

func TestCertExpiryEvent(t *testing.T) {
	notAfter := secNow.Add(6*24*time.Hour + time.Hour)
	e := CertExpiryEvent(CertReminder{ServerID: "r1", ServerName: "R", Port: "HTTPS", Days: 6, NotAfter: notAfter}, secNow)
	if e.Class != ClassSecurity || e.Severity != SeverityWarning || e.Key != "security/cert/r1/HTTPS" ||
		e.Title != "R: HTTPS certificate expires in 6 days" || !strings.Contains(e.Message, "2026-10-27") {
		t.Fatalf("event %+v", e)
	}
	if e := CertExpiryEvent(CertReminder{ServerName: "R", Port: "VNC", Days: 12, NotAfter: notAfter}, secNow); e.Severity != SeverityInfo {
		t.Fatalf("14-day reminder is informational: %+v", e)
	}
	// A week is the edge: 7 days left is a warning, 8 is still informational.
	if e := CertExpiryEvent(CertReminder{ServerName: "R", Port: "VNC", Days: 7, NotAfter: notAfter}, secNow); e.Severity != SeverityWarning {
		t.Fatalf("7-day reminder: %+v", e)
	}
	if e := CertExpiryEvent(CertReminder{ServerName: "R", Port: "VNC", Days: 8, NotAfter: notAfter}, secNow); e.Severity != SeverityInfo {
		t.Fatalf("8-day reminder: %+v", e)
	}
	if e := CertExpiryEvent(CertReminder{ServerName: "R", Port: "HTTPS", Days: 0, NotAfter: notAfter}, secNow); e.Title != "R: HTTPS certificate expires within a day" {
		t.Fatalf("last day %q", e.Title)
	}
	if e := CertExpiryEvent(CertReminder{ServerName: "R", Port: "HTTPS", Days: 1, NotAfter: notAfter}, secNow); e.Title != "R: HTTPS certificate expires in 1 day" {
		t.Fatalf("one day %q", e.Title)
	}
}

func TestSecurityClassIsSubscribableQuietAndNeverMuted(t *testing.T) {
	if c, err := ParseClass("security"); err != nil || c != ClassSecurity || !slices.Contains(Classes(), ClassSecurity) {
		t.Fatalf("subscribable: %v %v", c, err)
	}
	if ClassSecurity.Mutable() || ClassSecurity.Label() != "BMC security check findings" {
		t.Fatal("security findings are never paused by maintenance")
	}
	e := SecurityEvent(SecurityChange{ServerName: "R", New: []SecurityFinding{{Title: "Telnet", Result: "Fail", Fail: true}}}, secNow)
	tg := Target{ID: "p", Kind: KindPushover, Enabled: true, Classes: []Class{ClassSecurity}, MinSeverity: SeverityInfo}
	if !e.quiet() || ntfyPriority(e) != 3 || pushoverPriority(tg, e) != 0 || gotifyPriority(e) != 2 {
		t.Fatal("security findings never page: normal priority on every kind")
	}
	if !tg.Wants(e) {
		t.Fatal("a subscribed target gets it")
	}
	tg.Classes = []Class{ClassTrust}
	if tg.Wants(e) {
		t.Fatal("only subscribers get security findings")
	}
}
