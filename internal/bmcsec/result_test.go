package bmcsec

import (
	"slices"
	"testing"
)

func TestResultOrderAndLabels(t *testing.T) {
	rs := Results()
	for i := 1; i < len(rs); i++ {
		if rs[i-1].Rank() <= rs[i].Rank() {
			t.Fatalf("Results must be worst first: %v", rs)
		}
	}
	labels := map[Result]string{Fail: "Fail", Warn: "Warning", CantRead: "Can't read", Unknown: "Unknown", Info: "Info", Pass: "Pass"}
	for r, l := range labels {
		if r.Label() != l {
			t.Errorf("%s label %q", r, r.Label())
		}
	}
	for _, r := range rs {
		if r.Problem() != (r == Fail || r == Warn) {
			t.Errorf("%s problem", r)
		}
	}
	titles := map[Group]string{GroupTLS: "TLS and SSH", GroupServices: "Services and protocols", GroupAccounts: "Accounts",
		GroupFirmware: "Firmware and license", GroupNetwork: "Network"}
	for g, title := range titles {
		if g.Title() != title || !slices.Contains(Groups(), g) {
			t.Errorf("group %s title %q", g, g.Title())
		}
	}
}

func TestAcceptanceCoversOnlyTheSameFinding(t *testing.T) {
	finding := func(id string, r Result, subject string) Finding {
		return Finding{Check: Check{ID: id}, Result: r, Subject: subject, SubjectHash: subjectHash(subject)}
	}
	f := finding("svc.ipmi", Warn, "on")
	a := Acceptance{CheckID: "svc.ipmi", Result: Warn, Subject: "on", SubjectHash: subjectHash("on")}
	if !a.Covers(f) {
		t.Fatal("same check, result and subject")
	}
	if f.Seen() != "warn|"+subjectHash("on") {
		t.Fatalf("seen %q", f.Seen())
	}
	// A display subject that matches is not enough: the hash of the whole subject binds.
	same := finding("svc.ipmi", Warn, "on")
	same.SubjectHash = subjectHash("on, but longer than what is shown")
	for _, other := range []Finding{
		finding("svc.ipmi", Fail, "on"),
		finding("svc.ipmi", Warn, "other"),
		finding("svc.snmp", Warn, "on"),
		finding("svc.ipmi", Info, "on"),
		same,
	} {
		if a.Covers(other) {
			t.Errorf("must not cover %+v", other)
		}
	}
}

func TestCountsTreatAcceptedApart(t *testing.T) {
	r := Report{Findings: []Finding{
		{Result: Fail}, {Result: Warn}, {Result: Warn, Accepted: &Acceptance{}}, {Result: CantRead}, {Result: Unknown},
		{Result: Info}, {Result: Pass}, {Result: Pass},
	}}
	c := r.Counts()
	want := Counts{Fail: 1, Warn: 1, CantRead: 1, Unknown: 1, Info: 1, Pass: 2, Accepted: 1}
	if c != want || c.Problems() != 2 || c.Total() != 8 {
		t.Fatalf("counts %+v", c)
	}
	if _, found := r.Finding("x"); found {
		t.Fatal("no such check")
	}
}
