package bmc

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestSectionOf(t *testing.T) {
	cases := []struct {
		err  error
		want Section
	}{
		{nil, Section{State: ReadOK}},
		{fmt.Errorf("GET x: %w", ErrNotFound), Section{State: ReadAbsent}},
		{fmt.Errorf("GET x: %w", ErrAuth), Section{State: ReadForbidden}},
		{fmt.Errorf("GET x: %w", ErrTimeout), Section{State: ReadFailed, Class: ClassTimeout}},
		{errors.New("boom"), Section{State: ReadFailed, Class: ClassOther}},
	}
	for _, c := range cases {
		if got := SectionOf(c.err); got != c.want {
			t.Errorf("SectionOf(%v) = %+v, want %+v", c.err, got, c.want)
		}
	}
	if s := Skipped("console in use"); s.State != ReadSkipped || s.Why != "console in use" || s.OK() {
		t.Fatalf("Skipped = %+v", s)
	}
	if !SectionOf(nil).OK() {
		t.Fatal("ok section must report OK")
	}
}

func TestFactOrPrefersKnown(t *testing.T) {
	var unknown Fact[bool]
	dell := FactOf(true, "Dell IPMILan.1.Enable")
	dmtf := FactOf(false, "ManagerNetworkProtocol.IPMI")
	if got := dell.Or(dmtf); got != dell {
		t.Fatalf("known fact must win: %+v", got)
	}
	if got := unknown.Or(dmtf); got != dmtf {
		t.Fatalf("unknown falls back: %+v", got)
	}
	if got := unknown.Or(Fact[bool]{}); got.Known {
		t.Fatalf("both unknown: %+v", got)
	}
}

func TestAccountFactsAreCopied(t *testing.T) {
	list := []Account{{UserName: "root", Role: "Administrator", Enabled: FactOf(true, "e")}}
	a := AccountFacts{Read: SectionOf(nil)}.WithAccounts(list)
	list[0].UserName = "changed"
	got := a.Accounts()
	if got[0].UserName != "root" {
		t.Fatal("WithAccounts must copy its input")
	}
	got[0].UserName = "changed"
	if a.Accounts()[0].UserName != "root" {
		t.Fatal("Accounts must return a copy")
	}
}

func TestLicenseFactsAreCopied(t *testing.T) {
	in := []LicenseEntry{{Description: "Enterprise", Type: "Production"}}
	l := LicenseFacts{Read: SectionOf(nil)}.WithLicenses(in)
	in[0].Description = "x"
	out := l.Licenses()
	out[0].Description = "y"
	if l.Licenses()[0].Description != "Enterprise" {
		t.Fatal("licences must be copied in and out")
	}
}

func TestCertDaysLeft(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	c := CertFacts{NotAfter: now.Add(36 * time.Hour)}
	if d := c.DaysLeft(now); d != 1 {
		t.Fatalf("DaysLeft = %d, want 1 (whole days, rounded down)", d)
	}
	if d := (CertFacts{NotAfter: now.Add(-time.Hour)}).DaysLeft(now); d != -1 {
		t.Fatalf("expired DaysLeft = %d, want -1", d)
	}
}

func TestTLSProbeIdentityUsable(t *testing.T) {
	ok := TLSProbe{Read: SectionOf(nil), PinMatch: true}
	if !ok.Usable() {
		t.Fatal("a read probe with a matching pin is usable")
	}
	for _, p := range []TLSProbe{{Read: SectionOf(nil)}, {Read: Skipped("x"), PinMatch: true}, {}} {
		if p.Usable() {
			t.Fatalf("not usable: %+v", p)
		}
	}
}
