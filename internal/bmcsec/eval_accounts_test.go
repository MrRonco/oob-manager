package bmcsec

import (
	"slices"
	"testing"

	"oob-manager/internal/bmc"
)

func withAccounts(p bmc.Posture, list ...bmc.Account) bmc.Posture {
	p.Redfish.Accounts = p.Redfish.Accounts.WithAccounts(list)
	return p
}

func TestEnabledAndAdminAccounts(t *testing.T) {
	p := withAccounts(good(),
		bmc.Account{UserName: "root", Role: "Administrator", Enabled: on(true, "e")},
		bmc.Account{UserName: "ops", Role: "Administrator", Enabled: on(true, "e")},
		bmc.Account{UserName: "ro", Role: "ReadOnly", Enabled: on(true, "e")},
		bmc.Account{UserName: "old", Role: "Operator", Enabled: on(false, "e")})
	f := expect(t, p, goodInputs(), "acct.enabled", Info, "3 enabled accounts: root (Administrator), ops (Administrator), ro (ReadOnly).")
	if f.Evidence[1] != "1 more account is disabled." {
		t.Fatalf("evidence %v", f.Evidence)
	}
	expect(t, p, goodInputs(), "acct.admins", Info, "2 enabled Administrator accounts: root, ops.")
	p = withAccounts(good())
	expect(t, p, goodInputs(), "acct.enabled", Info, "0 enabled accounts: none.")
}

func TestAccountListUnread(t *testing.T) {
	p := good()
	p.Redfish.Accounts = bmc.AccountFacts{Read: bmc.Section{State: bmc.ReadForbidden}}
	for _, id := range []string{"acct.enabled", "acct.default_names", "acct.ipmi_sol", "acct.admins"} {
		expect(t, p, goodInputs(), id, CantRead, "Can't read the account list with the read-only account.")
	}
	p.Redfish.Accounts = bmc.AccountFacts{Read: ok(), List: bmc.Section{State: bmc.ReadForbidden}}
	expect(t, p, goodInputs(), "acct.enabled", CantRead, "")
	p.Redfish.Accounts = bmc.AccountFacts{Read: bmc.Section{State: bmc.ReadAbsent}}
	expect(t, p, goodInputs(), "acct.enabled", Unknown, "does not offer the account list")
	// A vendor document listed the users although AccountService was refused.
	p.Redfish.Accounts = bmc.AccountFacts{Read: bmc.Section{State: bmc.ReadForbidden}, List: ok()}.WithAccounts(
		[]bmc.Account{{UserName: "root", Enabled: on(true, "e")}})
	expect(t, p, goodInputs(), "acct.default_names", Warn, "root")
}

func TestDefaultNames(t *testing.T) {
	p := withAccounts(good(), bmc.Account{UserName: "ADMIN", Enabled: on(true, "e")}, bmc.Account{UserName: "USERID", Enabled: on(true, "e")},
		bmc.Account{UserName: "root", Enabled: on(false, "e")}, bmc.Account{UserName: "alice", Enabled: on(true, "e")},
		bmc.Account{UserName: "administrator", Enabled: on(true, "e")})
	f := expect(t, p, goodInputs(), "acct.default_names", Warn, "Enabled with a factory default name: ADMIN, USERID, administrator.")
	if f.Subject != `["ADMIN","USERID","administrator"]` || f.Evidence[1] == "" {
		t.Fatalf("finding %+v", f)
	}
}

func TestIPMIAndSOLAccounts(t *testing.T) {
	p := withAccounts(good(),
		bmc.Account{UserName: "root", Enabled: on(true, "e"), IPMI: on(true, "a"), SOL: on(true, "a")},
		bmc.Account{UserName: "ro", Enabled: on(true, "e"), IPMI: on(false, "a"), SOL: on(false, "a")})
	expect(t, p, goodInputs(), "acct.ipmi_sol", Info, "IPMI over LAN is off.")
	p.Redfish.Protocols.IPMI = on(true, "np")
	f := expect(t, p, goodInputs(), "acct.ipmi_sol", Warn, "IPMI LAN access: root.")
	// The subject names each access list: a change to either ends an acceptance.
	if f.Subject != `ipmi=["root"];sol=["root"]` {
		t.Fatalf("subject %q", f.Subject)
	}
	p = withAccounts(good(), bmc.Account{UserName: "x", Enabled: on(true, "e")})
	expect(t, p, goodInputs(), "acct.ipmi_sol", Unknown, "does not report per-account")
	p.Redfish.Protocols.IPMI = bmc.Fact[bool]{}
	p = withAccounts(p, bmc.Account{UserName: "x", Enabled: on(true, "e"), SOL: on(true, "a")})
	expect(t, p, goodInputs(), "acct.ipmi_sol", Info, "IPMI over LAN is not reported.")
}

func TestPasswordPolicy(t *testing.T) {
	p := good()
	p.Redfish.Accounts.MinPasswordLength = bmc.FactOf(0, "AccountService.MinPasswordLength")
	f := expect(t, p, goodInputs(), "acct.policy", Warn, "No minimum password length is enforced (AccountService.MinPasswordLength).")
	if f.Subject != "min-length" {
		t.Fatalf("subject %q", f.Subject)
	}
	p.Redfish.Accounts.MinPasswordLength = bmc.FactOf(6, "as")
	expect(t, p, goodInputs(), "acct.policy", Warn, "as short as 6 characters")

	p = good()
	p.Redfish.Accounts.LockoutThreshold = bmc.FactOf(0, "as")
	p.Redfish.Network.LoginBlocking = on(false, "attr")
	expect(t, p, goodInputs(), "acct.policy", Warn, "No account lockout")
	p.Redfish.Network.LoginBlocking = on(true, "Dell attribute IPBlocking.1.BlockEnable")
	expect(t, p, goodInputs(), "acct.policy", Pass, "Addresses are blocked after repeated failed logins")
	// The vendor document that may hold IP blocking was refused: nothing is concluded.
	p.Redfish.Network.LoginBlocking = bmc.Fact[bool]{}
	p.Redfish.Attributes = bmc.Section{State: bmc.ReadForbidden}
	expect(t, p, goodInputs(), "acct.policy", Unknown, "whole password and lockout policy")
	p.Redfish.Attributes = bmc.Section{}
	expect(t, p, goodInputs(), "acct.policy", Warn, "No account lockout")

	p = good()
	expect(t, p, goodInputs(), "acct.policy", Pass, "Accounts lock after 5 failed logins for 5m0s")
	p.Redfish.Accounts = bmc.AccountFacts{Read: bmc.Section{State: bmc.ReadForbidden}}
	p.Redfish.Network.LoginBlocking = on(true, "attr")
	expect(t, p, goodInputs(), "acct.policy", CantRead, "Addresses are blocked")
	p.Redfish.Network.LoginBlocking = bmc.Fact[bool]{}
	expect(t, p, goodInputs(), "acct.policy", CantRead, "")
}

// TestDefaultNamesSeeThroughFormatCharacters: a reader always strips format
// characters, and the evaluator does not rely on it: "root" with a zero-width space or a
// bidirectional override is still a factory name, while a Cyrillic look-alike is not one
// and is shown escaped so the difference is visible.
func TestDefaultNamesSeeThroughFormatCharacters(t *testing.T) {
	for _, name := range []string{"root\u200b", "ro\u202eot", "\ufeffADMIN", "Administrator\u2060"} {
		p := withAccounts(good(), bmc.Account{UserName: name, Enabled: on(true, "e")})
		expect(t, p, goodInputs(), "acct.default_names", Warn, "Enabled with a factory default name")
	}
	p := withAccounts(good(), bmc.Account{UserName: "r\u043eot", Role: "Administrator", Enabled: on(true, "e")},
		bmc.Account{UserName: "alice", Role: "ReadOnly", Enabled: on(true, "e")})
	expect(t, p, goodInputs(), "acct.default_names", Pass, "No enabled account has a factory default name.")
	f := expect(t, p, goodInputs(), "acct.enabled", Info, `2 enabled accounts: "r\u043eot" (Administrator), alice (ReadOnly).`)
	if f.Subject != `["\"r\\u043eot\"","alice"]` { // sorted, JSON-encoded display names
		t.Fatalf("subject %q", f.Subject)
	}
	expect(t, p, goodInputs(), "acct.admins", Info, `1 enabled Administrator account: "r\u043eot".`)
}

// TestAccountStateNotReportedCountsAsEnabled: an account whose state the BMC does not
// report cannot be ruled out, so it counts as enabled everywhere, and the evidence says
// which ones.
func TestAccountStateNotReportedCountsAsEnabled(t *testing.T) {
	p := withAccounts(good(), bmc.Account{UserName: "root", Role: "Administrator"}, bmc.Account{UserName: "alice", Role: "ReadOnly", Enabled: on(true, "e")})
	f := expect(t, p, goodInputs(), "acct.enabled", Info, "2 enabled accounts: root (Administrator), alice (ReadOnly).")
	if !slices.Contains(f.Evidence, "State not reported for: root (counted as enabled).") {
		t.Fatalf("evidence %v", f.Evidence)
	}
	expect(t, p, goodInputs(), "acct.default_names", Warn, "State not reported for: root (counted as enabled).")
	expect(t, p, goodInputs(), "acct.admins", Info, "1 enabled Administrator account: root.")
}

// TestAccountSubjectsAreSorted: a BMC that lists the same accounts in another order has
// not changed anything; the subjects are sorted so an acceptance survives it.
func TestAccountSubjectsAreSorted(t *testing.T) {
	p := withAccounts(good(), bmc.Account{UserName: "USERID", Enabled: on(true, "e"), IPMI: on(true, "a")},
		bmc.Account{UserName: "ADMIN", Enabled: on(true, "e"), IPMI: on(true, "a"), SOL: on(true, "a")})
	p.Redfish.Protocols.IPMI = on(true, "np")
	f := expect(t, p, goodInputs(), "acct.default_names", Warn, "Enabled with a factory default name: USERID, ADMIN.")
	if f.Subject != `["ADMIN","USERID"]` {
		t.Fatalf("default names subject %q", f.Subject)
	}
	if f := find(t, evalOf(p, goodInputs()), "acct.ipmi_sol"); f.Subject != `ipmi=["ADMIN","USERID"];sol=["ADMIN"]` {
		t.Fatalf("ipmi subject %q", f.Subject)
	}
	if f := find(t, evalOf(p, goodInputs()), "acct.enabled"); f.Subject != `["ADMIN","USERID"]` {
		t.Fatalf("enabled subject %q", f.Subject)
	}
}

// TestPartialAccountListIsNoted: a list cut at the cap, or with pages not followed, says so.
func TestPartialAccountListIsNoted(t *testing.T) {
	p := good()
	p.Redfish.Accounts.Partial = true
	expect(t, p, goodInputs(), "acct.enabled", Info, "Only the first 16 accounts were read; the BMC lists more.")
}

// TestPolicyThresholds pins the password length threshold: 7 warns, 8 passes.
func TestPolicyThresholds(t *testing.T) {
	p := good()
	p.Redfish.Accounts.MinPasswordLength = bmc.FactOf(7, "as")
	expect(t, p, goodInputs(), "acct.policy", Warn, "as short as 7 characters")
	p.Redfish.Accounts.MinPasswordLength = bmc.FactOf(8, "as")
	expect(t, p, goodInputs(), "acct.policy", Pass, "Minimum password length 8")
}

// TestListSubjectsAreInjective: two accounts "alice" and "bob" and one account named
// "alice, bob" are different findings, so one acceptance cannot cover the other.
func TestListSubjectsAreInjective(t *testing.T) {
	two := withAccounts(good(), bmc.Account{UserName: "alice", Enabled: on(true, "e")}, bmc.Account{UserName: "bob", Enabled: on(true, "e")})
	one := withAccounts(good(), bmc.Account{UserName: "alice, bob", Enabled: on(true, "e")})
	a, b := find(t, evalOf(two, goodInputs()), "acct.enabled"), find(t, evalOf(one, goodInputs()), "acct.enabled")
	if a.SubjectHash == b.SubjectHash || a.Subject == b.Subject {
		t.Fatalf("subjects collide: %q / %q", a.Subject, b.Subject)
	}
	if a.Subject != `["alice","bob"]` {
		t.Fatalf("subject %q", a.Subject)
	}
}
