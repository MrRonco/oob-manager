package bmcsec

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/textclean"
)

// minPasswordLength: a BMC that allows shorter passwords gets a warning.
const minPasswordLength = 8

// maxListedAccounts is the account walk's cap (redfish.maxPostureAccounts), for the note.
const maxListedAccounts = 16

func accountEntries() []entry {
	return []entry{
		{check: Check{ID: "acct.enabled", Group: GroupAccounts, Title: "Enabled accounts",
			Why: "Every enabled account is a way in. Knowing exactly which exist makes a forgotten or unexpected one stand out.",
			Fix: "Disable accounts nobody uses, and give each person and each tool an account of its own."},
			eval: enabledAccounts},
		{check: Check{ID: "acct.default_names", Group: GroupAccounts, Title: "Default account names",
			Why: "Factory account names (root, admin, ADMIN, USERID, Administrator) are the first ones attackers try, often with the " +
				"factory password. oob-manager cannot see passwords, so it cannot tell whether that password was changed.",
			Fix:  "Change the factory password if it is still set, and rename or disable the default account where the BMC allows it.",
			Dell: "iDRAC ships with root and a default password: calvin on older servers, a unique one printed on the information tag of newer ones.",
			Docs: "https://cwe.mitre.org/data/definitions/1392.html"},
			eval: defaultNames},
		{check: Check{ID: "acct.ipmi_sol", Group: GroupAccounts, Title: "IPMI and serial-over-LAN access",
			Why: "While IPMI over LAN is on, every account with IPMI access is exposed to the IPMI password hash disclosure; " +
				"serial over LAN gives a console on the host.",
			Fix:  "Give IPMI and serial-over-LAN access only to the accounts that need it.",
			Dell: "Per user, set the IPMI LAN privilege to No Access and turn serial over LAN off (Users.N.IpmiLanPrivilege, Users.N.SolEnable).",
			Docs: "https://nvd.nist.gov/vuln/detail/CVE-2013-4786"},
			eval: ipmiAccounts},
		{check: Check{ID: "acct.policy", Group: GroupAccounts, Title: "Password and lockout policy",
			Why: "Without a lockout a password can be guessed online as fast as the BMC answers, and short passwords fall quickly.",
			Fix: "Require passwords of at least 8 characters (longer for administrators), and lock accounts or block addresses after a few failed logins.",
			Dell: "IP blocking after failed logins (iDRAC.IPBlocking.BlockEnable, FailCount, FailWindow, PenaltyTime); " +
				"newer firmware also has password rules in its security settings.",
			Docs: "https://cwe.mitre.org/data/definitions/307.html"},
			eval: passwordPolicy},
		{check: Check{ID: "acct.admins", Group: GroupAccounts, Title: "Administrator accounts",
			Why: "An Administrator can create accounts and change every BMC setting. The fewer there are, the fewer passwords can lose the BMC.",
			Fix: "Keep one or two Administrator accounts for people. Give tools ReadOnly, or a custom role with only what they need " +
				"(oob-manager polls with ReadOnly, plus an operator account for power and consoles).",
			Docs: "https://cwe.mitre.org/data/definitions/250.html"},
			eval: adminAccounts},
	}
}

// accounts is the account list as the checks see it: the accounts that are enabled or
// whose state is not reported (they cannot be ruled out, so they count as enabled), the
// names of the latter, and the notes every account check appends.
type accounts struct {
	on      []bmc.Account
	unknown []string // names with no reported state
	off     int
	partial bool
}

// notes are the evidence lines about the list itself.
func (a accounts) notes() []string {
	var ev []string
	if len(a.unknown) > 0 {
		ev = append(ev, "State not reported for: "+strings.Join(a.unknown, ", ")+" (counted as enabled).")
	}
	if a.partial {
		ev = append(ev, fmt.Sprintf("Only the first %d accounts were read; the BMC lists more.", maxListedAccounts))
	}
	return ev
}

// accountList returns the accounts, or the outcome when they were not read.
func accountList(c evalCtx) (accounts, outcome, bool) {
	a := c.p.Redfish.Accounts
	switch {
	case a.List.OK():
	case a.List.State == bmc.ReadNotTried:
		return accounts{}, unread(a.Read, "the account list"), false
	default:
		return accounts{}, unread(a.List, "the account list"), false
	}
	out := accounts{partial: a.Partial}
	for _, acc := range a.Accounts() {
		switch {
		case !acc.Enabled.Known:
			out.on, out.unknown = append(out.on, acc), append(out.unknown, displayName(acc.UserName))
		case acc.Enabled.Value:
			out.on = append(out.on, acc)
		default:
			out.off++
		}
	}
	return out, outcome{}, true
}

// accountNames lists accounts in the BMC's order, for evidence.
func accountNames(list []bmc.Account, withRole bool) string {
	out := make([]string, 0, len(list))
	for _, a := range list {
		if withRole && a.Role != "" {
			out = append(out, displayName(a.UserName)+" ("+displayName(a.Role)+")")
			continue
		}
		out = append(out, displayName(a.UserName))
	}
	return strings.Join(out, ", ")
}

// subjectNames lists accounts sorted and JSON-encoded, for a finding's subject: a BMC
// that lists the same accounts in another order has not changed anything, so an
// acceptance survives it, and the encoding is injective, so "alice" and "bob" can never
// read as one account named "alice, bob".
func subjectNames(list []bmc.Account) string {
	names := make([]string, 0, len(list))
	for _, a := range list {
		names = append(names, displayName(a.UserName))
	}
	slices.Sort(names)
	return jsonList(names)
}

// jsonList encodes strings as a JSON array (never fails for strings).
func jsonList(s []string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return strings.Join(s, "\x00") // unreachable for strings; still injective
	}
	return string(b)
}

// displayName shows an account name or role as the BMC reported it when it is plain
// ASCII, and in Go's quoted-ASCII form otherwise, so a look-alike name (a Cyrillic о in
// "root") cannot pass for the real one on the page.
func displayName(s string) string {
	if textclean.GraphicASCII(s) {
		return s
	}
	return strconv.QuoteToASCII(s)
}

func enabledAccounts(c evalCtx) outcome {
	a, o, ok := accountList(c)
	if !ok {
		return o
	}
	ev := []string{fmt.Sprintf("%s: %s.", plural(len(a.on), "enabled account", "enabled accounts"), orNone(accountNames(a.on, true)))}
	if a.off > 0 {
		ev = append(ev, plural(a.off, "more account is", "more accounts are")+" disabled.")
	}
	ev = append(ev, a.notes()...)
	ev = append(ev, "Source: "+c.p.Redfish.Accounts.ListSource+".")
	return out(Info, subjectNames(a.on), ev...)
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// defaultName reports a factory account name (any vendor, any case). The readers
// already strip format characters; the comparison strips them again so "root" with a
// zero-width space cannot slip past it whatever produced the name.
func defaultName(name string) bool {
	return slices.Contains([]string{"root", "admin", "administrator", "userid"}, strings.ToLower(textclean.Clean(name, 0)))
}

func defaultNames(c evalCtx) outcome {
	a, o, ok := accountList(c)
	if !ok {
		return o
	}
	var hits []bmc.Account
	for _, acc := range a.on {
		if defaultName(acc.UserName) {
			hits = append(hits, acc)
		}
	}
	if len(hits) == 0 {
		return out(Pass, "", append([]string{"No enabled account has a factory default name."}, a.notes()...)...)
	}
	ev := []string{"Enabled with a factory default name: " + accountNames(hits, false) + ".",
		"oob-manager cannot check passwords: make sure the factory password is not still set."}
	return out(Warn, subjectNames(hits), append(ev, a.notes()...)...)
}

func ipmiAccounts(c evalCtx) outcome {
	a, o, ok := accountList(c)
	if !ok {
		return o
	}
	var ipmi, sol []bmc.Account
	known := false
	for _, acc := range a.on {
		known = known || acc.IPMI.Known || acc.SOL.Known
		if acc.IPMI.Value {
			ipmi = append(ipmi, acc)
		}
		if acc.SOL.Value {
			sol = append(sol, acc)
		}
	}
	lan := c.p.Redfish.Protocols.IPMI
	ev := append(accessLines(ipmi, sol), a.notes()...)
	switch {
	case len(ipmi) > 0 && lan.Known && lan.Value:
		subject := "ipmi=" + subjectNames(ipmi) + ";sol=" + subjectNames(sol)
		return out(Warn, subject, append([]string{"IPMI over LAN is on and these accounts can use it."}, ev...)...)
	case len(ipmi)+len(sol) > 0:
		return out(Info, "", append(ev, "IPMI over LAN is "+lanState(lan)+".")...)
	case !known:
		return out(Unknown, "", append([]string{"This BMC does not report per-account IPMI or serial-over-LAN access."}, a.notes()...)...)
	default:
		return out(Pass, "", append([]string{"No enabled account has IPMI LAN or serial-over-LAN access."}, a.notes()...)...)
	}
}

func accessLines(ipmi, sol []bmc.Account) []string {
	var ev []string
	if len(ipmi) > 0 {
		ev = append(ev, "IPMI LAN access: "+accountNames(ipmi, false)+".")
	}
	if len(sol) > 0 {
		ev = append(ev, "Serial over LAN: "+accountNames(sol, false)+".")
	}
	return ev
}

func lanState(f bmc.Fact[bool]) string {
	if !f.Known {
		return "not reported"
	}
	return onOff(f.Value)
}

func passwordPolicy(c evalCtx) outcome {
	a, n := c.p.Redfish.Accounts, c.p.Redfish.Network
	if !a.Read.OK() && !n.LoginBlocking.Known {
		return unread(a.Read, "the password policy")
	}
	var weak, ev []string
	switch l := a.MinPasswordLength; {
	case l.Known && l.Value < minPasswordLength:
		weak, ev = append(weak, "min-length"), append(ev, minLengthText(l.Value)+from(l.Source)+".")
	case l.Known:
		ev = append(ev, fmt.Sprintf("Minimum password length %d%s.", l.Value, from(l.Source)))
	}
	lock := lockoutText(a, n)
	if lock == "" && noLockout(a, n, c.p.Redfish.Attributes) {
		weak, ev = append(weak, "no-lockout"), append(ev, "No account lockout and no blocking after failed logins.")
	}
	if lock != "" {
		ev = append(ev, lock)
	}
	switch {
	case len(weak) > 0:
		return out(Warn, strings.Join(weak, ","), ev...)
	case lock != "" && a.MinPasswordLength.Known:
		return out(Pass, "", ev...)
	case !a.Read.OK():
		o := unread(a.Read, "the password policy")
		return out(o.result, "", append(ev, o.evidence...)...)
	default:
		return out(Unknown, "", append(ev, "The BMC does not report its whole password and lockout policy.")...)
	}
}

// noLockout: the DMTF lockout threshold is 0 and no other protection is known. A vendor
// attribute document that could not be read may hold one (Dell IP blocking), so then
// nothing is concluded.
func noLockout(a bmc.AccountFacts, n bmc.NetworkFacts, attrs bmc.Section) bool {
	if !a.LockoutThreshold.Known || a.LockoutThreshold.Value > 0 {
		return false
	}
	if n.LoginBlocking.Known {
		return !n.LoginBlocking.Value
	}
	return attrs.State == bmc.ReadNotTried
}

func minLengthText(n int) string {
	if n <= 0 {
		return "No minimum password length is enforced"
	}
	return fmt.Sprintf("Passwords may be as short as %d characters", n)
}

// lockoutText describes the lockout protections that are on ("" = none known to be on).
func lockoutText(a bmc.AccountFacts, n bmc.NetworkFacts) string {
	var parts []string
	if t := a.LockoutThreshold; t.Known && t.Value > 0 {
		s := fmt.Sprintf("Accounts lock after %s", plural(t.Value, "failed login", "failed logins"))
		if d := a.LockoutDuration; d.Known && d.Value > 0 {
			s += " for " + d.Value.Round(time.Second).String()
		}
		parts = append(parts, s+from(t.Source)+".")
	}
	if b := n.LoginBlocking; b.Known && b.Value {
		parts = append(parts, "Addresses are blocked after repeated failed logins"+from(b.Source)+".")
	}
	return strings.Join(parts, " ")
}

func adminAccounts(c evalCtx) outcome {
	a, o, ok := accountList(c)
	if !ok {
		return o
	}
	var admins []bmc.Account
	for _, acc := range a.on {
		if acc.Role == "Administrator" {
			admins = append(admins, acc)
		}
	}
	ev := []string{fmt.Sprintf("%s: %s.", plural(len(admins), "enabled Administrator account", "enabled Administrator accounts"),
		orNone(accountNames(admins, false)))}
	return out(Info, "", append(ev, a.notes()...)...)
}
