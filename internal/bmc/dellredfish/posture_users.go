package dellredfish

import (
	"strconv"
	"strings"

	"oob-manager/internal/bmc"
)

// maxUserSlots is the number of iDRAC account slots.
const maxUserSlots = 16

const usersSource = "Dell attributes Users.*"

// users lists the named accounts of the Users.N attributes, in slot order (empty slots
// are left out). Nil when the document lists none.
func (a dellAttrs) users() []bmc.Account {
	var out []bmc.Account
	for n := 1; n <= maxUserSlots; n++ {
		if acc, ok := a.user(n); ok {
			out = append(out, acc)
		}
	}
	return out
}

func (a dellAttrs) user(n int) (bmc.Account, bool) {
	key := func(field string) string { return "Users." + strconv.Itoa(n) + "." + field }
	name, ok := a.str(key("UserName"))
	if !ok || name == "" {
		return bmc.Account{}, false
	}
	acc := bmc.Account{UserName: name, Enabled: a.flag(key("Enable"))} // unknown when the slot has no Enable
	if priv, ok := a.num(key("Privilege")); ok {
		acc.Role = dellRole(priv)
	}
	acc.IPMI, acc.SOL = a.ipmiAccess(key("IpmiLanPrivilege")), a.flag(key("SolEnable"))
	return acc, true
}

// ipmiAccess: any IPMI LAN privilege other than "No Access" lets the account use IPMI.
func (a dellAttrs) ipmiAccess(key string) bmc.Fact[bool] {
	v, ok := a.str(key)
	if !ok || v == "" {
		return bmc.Fact[bool]{}
	}
	return bmc.FactOf(!strings.EqualFold(v, "No Access"), source(key))
}

// accounts fills the skipped account walk with the attribute users (Posture skips the
// walk exactly when the attributes list users).
func (a dellAttrs) accounts(f bmc.AccountFacts, users []bmc.Account) bmc.AccountFacts {
	if len(users) == 0 || f.List.State != bmc.ReadNotTried {
		return f
	}
	f.List, f.ListSource = bmc.SectionOf(nil), usersSource
	return f.WithAccounts(users)
}
