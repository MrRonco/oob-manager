package redfish

import (
	"context"
	"errors"
	"slices"
	"time"

	"oob-manager/internal/bmc"
)

// accountServiceDoc is the policy part of AccountService.
type accountServiceDoc struct {
	Accounts                odataRef `json:"Accounts"`
	MinPasswordLength       *int     `json:"MinPasswordLength"`
	AccountLockoutThreshold *int     `json:"AccountLockoutThreshold"`
	AccountLockoutDuration  *int     `json:"AccountLockoutDuration"` // seconds
}

// accountDoc is a ManagerAccount: name, role, state and account types only. Password
// (always null on GET) and keys are never decoded.
type accountDoc struct {
	UserName     string   `json:"UserName"`
	RoleID       string   `json:"RoleId"`
	Enabled      *bool    `json:"Enabled"`
	Locked       *bool    `json:"Locked"`
	AccountTypes []string `json:"AccountTypes"`
}

const accountSource = "Redfish AccountService"

// maxLockoutSeconds bounds a lockout duration the checks take as a fact: anything over
// a year is nonsense (and a huge value would overflow a time.Duration).
const maxLockoutSeconds = 365 * 24 * 3600

// postureAccounts reads the password and lockout policy and, unless skipped, walks the
// accounts (at most maxPostureAccounts GETs; empty slots are left out).
func (r *postureRun) postureAccounts(ctx context.Context, service string, o PostureOptions) bmc.AccountFacts {
	if service == "" {
		return bmc.AccountFacts{Read: bmc.Section{State: bmc.ReadAbsent}}
	}
	var doc accountServiceDoc
	if err := r.read(ctx, service, &doc); err != nil {
		return bmc.AccountFacts{Read: sectionOf(err)}
	}
	a := bmc.AccountFacts{Read: bmc.SectionOf(nil),
		MinPasswordLength: optInt(doc.MinPasswordLength, "AccountService.MinPasswordLength"),
		LockoutThreshold:  optInt(doc.AccountLockoutThreshold, "AccountService.AccountLockoutThreshold"),
		LockoutDuration:   lockoutDuration(doc.AccountLockoutDuration),
	}
	if o.SkipAccountList {
		return a
	}
	uri := doc.Accounts.ID
	if uri == "" {
		uri = service + "/Accounts"
	}
	list, sec, partial := r.walkAccounts(ctx, uri)
	a.List, a.ListSource, a.Partial = sec, accountSource, partial
	return a.WithAccounts(list)
}

// lockoutDuration is AccountLockoutDuration as a fact: unknown when absent, negative or
// absurd (over maxLockoutSeconds).
func lockoutDuration(seconds *int) bmc.Fact[time.Duration] {
	if seconds == nil || *seconds < 0 || *seconds > maxLockoutSeconds {
		return bmc.Fact[time.Duration]{}
	}
	return bmc.FactOf(time.Duration(*seconds)*time.Second, "AccountService.AccountLockoutDuration")
}

// walkAccounts reads the collection's members up to the cap. partial reports a list
// that goes on beyond what was read (more members than the cap, or a next page).
func (r *postureRun) walkAccounts(ctx context.Context, uri string) (list []bmc.Account, sec bmc.Section, partial bool) {
	var col collectionDoc
	if err := r.read(ctx, uri, &col); err != nil {
		return nil, sectionOf(err), false
	}
	members := col.uris()
	partial = len(members) > maxPostureAccounts || col.NextLink != ""
	for _, m := range firstN(members, maxPostureAccounts) {
		var doc accountDoc
		err := r.read(ctx, m, &doc)
		if errors.Is(err, bmc.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, sectionOf(err), false
		}
		if acc, ok := accountOf(doc); ok {
			list = append(list, acc)
		}
	}
	return list, bmc.SectionOf(nil), partial
}

// accountOf maps one account; an empty slot (no user name) is not an account. A missing
// Enabled is an unknown state, never "disabled".
func accountOf(doc accountDoc) (bmc.Account, bool) {
	name := clipField(clean(doc.UserName), 64)
	if name == "" {
		return bmc.Account{}, false
	}
	acc := bmc.Account{UserName: name, Role: clipField(clean(doc.RoleID), 64), Locked: doc.Locked != nil && *doc.Locked}
	if doc.Enabled != nil {
		acc.Enabled = bmc.FactOf(*doc.Enabled, "ManagerAccount.Enabled")
	}
	if doc.AccountTypes != nil {
		acc.IPMI = bmc.FactOf(slices.Contains(doc.AccountTypes, "IPMI"), "ManagerAccount.AccountTypes")
	}
	return acc, true
}

func optInt(v *int, source string) bmc.Fact[int] {
	if v == nil {
		return bmc.Fact[int]{}
	}
	return bmc.FactOf(*v, source)
}
