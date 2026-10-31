// Package bmcsec is the BMC security check panel (roadmap R5, docs/tech_doc.md §31): a
// catalog of read-only checks, their evaluation over what one run read from a BMC
// (bmc.Posture), the admin's accepted risks, and the notifications of new findings.
//
// Every check only reports. Nothing here, and nothing that collects its input, writes to
// a BMC: fixing a finding is BMC configuration, which this app leaves to the vendor's
// own tools (CLAUDE.md rule 11). A check the read-only account may not read answers
// "can't read with the read-only account" instead of asking for more BMC privileges.
package bmcsec

import "time"

// Result is the outcome of one check.
type Result string

// Results, from worst to best by Rank.
const (
	Fail     Result = "fail"
	Warn     Result = "warn"
	CantRead Result = "cant-read" // the read-only account may not read it
	Unknown  Result = "unknown"   // not reported, or the read failed
	Info     Result = "info"      // worth knowing, not a problem by itself
	Pass     Result = "pass"
)

// Results returns every result, worst first (a fresh slice).
func Results() []Result { return []Result{Fail, Warn, CantRead, Unknown, Info, Pass} }

// Rank orders results: higher is worse.
func (r Result) Rank() int {
	switch r {
	case Fail:
		return 5
	case Warn:
		return 4
	case CantRead:
		return 3
	case Unknown:
		return 2
	case Info:
		return 1
	default:
		return 0
	}
}

// Problem reports whether the result is a finding (warn or fail): only those are
// counted as problems, notified and can be accepted as a risk.
func (r Result) Problem() bool { return r == Warn || r == Fail }

// Label is the result as shown in the UI.
func (r Result) Label() string {
	switch r {
	case Fail:
		return "Fail"
	case Warn:
		return "Warning"
	case CantRead:
		return "Can't read"
	case Unknown:
		return "Unknown"
	case Info:
		return "Info"
	default:
		return "Pass"
	}
}

// Group is a section of the panel.
type Group string

// Groups.
const (
	GroupTLS      Group = "tls"
	GroupServices Group = "services"
	GroupAccounts Group = "accounts"
	GroupFirmware Group = "firmware"
	GroupNetwork  Group = "network"
)

// Groups returns every group in display order (a fresh slice).
func Groups() []Group {
	return []Group{GroupTLS, GroupServices, GroupAccounts, GroupFirmware, GroupNetwork}
}

// Title is the group's heading.
func (g Group) Title() string {
	switch g {
	case GroupTLS:
		return "TLS and SSH"
	case GroupServices:
		return "Services and protocols"
	case GroupAccounts:
		return "Accounts"
	case GroupFirmware:
		return "Firmware and license"
	default:
		return "Network"
	}
}

// Check is one catalog entry. Its text is written by this app, never BMC text.
type Check struct {
	ID    string
	Group Group
	Title string
	Why   string // why it matters
	Fix   string // what to do, on any BMC
	Dell  string // a Dell iDRAC hint ("" = none)
	Docs  string // a public reference ("" = none)
}

// Finding is one check's result for one server.
type Finding struct {
	Check  Check
	Result Result
	// Evidence is what the check saw, in short sentences. BMC-supplied values in it are
	// sanitized when they are read and escaped when they are rendered.
	Evidence []string
	// Subject identifies what was found (a certificate fingerprint, account names, a
	// version), clipped for display; SubjectHash is the SHA-256 (hex) of the whole
	// subject. An accepted risk covers exactly this result and this hash.
	Subject     string
	SubjectHash string
	// Accepted is set when an admin accepted this exact finding as a risk.
	Accepted *Acceptance
}

// Seen is the finding as the page showed it (result and subject hash): the accept form
// carries it, so an acceptance can only be made for the finding the admin looked at.
func (f Finding) Seen() string { return string(f.Result) + "|" + f.SubjectHash }

// Acceptance is an admin's decision to accept one finding as a risk. It binds to the
// check, the result, the subject hash and the BMC address the server had.
type Acceptance struct {
	ServerID, ServerAddr, CheckID string
	Result                        Result
	Subject, SubjectHash          string
	Comment                       string
	By                            string
	At                            time.Time
}

// Covers reports whether the acceptance is for exactly this finding.
func (a Acceptance) Covers(f Finding) bool {
	return f.Result.Problem() && a.CheckID == f.Check.ID && a.Result == f.Result && a.SubjectHash == f.SubjectHash
}

// Report is one server's evaluated checks, in catalog order.
type Report struct {
	ServerID  string
	CheckedAt time.Time // when the posture was read
	Took      time.Duration
	Findings  []Finding
}

// Counts are the findings per result. An accepted finding counts as Accepted only.
type Counts struct {
	Fail, Warn, CantRead, Unknown, Info, Pass, Accepted int
}

// Counts tallies the report.
func (r Report) Counts() Counts {
	var c Counts
	for _, f := range r.Findings {
		if f.Accepted != nil {
			c.Accepted++
			continue
		}
		switch f.Result {
		case Fail:
			c.Fail++
		case Warn:
			c.Warn++
		case CantRead:
			c.CantRead++
		case Unknown:
			c.Unknown++
		case Info:
			c.Info++
		default:
			c.Pass++
		}
	}
	return c
}

// Problems is the number of findings that need attention (warn or fail, not accepted).
func (c Counts) Problems() int { return c.Fail + c.Warn }

// Total is the number of checks in the report.
func (c Counts) Total() int {
	return c.Fail + c.Warn + c.CantRead + c.Unknown + c.Info + c.Pass + c.Accepted
}

// Finding returns the finding of a check.
func (r Report) Finding(checkID string) (Finding, bool) {
	for _, f := range r.Findings {
		if f.Check.ID == checkID {
			return f, true
		}
	}
	return Finding{}, false
}
