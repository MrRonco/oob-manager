package bmcsec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"oob-manager/internal/bmc"
)

// Inputs are the per-server settings the checks need besides the posture: all from the
// validated config or the server registry.
type Inputs struct {
	Kind string // BMC kind: idrac8, idrac9, redfish
	// Address is the BMC's address and port as configured ("host:port"). An accepted
	// risk binds to it: a server ID pointed at another BMC does not inherit acceptances.
	Address string
	// MinFirmware is security.min_firmware for Kind ("" = none configured).
	MinFirmware string
	// VNC and VNCTLS: the graphical console is set up as VNC (over TLS).
	VNC, VNCTLS bool
	// SerialSSH: the serial console uses the BMC's SSH service.
	SerialSSH bool
}

// Dell reports whether the server is a Dell iDRAC (Dell hints apply).
func (in Inputs) Dell() bool { return in.Kind == "idrac8" || in.Kind == "idrac9" }

// evalCtx is what a check sees.
type evalCtx struct {
	p   bmc.Posture
	in  Inputs
	now time.Time
}

// outcome is a check's result before it becomes a Finding.
type outcome struct {
	result   Result
	evidence []string
	subject  string
}

func out(r Result, subject string, evidence ...string) outcome {
	return outcome{result: r, evidence: evidence, subject: subject}
}

// entry is one check: its text, when it applies and how it is evaluated.
type entry struct {
	check   Check
	applies func(c evalCtx) bool // nil: always
	eval    func(c evalCtx) outcome
}

func entries() []entry {
	return slices.Concat(tlsEntries(), serviceEntries(), timeEntries(), accountEntries(), firmwareEntries(),
		networkEntries())
}

// Catalog returns every check in display order (a fresh slice).
func Catalog() []Check {
	es := entries()
	out := make([]Check, 0, len(es))
	for _, e := range es {
		out = append(out, e.check)
	}
	return out
}

// Evaluate runs every check that applies to the server over what one run read. It is a
// pure function of its arguments: expiry and drift are judged at now, so a report read
// later is still right without a new run.
func Evaluate(serverID string, p bmc.Posture, in Inputs, now time.Time) Report {
	c := evalCtx{p: p, in: in, now: now}
	r := Report{ServerID: serverID, CheckedAt: p.Started, Took: p.Duration}
	for _, e := range entries() {
		if e.applies != nil && !e.applies(c) {
			continue
		}
		o := e.eval(c)
		chk := e.check
		if !in.Dell() {
			chk.Dell = ""
		}
		r.Findings = append(r.Findings, Finding{Check: chk, Result: o.result, Evidence: o.evidence,
			Subject: clip(o.subject, maxSubject), SubjectHash: subjectHash(o.subject)})
	}
	return r
}

// maxSubject caps a finding's displayed subject (it is stored with an accepted risk);
// the subject hash covers the whole text.
const maxSubject = 200

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// subjectHash is the SHA-256 of a finding's whole subject, hex encoded.
func subjectHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// unread is the outcome of a check whose source was not read.
func unread(s bmc.Section, what string) outcome {
	switch s.State {
	case bmc.ReadForbidden:
		return out(CantRead, "", "Can't read "+what+" with the read-only account.")
	case bmc.ReadAbsent:
		return out(Unknown, "", "This BMC does not offer "+what+".")
	case bmc.ReadFailed:
		return out(Unknown, "", fmt.Sprintf("%s could not be read (%s).", upperFirst(what), classText(s.Class)))
	case bmc.ReadSkipped:
		return out(Unknown, "", "Not checked: "+s.Why+".")
	default:
		return out(Unknown, "", upperFirst(what)+" was not read.")
	}
}

// missing is the outcome of a fact no source reported: can't read when a section that
// could carry it was refused, unknown otherwise.
func missing(what string, secs ...bmc.Section) outcome {
	for _, s := range secs {
		if s.State == bmc.ReadForbidden {
			return out(CantRead, "", "Can't read "+what+" with the read-only account.")
		}
	}
	for _, s := range secs {
		if s.State == bmc.ReadFailed {
			return out(Unknown, "", fmt.Sprintf("%s could not be read (%s).", upperFirst(what), classText(s.Class)))
		}
	}
	return out(Unknown, "", "This BMC does not report "+what+".")
}

func classText(c bmc.ErrorClass) string {
	switch c {
	case bmc.ClassTimeout:
		return "timed out"
	case bmc.ClassUnreachable:
		return "not reachable"
	case bmc.ClassTLS:
		return "certificate mismatch"
	case bmc.ClassProtocol:
		return "unexpected answer"
	case bmc.ClassAuth:
		return "refused"
	case "":
		return "unknown error"
	default:
		return string(c)
	}
}

func upperFirst(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}

// from is " (source)" for evidence lines; "" when there is no source.
func from(source string) string {
	if source == "" {
		return ""
	}
	return " (" + source + ")"
}

func onOff(v bool) string {
	if v {
		return "on"
	}
	return "off"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

const dateFmt = "2006-01-02"
