package bmc

import (
	"context"
	"errors"
	"time"
)

// Posture is what one run of the BMC security checks read (docs/tech_doc.md §31):
// Redfish resources read with the read-only login, plus handshake-only probes of the
// BMC's network ports. It is a value; nothing in it is ever written to a BMC. Slices
// sit behind accessors that copy, so a Posture can be shared between readers.
type Posture struct {
	Started  time.Time
	Duration time.Duration
	Redfish  RedfishPosture
	Web      TLSProbe // the HTTPS port the app polls
	VNC      TLSProbe // the VNC port, when the graphical console uses VNC over TLS
	SSH      SSHProbe
	HTTP     HTTPProbe // the plain-HTTP port (does it redirect to HTTPS?)
	WSMan    WSManProbe
}

// TransportFailure is the class of a probe section that could not reach the BMC: a
// timeout, or unreachable without a refusal (no route). Such a run ran out of time or hit
// a network fault, and the fleet treats it as failed (the previous posture is kept, the
// run is retried with a backoff). A port that refused the connection is a result
// (nothing listens there), and a protocol error is an answer; neither counts. The VNC
// port never counts either: it serves one graphical client at a time, so a timeout there
// is expected while another session holds it (or, on an iDRAC8, while the last one
// drains), and the run is kept with that port's check unknown. ClassNone when every
// counted probe reached the BMC or was answered.
func (p Posture) TransportFailure() ErrorClass {
	for _, pr := range []struct {
		s       Section
		refused bool
	}{{p.Web.Read, p.Web.Refused}, {p.SSH.Read, p.SSH.Refused}, {p.HTTP.Read, p.HTTP.Refused}, {p.WSMan.Read, false}} {
		if pr.s.State != ReadFailed {
			continue
		}
		if pr.s.Class == ClassTimeout || (pr.s.Class == ClassUnreachable && !pr.refused) {
			return pr.s.Class
		}
	}
	return ClassNone
}

// PostureReader is implemented by drivers that can read a BMC's security settings
// over Redfish with GETs only (redfish.Driver, dellredfish.Driver). A section the
// read-only account may not read is reported as ReadForbidden, never as an error; the
// error is for a run that read nothing at all.
type PostureReader interface {
	Posture(ctx context.Context) (RedfishPosture, error)
}

// ReadState is how one posture source was read.
type ReadState string

// Read states.
const (
	ReadNotTried  ReadState = ""          // not attempted
	ReadOK        ReadState = "ok"        // read
	ReadAbsent    ReadState = "absent"    // the BMC does not offer it (404, or no link to it)
	ReadForbidden ReadState = "forbidden" // 401/403: the read-only account may not read it
	ReadFailed    ReadState = "failed"    // timeout, TLS, protocol…: see Section.Class
	ReadSkipped   ReadState = "skipped"   // deliberately not attempted: see Section.Why
)

// Section is the outcome of reading one posture source.
type Section struct {
	State ReadState
	Class ErrorClass // ReadFailed only
	Why   string     // ReadSkipped only: a short reason written by this app, never BMC text
}

// OK reports whether the source was read.
func (s Section) OK() bool { return s.State == ReadOK }

// SectionOf maps the error of a read to its Section: nil is ok, ErrNotFound absent,
// ErrAuth forbidden, anything else failed with its class.
func SectionOf(err error) Section {
	switch {
	case err == nil:
		return Section{State: ReadOK}
	case errors.Is(err, ErrNotFound):
		return Section{State: ReadAbsent}
	case errors.Is(err, ErrAuth):
		return Section{State: ReadForbidden}
	default:
		return Section{State: ReadFailed, Class: Classify(err)}
	}
}

// Skipped is a section deliberately not read, with the reason.
func Skipped(why string) Section { return Section{State: ReadSkipped, Why: why} }

// Fact is one setting a BMC reported. Known is false when no source reported it.
// Source names where it came from ("ManagerNetworkProtocol.IPMI",
// "Dell attribute IPMILan.1.Enable"); it is written by this app, never BMC text.
type Fact[T any] struct {
	Known  bool
	Value  T
	Source string
}

// FactOf returns a known fact.
func FactOf[T any](v T, source string) Fact[T] { return Fact[T]{Known: true, Value: v, Source: source} }

// Or returns f when it is known, else g.
func (f Fact[T]) Or(g Fact[T]) Fact[T] {
	if f.Known {
		return f
	}
	return g
}
