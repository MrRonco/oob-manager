package notify

import "time"

// ShipperTrust is what the audit shipper's certificate check reports (tech_doc §34).
type ShipperTrust int

// Shipper trust changes.
const (
	ShipperMismatch  ShipperTrust = iota // the certificate does not match the pin
	ShipperExpired                       // the right CA and name, but an expired certificate
	ShipperResolved                      // the destination passes the pin again
	ShipperWithdrawn                     // the alert is closed: shipping was disabled or moved
)

// ShipperTrustEvent is the audit shipper's certificate check as a trust event: critical,
// naming no server (it is not a BMC, so maintenance never suppresses it), one dedupe key
// for the problem and its end.
func ShipperTrustEvent(kind ShipperTrust, now time.Time) Event {
	e := Event{ID: newEventID(), Class: ClassTrust, Severity: SeverityCritical, Key: "trust/audit-shipper/gelf", At: now}
	switch kind {
	case ShipperResolved:
		e.Recovery = true
		e.Title = "Audit shipping: GELF server certificate check passes again"
		e.Message = "The log server's certificate matches the pin again; audit rows are shipped."
	case ShipperWithdrawn:
		e.Recovery = true
		e.Title = "Audit shipping: certificate alert closed"
		e.Message = "Audit shipping was turned off or moved to another log server in Settings → Integrations, so the " +
			"earlier certificate alert no longer applies."
	case ShipperExpired:
		e.Title = "Audit shipping: GELF server certificate expired"
		e.Message = "The log server's certificate was issued by the pinned CA for the right name but is outside its " +
			"validity period, so audit shipping is paused (rows queue, the database copy is kept). Renew the " +
			"certificate on the log server; shipping resumes on its own."
	default:
		e.Title = "Audit shipping: GELF server certificate mismatch"
		e.Message = "The log server's TLS certificate does not match the pinned fingerprint, so audit shipping is paused " +
			"(rows queue, the database copy is kept). Check the log server before confirming a new fingerprint in " +
			"Settings → Integrations."
	}
	return e
}
