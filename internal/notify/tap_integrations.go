package notify

import (
	"encoding/json"
	"strings"
)

// integrationsChange is one changed GELF field with its values before and after.
type integrationsChange struct {
	Field  string `json:"field"`
	Before string `json:"before"`
	After  string `json:"after"`
}

// integrationsParams is the part of an admin.integrations.update or .reset row the tap
// reads: the changed GELF fields with their values before and after (all public).
type integrationsParams struct {
	Changes []integrationsChange `json:"changes"`
}

// integrations reports a change of the audit stream's destination (security.md T10):
// the people alerted learn that the audit copy was redirected, even when the log server
// that should record it is the one being replaced. Critical when shipping is turned
// off, TLS is dropped for plain TCP, or the address, the pin or the server name
// changes; a warning otherwise (for example plain TCP to TLS). Turning shipping on
// with a first address, pin or server name (empty before) is a warning too: nothing
// was shipped or trusted before, so nothing is redirected (the first Fetch and confirm).
func (t *Tap) integrations(r record) Event {
	var p integrationsParams
	_ = json.Unmarshal([]byte(r.params), &p)
	e := Event{ID: newEventID(), Class: ClassAudit, Severity: SeverityWarning, Key: "audit/integrations", At: t.now()}
	enabling := turnsShippingOn(p.Changes)
	var lines []string
	for _, c := range p.Changes {
		if criticalChange(c, enabling) {
			e.Severity = SeverityCritical
		}
		lines = append(lines, c.Field+": "+orText(c.Before, "(none)")+" → "+orText(c.After, "(none)"))
	}
	e.Title = "Audit shipping changed by " + r.principal
	e.Message = r.principal + " changed where the audit log's off-box copy goes (Settings → Integrations): " +
		orText(strings.Join(lines, "; "), "no field listed") + "."
	return e
}

func turnsShippingOn(changes []integrationsChange) bool {
	for _, c := range changes {
		if c.Field == "gelf.enabled" && c.Before == "off" && c.After == "on" {
			return true
		}
	}
	return false
}

// criticalChange: shipping off, TLS dropped, or a different address, pin or server name
// (a different pin or name trusts a different key or name). A first value set while
// shipping is being turned on (enabling) is not a redirection.
func criticalChange(c integrationsChange, enabling bool) bool {
	switch c.Field {
	case "gelf.enabled":
		return c.Before == "on" && c.After == "off"
	case "gelf.transport":
		return c.Before == "tls" && c.After == "tcp"
	case "gelf.address", "gelf.pin_sha256", "gelf.server_name":
		return c.Before != c.After && (c.Before != "" || !enabling)
	}
	return false
}
