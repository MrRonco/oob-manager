package settings

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"oob-manager/internal/config"
	"oob-manager/internal/store"
)

// Units of the Integrations keys.
const (
	UnitBool Unit = "bool" // on / off (radio buttons, always submitted)
	UnitText Unit = "text" // free text checked by config.ValidateGELF or config.ValidateGeneral
)

// IntegrationSpecs returns the Integrations section's keys in display order (fresh slice).
func IntegrationSpecs() []Spec {
	return []Spec{
		{Key: config.KeyGELFEnabled, Label: "Ship audit rows", Unit: UnitBool,
			Help: "Send a copy of every audit row to a GELF (Graylog-compatible) TCP or TLS input. The database copy is always kept."},
		{Key: config.KeyGELFAddress, Label: "Address", Unit: UnitText,
			Help: "host:port of the GELF input, for example 192.0.2.30:12201. It must be inside audit.gelf.allowed_networks."},
		{Key: config.KeyGELFTransport, Label: "Transport", Unit: UnitName,
			Help: "TLS with a pinned certificate, or plain TCP (unencrypted: only on a trusted network segment)."},
		{Key: config.KeyGELFServerName, Label: "Server name (TLS)", Unit: UnitText,
			Help: "Optional. Sent as SNI; empty sends the host part of the address when it is a name. The pin, not this name, decides trust."},
		{Key: config.KeyGELFPin, Label: "Certificate fingerprint (TLS)", Unit: UnitText,
			Help: "SHA-256 of the public key of the log server's certificate or of the CA that issued it. Fetch it, compare it, confirm it."},
	}
}

func integrationSpecFor(key string) (Spec, bool) {
	for _, s := range IntegrationSpecs() {
		if s.Key == key {
			return s, true
		}
	}
	return Spec{}, false
}

func getI(g config.GELF, key string) value {
	switch key {
	case config.KeyGELFEnabled:
		return value{b: g.Enabled}
	case config.KeyGELFAddress:
		return value{s: g.Address}
	case config.KeyGELFTransport:
		return value{s: g.Transport}
	case config.KeyGELFServerName:
		return value{s: g.ServerName}
	default: // config.KeyGELFPin
		return value{s: g.PinSHA256}
	}
}

// setI returns a copy of g with key set to v.
func setI(g config.GELF, key string, v value) config.GELF {
	switch key {
	case config.KeyGELFEnabled:
		g.Enabled = v.b
	case config.KeyGELFAddress:
		g.Address = v.s
	case config.KeyGELFTransport:
		g.Transport = v.s
	case config.KeyGELFServerName:
		g.ServerName = v.s
	case config.KeyGELFPin:
		g.PinSHA256 = v.s
	}
	return g
}

// normalisePin accepts a pin as BMC and log server pages print it (colons, spaces,
// upper case) and returns the stored form; anything else is left for the validator.
func normalisePin(raw string) string {
	return strings.ToLower(strings.NewReplacer(":", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(raw))
}

// checkGELF is ValidateGELF plus the static destination policy for an IP literal
// address (the integrations service also checks DNS answers and its own addresses).
func checkGELF(g config.GELF, nets []netip.Prefix) []string {
	if p := config.ValidateGELF(g); len(p) > 0 {
		return p
	}
	if !g.Enabled {
		return nil
	}
	host, _, err := net.SplitHostPort(g.Address)
	if err != nil {
		return []string{"audit.gelf.address must be host:port"}
	}
	if a, aerr := netip.ParseAddr(host); aerr == nil {
		if perr := config.GELFAddrAllowed(a, nets); perr != nil {
			return []string{"audit.gelf.address: " + perr.Error()}
		}
	}
	return nil
}

// resolveIntegrations applies the saved GELF rows over the file's target. Every
// decodable, non-shadowed row is applied, then the combination is checked: if it fails
// the validator or the static policy, every GELF row is ignored (the file's target
// runs), so a half-applied target never ships.
func resolveIntegrations(file config.Config, rows []store.SettingRow) (config.GELF, map[string]store.SettingRow, []string, string) {
	g := file.GELF()
	var ignored []string
	saved := map[string]store.SettingRow{}
	for _, row := range rows {
		spec, known := integrationSpecFor(row.Key)
		switch {
		case !known:
			continue
		case file.FileSets(row.Key):
			ignored = append(ignored, row.Key+": shadowed by config.yaml")
			continue
		}
		v, err := spec.decode(row.ValueJSON)
		if err != nil {
			ignored = append(ignored, fmt.Sprintf("%s: unreadable value %s", row.Key, row.ValueJSON))
			continue
		}
		g, saved[row.Key] = setI(g, row.Key, v), row
	}
	if p := checkGELF(g, file.GELFNetworks()); len(p) > 0 && len(saved) > 0 {
		note := "The GELF settings saved here are not in force (" + p[0] + "); the config.yaml or default target runs. Save valid values again."
		return file.GELF(), map[string]store.SettingRow{}, append(ignored, "saved GELF settings: "+p[0]), note
	}
	return g, saved, ignored, ""
}

func integrationFieldsOf(file config.Config, g config.GELF, saved map[string]store.SettingRow) []Field {
	specs := IntegrationSpecs()
	out := make([]Field, 0, len(specs))
	for _, s := range specs {
		f := Field{Spec: s, Value: s.display(getI(g, s.Key)), Default: s.display(getI(file.GELF(), s.Key)),
			Source: SourceDefault}
		if row, ok := saved[s.Key]; ok {
			f.Source, f.UpdatedAt, f.UpdatedBy = SourceDB, row.UpdatedAt, row.UpdatedBy
		}
		if file.FileSets(s.Key) {
			f.Source = SourceFile
		}
		out = append(out, f)
	}
	return out
}

// integrationValues maps every Integrations key to its display value (audit diffs).
func integrationValues(g config.GELF) map[string]string {
	out := map[string]string{}
	for _, s := range IntegrationSpecs() {
		out[s.Key] = s.display(getI(g, s.Key))
	}
	return out
}

// integrationsPublic is the Integrations redaction allow-list: every key (the address
// and the pin are public values; GELF has no credential).
func integrationsPublic(key string) bool {
	_, ok := integrationSpecFor(key)
	return ok
}
