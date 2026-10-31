package redfish

import (
	"context"
	"slices"
	"strings"

	"oob-manager/internal/bmc"
)

// maxNTPServers bounds the NTP servers kept as evidence.
const maxNTPServers = 3

// protocolDoc is one ManagerNetworkProtocol entry (Protocol in DSP0268).
type protocolDoc struct {
	ProtocolEnabled *bool `json:"ProtocolEnabled"`
	Port            *int  `json:"Port"`
}

// networkProtocolDoc is the part of ManagerNetworkProtocol the checks read. Fields the
// BMC may fill with secrets (SNMP community strings) are deliberately not decoded.
type networkProtocolDoc struct {
	HTTP, HTTPS, IPMI, SSH, Telnet, VirtualMedia, SSDP, KVMIP, RFB, DHCP, DHCPv6 *protocolDoc

	SNMP *snmpDoc `json:"SNMP"`
	NTP  *ntpDoc  `json:"NTP"`
}

type snmpDoc struct {
	protocolDoc
	EnableSNMPv1  *bool `json:"EnableSNMPv1"`
	EnableSNMPv2c *bool `json:"EnableSNMPv2c"`
}

type ntpDoc struct {
	protocolDoc
	NTPServers []string `json:"NTPServers"`
}

const npSource = "ManagerNetworkProtocol."

// postureProtocols reads ManagerNetworkProtocol. It returns the decoded document too:
// the DHCP entries describe the network settings.
func (r *postureRun) postureProtocols(ctx context.Context, uri string) (bmc.ProtocolFacts, networkProtocolDoc) {
	if uri == "" {
		return bmc.ProtocolFacts{Read: bmc.Section{State: bmc.ReadAbsent}}, networkProtocolDoc{}
	}
	var doc networkProtocolDoc
	if err := r.read(ctx, uri, &doc); err != nil {
		return bmc.ProtocolFacts{Read: sectionOf(err)}, networkProtocolDoc{}
	}
	p := bmc.ProtocolFacts{Read: bmc.SectionOf(nil),
		IPMI: enabled(doc.IPMI, "IPMI"), Telnet: enabled(doc.Telnet, "Telnet"), SSH: enabled(doc.SSH, "SSH"),
		HTTP: enabled(doc.HTTP, "HTTP"), HTTPS: enabled(doc.HTTPS, "HTTPS"),
		VirtualMedia: enabled(doc.VirtualMedia, "VirtualMedia"), SSDP: enabled(doc.SSDP, "SSDP"),
		KVMIP: enabled(doc.KVMIP, "KVMIP"), VNC: enabled(doc.RFB, "RFB"),
		SSHPort: port(doc.SSH, "SSH"), HTTPPort: port(doc.HTTP, "HTTP"), HTTPSPort: port(doc.HTTPS, "HTTPS"),
		VNCPort: port(doc.RFB, "RFB"),
	}
	if doc.SNMP != nil {
		p.SNMP = enabled(&doc.SNMP.protocolDoc, "SNMP")
		p.SNMPLegacy = snmpLegacy(doc.SNMP.EnableSNMPv1, doc.SNMP.EnableSNMPv2c)
	}
	if doc.NTP != nil {
		p.NTP = enabled(&doc.NTP.protocolDoc, "NTP")
		p.NTPServers = ntpServers(doc.NTP.NTPServers, npSource+"NTP.NTPServers")
	}
	return p, doc
}

func enabled(p *protocolDoc, name string) bmc.Fact[bool] {
	if p == nil || p.ProtocolEnabled == nil {
		return bmc.Fact[bool]{}
	}
	return bmc.FactOf(*p.ProtocolEnabled, npSource+name)
}

func port(p *protocolDoc, name string) bmc.Fact[int] {
	if p == nil || p.Port == nil || *p.Port < 1 || *p.Port > 65535 {
		return bmc.Fact[int]{}
	}
	return bmc.FactOf(*p.Port, npSource+name+".Port")
}

// snmpLegacy is known when the BMC reports either flag (ManagerNetworkProtocol v1_5+).
func snmpLegacy(v1, v2c *bool) bmc.Fact[bool] {
	if v1 == nil && v2c == nil {
		return bmc.Fact[bool]{}
	}
	on := (v1 != nil && *v1) || (v2c != nil && *v2c)
	return bmc.FactOf(on, npSource+"SNMP.EnableSNMPv1/v2c")
}

// ntpServers keeps the first non-empty, distinct servers (cleaned, capped). The list is
// optional in DSP0268: absent, the servers are unknown (an empty list is known and empty).
func ntpServers(list []string, source string) bmc.Fact[string] {
	if list == nil {
		return bmc.Fact[string]{}
	}
	var out []string
	for _, s := range list {
		s = clipField(clean(s), 64)
		if s != "" && !slices.Contains(out, s) && len(out) < maxNTPServers {
			out = append(out, s)
		}
	}
	return bmc.FactOf(strings.Join(out, ", "), source)
}

// networkFrom maps the DHCP entries: DHCP is the manager's own DHCPv4 client.
func networkFrom(doc networkProtocolDoc) bmc.NetworkFacts {
	return bmc.NetworkFacts{DHCP: enabled(doc.DHCP, "DHCP")}
}

// clipField cuts s to at most n bytes on a rune boundary.
func clipField(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
