package dellredfish

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/textclean"
)

// dellAttrs holds the allowlisted iDRAC attributes of one read.
type dellAttrs map[string]json.RawMessage

// userAttr matches the per-account keys that are kept (never Password or its hashes).
var userAttr = regexp.MustCompile(`^Users\.([1-9]|1[0-6])\.(UserName|Enable|Privilege|IpmiLanPrivilege|SolEnable)$`)

// attrKeep reports whether an attribute key is on the allowlist. A switch, not a map:
// no package-level mutable state.
func attrKeep(key string) bool {
	switch key {
	case "IPMILan.1.Enable", "IPMILan.1.PrivLimit",
		"Telnet.1.Enable", "SSH.1.Enable", "SSH.1.Port",
		"WebServer.1.HttpsRedirection", "WebServer.1.HttpPort", "WebServer.1.HttpsPort", "WebServer.1.TLSProtocol",
		"SNMP.1.AgentEnable", "SNMP.1.SNMPProtocol",
		"VNCServer.1.Enable", "VNCServer.1.Port", "VNCServer.1.SSLEncryptionBitLength",
		"NTPConfigGroup.1.NTPEnable", "NTPConfigGroup.1.NTP1", "NTPConfigGroup.1.NTP2", "NTPConfigGroup.1.NTP3",
		"SysLog.1.SysLogEnable", "SysLog.1.Server1", "SysLog.1.Server2", "SysLog.1.Server3",
		"IPv4.1.DHCPEnable", "IPv6.1.Enable",
		"IPBlocking.1.RangeEnable", "IPBlocking.1.RangeAddr", "IPBlocking.1.RangeMask", "IPBlocking.1.BlockEnable":
		return true
	default:
		return userAttr.MatchString(key)
	}
}

// keepAttrs copies the allowlisted keys and drops the rest of the document.
func keepAttrs(all map[string]json.RawMessage) dellAttrs {
	out := dellAttrs{}
	for k, v := range all {
		if attrKeep(k) {
			out[k] = v
		}
	}
	return out
}

const maxAttrText = 64

// str is a string attribute, sanitized (textclean: invalid UTF-8, control and format
// characters out), trimmed and capped.
func (a dellAttrs) str(key string) (string, bool) {
	var s string
	if raw, ok := a[key]; !ok || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return textclean.Clean(s, maxAttrText), true
}

func (a dellAttrs) num(key string) (int, bool) {
	var n int
	if raw, ok := a[key]; !ok || json.Unmarshal(raw, &n) != nil {
		return 0, false
	}
	return n, true
}

// onOff reads Dell's "Enabled"/"Disabled" (or a JSON boolean).
func (a dellAttrs) onOff(key string) (bool, bool) {
	if s, ok := a.str(key); ok {
		switch strings.ToLower(s) {
		case "enabled":
			return true, true
		case "disabled":
			return false, true
		}
		return false, false
	}
	var b bool
	if raw, ok := a[key]; ok && json.Unmarshal(raw, &b) == nil {
		return b, true
	}
	return false, false
}

func source(key string) string { return "Dell attribute " + key }

func (a dellAttrs) flag(key string) bmc.Fact[bool] {
	if v, ok := a.onOff(key); ok {
		return bmc.FactOf(v, source(key))
	}
	return bmc.Fact[bool]{}
}

func (a dellAttrs) text(key string) bmc.Fact[string] {
	if v, ok := a.str(key); ok && v != "" {
		return bmc.FactOf(v, source(key))
	}
	return bmc.Fact[string]{}
}

func (a dellAttrs) port(key string) bmc.Fact[int] {
	if v, ok := a.num(key); ok && v >= 1 && v <= 65535 {
		return bmc.FactOf(v, source(key))
	}
	return bmc.Fact[int]{}
}

// apply lays the attributes over the generic posture: a reported attribute wins over the
// DMTF value (it is the setting the iDRAC itself uses).
func (a dellAttrs) apply(p bmc.RedfishPosture, users []bmc.Account) bmc.RedfishPosture {
	p.Protocols = a.protocols(p.Protocols)
	p.Network = a.network(p.Network)
	p.Accounts = a.accounts(p.Accounts, users)
	return p
}

func (a dellAttrs) protocols(p bmc.ProtocolFacts) bmc.ProtocolFacts {
	p.IPMI = a.flag("IPMILan.1.Enable").Or(p.IPMI)
	p.IPMIPrivLimit = a.text("IPMILan.1.PrivLimit").Or(p.IPMIPrivLimit)
	p.Telnet = a.flag("Telnet.1.Enable").Or(p.Telnet)
	p.SSH, p.SSHPort = a.flag("SSH.1.Enable").Or(p.SSH), a.port("SSH.1.Port").Or(p.SSHPort)
	p.HTTPSRedirect = a.flag("WebServer.1.HttpsRedirection").Or(p.HTTPSRedirect)
	p.HTTPPort, p.HTTPSPort = a.port("WebServer.1.HttpPort").Or(p.HTTPPort), a.port("WebServer.1.HttpsPort").Or(p.HTTPSPort)
	p.WebTLSPolicy = a.text("WebServer.1.TLSProtocol").Or(p.WebTLSPolicy)
	p.SNMP, p.SNMPLegacy = a.flag("SNMP.1.AgentEnable").Or(p.SNMP), a.snmpLegacy().Or(p.SNMPLegacy)
	p.VNC, p.VNCPort = a.flag("VNCServer.1.Enable").Or(p.VNC), a.port("VNCServer.1.Port").Or(p.VNCPort)
	p.VNCTLS = a.vncTLS().Or(p.VNCTLS)
	p.NTP = a.flag("NTPConfigGroup.1.NTPEnable").Or(p.NTP)
	p.NTPServers = a.list("NTPConfigGroup.1.NTP", 3).Or(p.NTPServers)
	p.Syslog = a.flag("SysLog.1.SysLogEnable").Or(p.Syslog)
	p.SyslogServers = a.count("SysLog.1.Server", 3).Or(p.SyslogServers)
	return p
}

// snmpLegacy: SNMPProtocol "All" accepts v1, v2c and v3; "SNMPv3" only v3.
func (a dellAttrs) snmpLegacy() bmc.Fact[bool] {
	const key = "SNMP.1.SNMPProtocol"
	switch v, _ := a.str(key); strings.ToLower(v) {
	case "all":
		return bmc.FactOf(true, source(key))
	case "snmpv3":
		return bmc.FactOf(false, source(key))
	default:
		return bmc.Fact[bool]{}
	}
}

// vncTLS: SSLEncryptionBitLength "Disabled" is plain VNC; "Auto Negotiate" serves TLS
// to a TLS client and plain VNC to a plain one (optional); a bit length ("128-Bit or
// higher") requires TLS.
func (a dellAttrs) vncTLS() bmc.Fact[bmc.Encryption] {
	const key = "VNCServer.1.SSLEncryptionBitLength"
	v, ok := a.str(key)
	switch {
	case !ok || v == "":
		return bmc.Fact[bmc.Encryption]{}
	case strings.EqualFold(v, "disabled"):
		return bmc.FactOf(bmc.EncryptionOff, source(key))
	case strings.EqualFold(v, "auto negotiate"):
		return bmc.FactOf(bmc.EncryptionOptional, source(key))
	default:
		return bmc.FactOf(bmc.EncryptionRequired, source(key))
	}
}

// list joins prefix1..prefixN (non-empty, distinct).
func (a dellAttrs) list(prefix string, n int) bmc.Fact[string] {
	var out []string
	found := false
	for i := 1; i <= n; i++ {
		v, ok := a.str(prefix + strconv.Itoa(i))
		found = found || ok
		if ok && v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	if !found {
		return bmc.Fact[string]{}
	}
	return bmc.FactOf(strings.Join(out, ", "), source(prefix+"1-"+strconv.Itoa(n)))
}

// count counts the non-empty prefix1..prefixN.
func (a dellAttrs) count(prefix string, n int) bmc.Fact[int] {
	c, found := 0, false
	for i := 1; i <= n; i++ {
		v, ok := a.str(prefix + strconv.Itoa(i))
		found = found || ok
		if ok && v != "" {
			c++
		}
	}
	if !found {
		return bmc.Fact[int]{}
	}
	return bmc.FactOf(c, source(prefix+"1-"+strconv.Itoa(n)))
}

func (a dellAttrs) network(n bmc.NetworkFacts) bmc.NetworkFacts {
	n.IPFilter = a.flag("IPBlocking.1.RangeEnable").Or(n.IPFilter)
	addr, _ := a.str("IPBlocking.1.RangeAddr")
	mask, _ := a.str("IPBlocking.1.RangeMask")
	if r := rangeCIDR(addr, mask); r != "" {
		n.IPFilterRange = bmc.FactOf(r, source("IPBlocking.1.RangeAddr/RangeMask"))
	}
	n.LoginBlocking = a.flag("IPBlocking.1.BlockEnable").Or(n.LoginBlocking)
	n.DHCP = a.flag("IPv4.1.DHCPEnable").Or(n.DHCP)
	n.IPv6 = a.flag("IPv6.1.Enable").Or(n.IPv6)
	return n
}

// rangeCIDR writes an address and a netmask as a CIDR ("" for an invalid address); a
// mask that is not contiguous is shown as is.
func rangeCIDR(addr, mask string) string {
	a, err := netip.ParseAddr(addr)
	if err != nil || !a.Is4() {
		return ""
	}
	if mask == "" {
		return a.String()
	}
	m, err := netip.ParseAddr(mask)
	if err != nil || !m.Is4() {
		return a.String()
	}
	b := m.As4()
	bits, ok := maskBits(b)
	if !ok {
		return a.String() + " mask " + m.String()
	}
	return netip.PrefixFrom(a, bits).Masked().String()
}

func maskBits(b [4]byte) (int, bool) {
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	n := 0
	for n < 32 && v&(1<<(31-n)) != 0 {
		n++
	}
	return n, n == 32 || v<<n == 0
}

// dellRole names an iDRAC privilege bitmask: the three built-in roles, else custom.
func dellRole(priv int) string {
	switch priv {
	case 0x1FF:
		return "Administrator"
	case 0x1F3:
		return "Operator"
	case 0x1:
		return "ReadOnly"
	case 0:
		return "None"
	default:
		return fmt.Sprintf("Custom (privilege 0x%x)", priv)
	}
}
