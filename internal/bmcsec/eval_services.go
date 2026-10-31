package bmcsec

import (
	"fmt"
	"slices"
	"strconv"

	"oob-manager/internal/bmc"
)

const cwe319 = "https://cwe.mitre.org/data/definitions/319.html"

func serviceEntries() []entry { return slices.Concat(cleartextEntries(), surfaceEntries()) }

// cleartextEntries are the services that expose credentials: IPMI, SNMP, Telnet, HTTP.
func cleartextEntries() []entry {
	return []entry{
		{check: Check{ID: "svc.ipmi", Group: GroupServices, Title: "IPMI over LAN",
			Why: "IPMI 2.0 hands anyone who can reach UDP port 623 a salted hash of any account's password before login " +
				"(RAKP, CVE-2013-4786). It is a flaw of the protocol that no firmware fixes, and the hash can be cracked offline.",
			Fix:  "Turn IPMI over LAN off unless a tool needs it. If one does, allow UDP 623 only from that tool and give every BMC account a long random password.",
			Dell: "racadm set iDRAC.IPMILan.Enable 0, or the IPMI settings of the iDRAC network page. oob-manager does not use IPMI on Dell servers.",
			Docs: "https://nvd.nist.gov/vuln/detail/CVE-2013-4786"},
			eval: ipmiLAN},
		{check: Check{ID: "svc.ipmi_cipher0", Group: GroupServices, Title: "IPMI cipher suite 0",
			Why:  "Cipher suite 0 has no authentication: any password, or none, logs in with the account's privileges.",
			Fix:  "Make sure cipher suite 0 is not allowed; prefer suite 17. ipmitool lan print lists the allowed suites under RMCP+ Cipher Suites.",
			Dell: "ipmitool -I lanplus -H <bmc> -U <user> lan print 1 shows the cipher suites and the privilege allowed per suite."},
			eval: ipmiCipherZero},
		{check: Check{ID: "svc.snmp", Group: GroupServices, Title: "SNMP v1 and v2c",
			Why:  "SNMP v1 and v2c send the community string, which works like a password, in clear, with no per-user access control.",
			Fix:  "Turn the SNMP agent off, or allow SNMPv3 only, with authentication and privacy.",
			Dell: "racadm set iDRAC.SNMP.AgentEnable 0, or set iDRAC.SNMP.SNMPProtocol to SNMPv3.",
			Docs: "https://www.rfc-editor.org/rfc/rfc3414"},
			eval: snmp},
		{check: Check{ID: "svc.telnet", Group: GroupServices, Title: "Telnet",
			Why:  "Telnet sends the login and the whole session, passwords included, in clear.",
			Fix:  "Turn Telnet off and use SSH.",
			Dell: "racadm set iDRAC.Telnet.Enable 0 (recent iDRAC9 firmware has no Telnet at all).",
			Docs: cwe319},
			eval: func(c evalCtx) outcome { return onIs(c, c.p.Redfish.Protocols.Telnet, "Telnet", Fail, "Telnet") }},
		{check: Check{ID: "svc.http", Group: GroupServices, Title: "Plain HTTP",
			Why:  "A login page served over plain HTTP sends the password in clear. A redirect to HTTPS protects people who type the address without https://.",
			Fix:  "Redirect HTTP to HTTPS, or turn plain HTTP off.",
			Dell: "racadm set iDRAC.WebServer.HttpsRedirection 1.",
			Docs: cwe319},
			eval: plainHTTP},
	}
}

// surfaceEntries are the other remote services: SSH, VNC, virtual media, SSDP, WS-Management.
func surfaceEntries() []entry {
	return []entry{
		{check: Check{ID: "svc.ssh", Group: GroupServices, Title: "SSH service",
			Why: "SSH is the BMC's command line: every account that can log in there can change BMC settings within its role. " +
				"A service nothing uses is attack surface.",
			Fix:  "Leave SSH on only if something uses it (oob-manager's serial console does), and limit who can reach port 22.",
			Dell: "racadm set iDRAC.SSH.Enable 0 when nothing needs it."},
			eval: sshService},
		{check: Check{ID: "svc.vnc", Group: GroupServices, Title: "VNC server",
			Why: "VNC is a remote console next to the BMC's own. Without TLS, the screen, the keystrokes and the VNC password travel in clear, " +
				"and a VNC password is at most 8 characters.",
			Fix:  "Turn the VNC server off unless oob-manager's graphical console uses it, and keep its TLS on.",
			Dell: "iDRAC.VNCServer.Enable and iDRAC.VNCServer.SSLEncryptionBitLength (VNC server settings).",
			Docs: cwe319},
			eval: vncServer},
		{check: Check{ID: "svc.virtual_media", Group: GroupServices, Title: "Virtual media",
			Why: "Virtual media lets a console user attach disk images to the host, a way to boot or plant anything. BMC virtual media " +
				"has had authentication bypass bugs (USBAnywhere, CVE-2019-16649).",
			Fix:  "Turn virtual media off when you do not use it.",
			Dell: "Set iDRAC.VirtualMedia.Attached to Detached.",
			Docs: "https://nvd.nist.gov/vuln/detail/CVE-2019-16649"},
			eval: func(c evalCtx) outcome {
				return onIs(c, c.p.Redfish.Protocols.VirtualMedia, "Virtual media", Info, "virtual media")
			}},
		{check: Check{ID: "svc.ssdp", Group: GroupServices, Title: "SSDP and UPnP",
			Why:  "SSDP answers discovery multicasts with details about the BMC and can be abused to amplify traffic towards a victim.",
			Fix:  "Turn SSDP off.",
			Docs: "https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks"},
			eval: func(c evalCtx) outcome { return onIs(c, c.p.Redfish.Protocols.SSDP, "SSDP", Warn, "SSDP") }},
		{check: Check{ID: "svc.wsman", Group: GroupServices, Title: "WS-Management",
			Why:  "WS-Management is a second management API on the HTTPS port, with the same accounts as the web interface. Every reachable API is attack surface.",
			Fix:  "If nothing uses it and the BMC can turn it off, do; otherwise let only management hosts reach the HTTPS port.",
			Dell: "iDRAC serves WS-Management at /wsman for remote RACADM and OpenManage tools."},
			eval: wsman},
	}
}

// onIs: a protocol that is on gives result; off passes; unreported is unknown or can't read.
func onIs(c evalCtx, f bmc.Fact[bool], name string, result Result, what string) outcome {
	switch {
	case !f.Known:
		return missing("whether "+what+" is on", c.p.Redfish.Protocols.Read, c.p.Redfish.Attributes)
	case f.Value:
		return out(result, "on", name+" is on"+from(f.Source)+".")
	default:
		return out(Pass, "", name+" is off"+from(f.Source)+".")
	}
}

func ipmiLAN(c evalCtx) outcome {
	pr := c.p.Redfish.Protocols
	o := onIs(c, pr.IPMI, "IPMI over LAN", Warn, "IPMI over LAN")
	if pr.IPMI.Value && pr.IPMIPrivLimit.Known {
		o.evidence = append(o.evidence, "Channel privilege limit: "+pr.IPMIPrivLimit.Value+from(pr.IPMIPrivLimit.Source)+".")
	}
	return o
}

func ipmiCipherZero(c evalCtx) outcome {
	pr := c.p.Redfish.Protocols
	switch {
	case pr.IPMICipherZero.Known && pr.IPMICipherZero.Value:
		return out(Fail, "cipher0", "Cipher suite 0 is accepted"+from(pr.IPMICipherZero.Source)+".")
	case pr.IPMICipherZero.Known:
		return out(Pass, "", "Cipher suite 0 is refused"+from(pr.IPMICipherZero.Source)+".")
	case pr.IPMI.Known && !pr.IPMI.Value:
		return out(Pass, "", "IPMI over LAN is off, so its cipher suites cannot be reached.")
	case pr.IPMI.Known:
		return out(Unknown, "", "The BMC does not report its IPMI cipher suites over Redfish, and oob-manager sends no IPMI packets to find out.")
	default:
		return missing("whether IPMI over LAN is on", pr.Read, c.p.Redfish.Attributes)
	}
}

func snmp(c evalCtx) outcome {
	pr := c.p.Redfish.Protocols
	switch {
	case !pr.SNMP.Known:
		return missing("whether the SNMP agent is on", pr.Read, c.p.Redfish.Attributes)
	case !pr.SNMP.Value:
		return out(Pass, "", "The SNMP agent is off"+from(pr.SNMP.Source)+".")
	case !pr.SNMPLegacy.Known:
		return out(Unknown, "", "The SNMP agent is on; this BMC does not report which SNMP versions it accepts.")
	case pr.SNMPLegacy.Value:
		return out(Warn, "v1-v2c", "The SNMP agent is on and accepts v1 and v2c"+from(pr.SNMPLegacy.Source)+".")
	default:
		return out(Pass, "", "The SNMP agent accepts SNMPv3 only"+from(pr.SNMPLegacy.Source)+".")
	}
}

// plainHTTP prefers what the probe saw on the HTTP port over what the BMC says.
func plainHTTP(c evalCtx) outcome {
	pr, h := c.p.Redfish.Protocols, c.p.HTTP
	if pr.HTTP.Known && !pr.HTTP.Value {
		return out(Pass, "", "Plain HTTP is off"+from(pr.HTTP.Source)+".")
	}
	port := "Port " + strconv.Itoa(h.Port)
	// The probe talks to whatever answers on the plain port, without credentials; unlike
	// the TLS probes it has no pin to tie the answer to the BMC.
	unpinned := fmt.Sprintf("Unauthenticated request to whatever answers on port %d; not tied to a pin.", h.Port)
	switch {
	case h.Read.OK() && h.ToHTTPS:
		return out(Pass, "", fmt.Sprintf("%s redirects to HTTPS (HTTP %d).", port, h.Status), unpinned)
	case h.Read.OK() && h.Redirect:
		return out(Warn, "redirect-http", fmt.Sprintf("%s redirects, but not to HTTPS (HTTP %d).", port, h.Status), unpinned)
	case h.Read.OK() && (h.Status/100 == 2 || h.Status == 401):
		return out(Warn, "status-"+strconv.Itoa(h.Status), fmt.Sprintf("%s answers without redirecting to HTTPS (HTTP %d).", port, h.Status), unpinned)
	case h.Read.OK():
		return out(Info, "status-"+strconv.Itoa(h.Status), fmt.Sprintf("%s answers HTTP %d without redirecting to HTTPS.", port, h.Status), unpinned)
	case h.Read.State == bmc.ReadFailed && h.Refused:
		// Only a refused connection means nothing listens; no route or a dialer refusal
		// say nothing about the port and fall through to "could not be read".
		return out(Pass, "", port+" is closed (connection refused).")
	}
	if r := pr.HTTPSRedirect; r.Known {
		if r.Value {
			return out(Pass, "", "The BMC redirects HTTP to HTTPS"+from(r.Source)+".")
		}
		return out(Warn, "no-redirect", "HTTP to HTTPS redirection is off"+from(r.Source)+".")
	}
	return unread(h.Read, "the HTTP port")
}

func sshService(c evalCtx) outcome {
	pr := c.p.Redfish.Protocols
	o := onIs(c, pr.SSH, "SSH", Info, "SSH")
	if pr.SSH.Value && pr.SSHPort.Known {
		o.evidence = append(o.evidence, "Port "+strconv.Itoa(pr.SSHPort.Value)+".")
	}
	if pr.SSH.Value && c.in.SerialSSH {
		o.evidence = append(o.evidence, "oob-manager's serial console uses it.")
	}
	return o
}

func vncServer(c evalCtx) outcome {
	pr := c.p.Redfish.Protocols
	if !pr.VNC.Known || !pr.VNC.Value {
		return onIs(c, pr.VNC, "The VNC server", Info, "the VNC server")
	}
	on := "The VNC server is on" + from(pr.VNC.Source)
	if pr.VNCPort.Known {
		on += ", port " + strconv.Itoa(pr.VNCPort.Value)
	}
	switch {
	case pr.VNCTLS.Known && pr.VNCTLS.Value == bmc.EncryptionOff:
		return out(Warn, "no-tls", on+", without TLS"+from(pr.VNCTLS.Source)+".")
	case pr.VNCTLS.Known && pr.VNCTLS.Value == bmc.EncryptionOptional:
		// Dell's "Auto Negotiate": a TLS client gets TLS, but a plain client gets plain VNC.
		return out(Warn, "tls-optional", on+"; TLS is optional: plain VNC is also accepted"+from(pr.VNCTLS.Source)+".")
	case pr.VNCTLS.Known:
		return out(Info, "", on+", with TLS required"+from(pr.VNCTLS.Source)+".")
	case c.in.VNC && c.in.VNCTLS && c.p.VNC.Usable():
		return out(Info, "", on+". oob-manager connects to it with TLS.")
	default:
		return out(Info, "", on+"; its TLS setting is not reported.")
	}
}

func wsman(c evalCtx) outcome {
	w := c.p.WSMan
	if !w.Read.OK() {
		return unread(w.Read, "the HTTPS port")
	}
	switch {
	case w.Status == 404 || w.Status == 410:
		return out(Pass, "", fmt.Sprintf("Nothing answers at /wsman (HTTP %d).", w.Status))
	case w.Status == w.ControlStatus || w.Status/100 == 3:
		return out(Unknown, "", fmt.Sprintf("/wsman answers like a path that does not exist (HTTP %d), so this says nothing about WS-Management.", w.Status))
	default:
		return out(Info, "status-"+strconv.Itoa(w.Status), fmt.Sprintf("/wsman answers HTTP %d where a missing path gets HTTP %d: WS-Management is on.",
			w.Status, w.ControlStatus))
	}
}
