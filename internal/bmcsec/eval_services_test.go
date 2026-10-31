package bmcsec

import (
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

func TestIPMIOverLAN(t *testing.T) {
	p := good()
	p.Redfish.Protocols.IPMI = on(true, "Dell attribute IPMILan.1.Enable")
	p.Redfish.Protocols.IPMIPrivLimit = bmc.FactOf("Administrator", "Dell attribute IPMILan.1.PrivLimit")
	f := expect(t, p, goodInputs(), "svc.ipmi", Warn, "IPMI over LAN is on (Dell attribute IPMILan.1.Enable).")
	if f.Subject != "on" || f.Evidence[1] != "Channel privilege limit: Administrator (Dell attribute IPMILan.1.PrivLimit)." {
		t.Fatalf("finding %+v", f)
	}
	expect(t, p, goodInputs(), "svc.ipmi_cipher0", Unknown, "sends no IPMI packets")
	p.Redfish.Protocols.IPMICipherZero = on(true, "OEM")
	expect(t, p, goodInputs(), "svc.ipmi_cipher0", Fail, "Cipher suite 0 is accepted (OEM).")
	p.Redfish.Protocols.IPMICipherZero = on(false, "OEM")
	expect(t, p, goodInputs(), "svc.ipmi_cipher0", Pass, "refused")
}

func TestUnreportedProtocolsAreUnknownOrCantRead(t *testing.T) {
	p := good()
	p.Redfish.Protocols = bmc.ProtocolFacts{Read: bmc.Section{State: bmc.ReadForbidden}}
	p.Redfish.Attributes = bmc.Section{State: bmc.ReadAbsent}
	p.Redfish.Network.DHCP = bmc.Fact[bool]{}
	for _, id := range []string{"svc.ipmi", "svc.ipmi_cipher0", "svc.snmp", "svc.telnet", "svc.ssh", "svc.vnc",
		"svc.virtual_media", "svc.ssdp", "svc.ntp", "svc.syslog", "net.dhcp"} {
		expect(t, p, goodInputs(), id, CantRead, "with the read-only account")
	}
	p.Redfish.Protocols = bmc.ProtocolFacts{Read: bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassTimeout}}
	expect(t, p, goodInputs(), "svc.telnet", Unknown, "could not be read (timed out)")
	p.Redfish.Protocols = bmc.ProtocolFacts{Read: ok()}
	expect(t, p, goodInputs(), "svc.ssdp", Unknown, "This BMC does not report whether SSDP is on.")
}

func TestSNMP(t *testing.T) {
	p := good()
	p.Redfish.Protocols.SNMP = on(true, "np")
	expect(t, p, goodInputs(), "svc.snmp", Unknown, "does not report which SNMP versions")
	p.Redfish.Protocols.SNMPLegacy = on(true, "Dell attribute SNMP.1.SNMPProtocol")
	expect(t, p, goodInputs(), "svc.snmp", Warn, "accepts v1 and v2c")
	p.Redfish.Protocols.SNMPLegacy = on(false, "x")
	expect(t, p, goodInputs(), "svc.snmp", Pass, "SNMPv3 only")
}

func TestTelnetVirtualMediaSSDP(t *testing.T) {
	p := good()
	p.Redfish.Protocols.Telnet = on(true, "np")
	expect(t, p, goodInputs(), "svc.telnet", Fail, "Telnet is on")
	p.Redfish.Protocols.VirtualMedia = on(true, "np")
	expect(t, p, goodInputs(), "svc.virtual_media", Info, "Virtual media is on")
	p.Redfish.Protocols.SSDP = on(true, "np")
	expect(t, p, goodInputs(), "svc.ssdp", Warn, "SSDP is on")
}

func TestPlainHTTP(t *testing.T) {
	cases := []struct {
		name  string
		probe bmc.HTTPProbe
		res   Result
		want  string
	}{
		{"redirect", bmc.HTTPProbe{Read: ok(), Port: 80, Status: 302, Redirect: true, ToHTTPS: true}, Pass, "Port 80 redirects to HTTPS (HTTP 302)."},
		{"to http", bmc.HTTPProbe{Read: ok(), Port: 80, Status: 302, Redirect: true}, Warn, "not to HTTPS"},
		{"page", bmc.HTTPProbe{Read: ok(), Port: 8080, Status: 200}, Warn, "Port 8080 answers without redirecting to HTTPS (HTTP 200)."},
		{"basic auth", bmc.HTTPProbe{Read: ok(), Port: 80, Status: 401}, Warn, "HTTP 401"},
		{"not found", bmc.HTTPProbe{Read: ok(), Port: 80, Status: 404}, Info, "HTTP 404"},
		{"closed", bmc.HTTPProbe{Read: bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassUnreachable}, Port: 80, Refused: true}, Pass, "Port 80 is closed (connection refused)."},
		// No route, a dialer refusal: nothing is known about the port.
		{"unreachable", bmc.HTTPProbe{Read: bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassUnreachable}, Port: 80}, Unknown, "The HTTP port could not be read (not reachable)."},
		{"timeout", bmc.HTTPProbe{Read: bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassTimeout}, Port: 80}, Unknown, "timed out"},
	}
	for _, c := range cases {
		p := good()
		p.HTTP = c.probe
		expect(t, p, goodInputs(), "svc.http", c.res, c.want)
	}
	p := good()
	p.HTTP = bmc.HTTPProbe{Read: bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassTimeout}}
	p.Redfish.Protocols.HTTPSRedirect = on(false, "Dell attribute WebServer.1.HttpsRedirection")
	expect(t, p, goodInputs(), "svc.http", Warn, "HTTP to HTTPS redirection is off")
	p.Redfish.Protocols.HTTPSRedirect = on(true, "attr")
	expect(t, p, goodInputs(), "svc.http", Pass, "redirects HTTP to HTTPS")
	p.Redfish.Protocols.HTTP = on(false, "np")
	expect(t, p, goodInputs(), "svc.http", Pass, "Plain HTTP is off")
}

func TestSSHService(t *testing.T) {
	in := goodInputs()
	in.SerialSSH = true
	f := expect(t, good(), in, "svc.ssh", Info, "SSH is on")
	if len(f.Evidence) != 3 || f.Evidence[2] != "oob-manager's serial console uses it." {
		t.Fatalf("evidence %v", f.Evidence)
	}
	p := good()
	p.Redfish.Protocols.SSH = on(false, "np")
	expect(t, p, in, "svc.ssh", Pass, "SSH is off")
}

func TestVNCServer(t *testing.T) {
	p := good()
	p.Redfish.Protocols.VNC, p.Redfish.Protocols.VNCPort = on(true, "attr"), bmc.FactOf(5901, "attr")
	expect(t, p, goodInputs(), "svc.vnc", Info, "oob-manager connects to it with TLS.")
	p.Redfish.Protocols.VNCTLS = bmc.FactOf(bmc.EncryptionOff, "Dell attribute VNCServer.1.SSLEncryptionBitLength")
	f := expect(t, p, goodInputs(), "svc.vnc", Warn, "port 5901, without TLS")
	if f.Subject != "no-tls" {
		t.Fatalf("subject %q", f.Subject)
	}
	// "Auto Negotiate": a TLS client gets TLS, a plain client gets plain VNC.
	p.Redfish.Protocols.VNCTLS = bmc.FactOf(bmc.EncryptionOptional, "attr")
	f = expect(t, p, goodInputs(), "svc.vnc", Warn, "TLS is optional: plain VNC is also accepted")
	if f.Subject != "tls-optional" {
		t.Fatalf("subject %q", f.Subject)
	}
	p.Redfish.Protocols.VNCTLS = bmc.FactOf(bmc.EncryptionRequired, "attr")
	expect(t, p, goodInputs(), "svc.vnc", Info, "with TLS required")
	p.Redfish.Protocols.VNCTLS = bmc.Fact[bmc.Encryption]{}
	in := goodInputs()
	in.VNC = false
	expect(t, p, in, "svc.vnc", Info, "its TLS setting is not reported")
}

func TestWSMan(t *testing.T) {
	p := good()
	p.WSMan = bmc.WSManProbe{Read: ok(), Status: 401, ControlStatus: 404}
	expect(t, p, goodInputs(), "svc.wsman", Info, "WS-Management is on")
	p.WSMan = bmc.WSManProbe{Read: ok(), Status: 401, ControlStatus: 401}
	expect(t, p, goodInputs(), "svc.wsman", Unknown, "says nothing")
	p.WSMan = bmc.WSManProbe{Read: ok(), Status: 302, ControlStatus: 404}
	expect(t, p, goodInputs(), "svc.wsman", Unknown, "")
	p.WSMan = bmc.WSManProbe{Read: bmc.Section{State: bmc.ReadFailed, Class: bmc.ClassTLS}}
	expect(t, p, goodInputs(), "svc.wsman", Unknown, "certificate mismatch")
}

func TestNTPAndClock(t *testing.T) {
	p := good()
	p.Redfish.Protocols.NTP = on(false, "Dell attribute NTPConfigGroup.1.NTPEnable")
	expect(t, p, goodInputs(), "svc.ntp", Warn, "NTP is off")
	p.Redfish.Protocols.NTP, p.Redfish.Protocols.NTPServers = on(true, "np"), bmc.FactOf("", "np")
	expect(t, p, goodInputs(), "svc.ntp", Warn, "no server is set")
	p.Redfish.Protocols.NTPServers = bmc.Fact[string]{}
	expect(t, p, goodInputs(), "svc.ntp", Pass, "NTP is on (np).")

	p = good()
	p.Redfish.Clock.BMCTime = now.Add(-5 * time.Minute)
	f := expect(t, p, goodInputs(), "svc.clock", Warn, "5 minutes behind")
	if f.Subject != "behind" {
		t.Fatalf("subject %q", f.Subject)
	}
	p.Redfish.Clock.BMCTime = now.Add(3 * time.Hour)
	expect(t, p, goodInputs(), "svc.clock", Warn, "3 hours ahead of")
	p.Redfish.Clock.BMCTime = now.Add(40 * time.Second)
	expect(t, p, goodInputs(), "svc.clock", Pass, "Within 40 seconds")
	p.Redfish.Clock.BMCTime, p.Redfish.Clock.After = now.Add(30*time.Second), now.Add(30*time.Second)
	expect(t, p, goodInputs(), "svc.clock", Pass, "Within 1 second")
	p.Redfish.Clock = bmc.ClockFacts{Read: bmc.Section{State: bmc.ReadForbidden}}
	expect(t, p, goodInputs(), "svc.clock", CantRead, "")
}

func TestSyslog(t *testing.T) {
	p := good()
	p.Redfish.Protocols.Syslog = on(false, "attr")
	expect(t, p, goodInputs(), "svc.syslog", Info, "Remote syslog is off")
	p.Redfish.Protocols.Syslog, p.Redfish.Protocols.SyslogServers = on(true, "attr"), bmc.FactOf(0, "attr")
	expect(t, p, goodInputs(), "svc.syslog", Info, "no server is set")
	p.Redfish.Protocols.SyslogServers = bmc.FactOf(2, "attr")
	expect(t, p, goodInputs(), "svc.syslog", Pass, "to 2 servers")
	p.Redfish.Protocols.SyslogServers = bmc.Fact[int]{}
	expect(t, p, goodInputs(), "svc.syslog", Pass, "Remote syslog is on (attr).")
}

// TestClockDriftThreshold pins the drift threshold: 60 s passes, 61 s warns.
func TestClockDriftThreshold(t *testing.T) {
	p := good()
	p.Redfish.Clock.BMCTime = now.Add(-60 * time.Second)
	expect(t, p, goodInputs(), "svc.clock", Pass, "Within 60 seconds")
	p.Redfish.Clock.BMCTime = now.Add(-61 * time.Second)
	expect(t, p, goodInputs(), "svc.clock", Warn, "61 seconds behind")
}
