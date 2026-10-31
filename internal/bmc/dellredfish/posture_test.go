package dellredfish

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/bmc/redfishmock"
)

var _ bmc.PostureReader = (*Driver)(nil)

const (
	attrs8     = "/redfish/v1/Managers/iDRAC.Embedded.1/Attributes"
	attrs9OEM  = "/redfish/v1/Managers/iDRAC.Embedded.1/Oem/Dell/DellAttributes/iDRAC.Embedded.1"
	accounts9  = "/redfish/v1/AccountService/Accounts"
	accountsR8 = "/redfish/v1/Managers/iDRAC.Embedded.1/AccountService/Accounts"
)

func posture(t *testing.T, d *Driver) bmc.RedfishPosture {
	t.Helper()
	p, err := d.Posture(ctx(t))
	if err != nil {
		t.Fatalf("Posture: %v", err)
	}
	return p
}

func TestPostureIDRAC8AttributesOverrideAndFill(t *testing.T) {
	d, s := newDriver(t, idrac8, redfishmock.WithTokenOnly())
	p := posture(t, d)
	if !p.Attributes.OK() {
		t.Fatalf("attributes %+v", p.Attributes)
	}
	pr := p.Protocols
	checks := []struct {
		name string
		got  bmc.Fact[bool]
		want bool
		src  string
	}{
		{"IPMI", pr.IPMI, true, "Dell attribute IPMILan.1.Enable"},
		{"Telnet", pr.Telnet, false, "Dell attribute Telnet.1.Enable"},
		{"SNMP", pr.SNMP, false, "Dell attribute SNMP.1.AgentEnable"},
		{"SNMPLegacy", pr.SNMPLegacy, true, "Dell attribute SNMP.1.SNMPProtocol"},
		{"HTTPSRedirect", pr.HTTPSRedirect, true, "Dell attribute WebServer.1.HttpsRedirection"},
		{"VNC", pr.VNC, true, "Dell attribute VNCServer.1.Enable"},
		{"Syslog", pr.Syslog, false, "Dell attribute SysLog.1.SysLogEnable"},
		{"IPFilter", p.Network.IPFilter, true, "Dell attribute IPBlocking.1.RangeEnable"},
		{"LoginBlocking", p.Network.LoginBlocking, true, "Dell attribute IPBlocking.1.BlockEnable"},
		{"DHCP", p.Network.DHCP, false, "Dell attribute IPv4.1.DHCPEnable"},
		{"IPv6", p.Network.IPv6, false, "Dell attribute IPv6.1.Enable"},
	}
	for _, c := range checks {
		if !c.got.Known || c.got.Value != c.want || c.got.Source != c.src {
			t.Errorf("%s = %+v, want %v from %q", c.name, c.got, c.want, c.src)
		}
	}
	if pr.IPMIPrivLimit.Value != "Administrator" || pr.VNCPort.Value != 5901 || pr.SSHPort.Value != 22 || pr.HTTPPort.Value != 80 {
		t.Errorf("values %+v %+v %+v %+v", pr.IPMIPrivLimit, pr.VNCPort, pr.SSHPort, pr.HTTPPort)
	}
	// "Auto Negotiate" also answers plain-text VNC: TLS is optional there, not on.
	if pr.VNCTLS.Value != bmc.EncryptionOptional || pr.VNCTLS.Source != "Dell attribute VNCServer.1.SSLEncryptionBitLength" {
		t.Errorf("VNC encryption %+v, want optional", pr.VNCTLS)
	}
	if p.Network.IPFilterRange.Value != "192.0.2.44/31" || pr.NTPServers.Value != "pool.ntp.org" || pr.WebTLSPolicy.Value != "TLS 1.1 and Higher" {
		t.Errorf("range %+v ntp %+v tls %+v", p.Network.IPFilterRange, pr.NTPServers, pr.WebTLSPolicy)
	}
	if pr.SyslogServers.Value != 0 || !pr.SyslogServers.Known {
		t.Errorf("syslog servers %+v", pr.SyslogServers)
	}
	if s.OtherWrites() != 0 {
		t.Fatalf("writes: %+v", s.Requests())
	}
}

func TestPostureIDRAC8AccountsFromAttributesInOneRead(t *testing.T) {
	d, s := newDriver(t, idrac8)
	a := posture(t, d).Accounts
	got := a.Accounts()
	if !a.List.OK() || a.ListSource != "Dell attributes Users.*" || len(got) != 3 {
		t.Fatalf("list %+v source %q accounts %+v", a.List, a.ListSource, got)
	}
	root, ro, op := got[0], got[1], got[2]
	if root.UserName != "root" || root.Role != "Administrator" || !root.Enabled.Value || !root.IPMI.Value || !root.SOL.Value {
		t.Errorf("root %+v", root)
	}
	if ro.UserName != "oob_ro" || ro.Role != "ReadOnly" || ro.IPMI.Value || ro.SOL.Value || !ro.IPMI.Known {
		t.Errorf("read-only %+v", ro)
	}
	if op.Role != "Custom (privilege 0x31)" {
		t.Errorf("operator role %+v", op)
	}
	for _, r := range s.Requests() {
		if strings.HasPrefix(r.Path, accountsR8) {
			t.Fatalf("accounts walked although the attributes list them: %s", r.Path)
		}
	}
	if !a.Read.OK() || !a.MinPasswordLength.Known {
		t.Fatalf("the AccountService policy is still read: %+v", a)
	}
}

func TestPostureIDRAC9UsesTheOEMAttributePath(t *testing.T) {
	d, s := newDriver(t, idrac9)
	p := posture(t, d)
	if !p.Attributes.OK() || p.Network.IPFilter.Value || !p.Network.DHCP.Value || !p.Network.IPv6.Value {
		t.Fatalf("attributes %+v network %+v", p.Attributes, p.Network)
	}
	if p.Protocols.SNMPLegacy.Value || !p.Protocols.SNMPLegacy.Known || p.Protocols.HTTPSRedirect.Value {
		t.Fatalf("protocols %+v", p.Protocols)
	}
	if p.Protocols.SyslogServers.Value != 1 || !p.Protocols.Syslog.Value {
		t.Fatalf("syslog %+v %+v", p.Protocols.Syslog, p.Protocols.SyslogServers)
	}
	var tried []string
	for _, r := range s.Requests() {
		if strings.Contains(r.Path, "Attributes") {
			tried = append(tried, r.Path)
		}
	}
	if len(tried) != 2 || tried[0] != attrs8 || tried[1] != attrs9OEM {
		t.Fatalf("attribute paths tried %v", tried)
	}
	if got := p.Accounts.Accounts(); len(got) != 4 || got[3].UserName != "admin" || !got[3].Enabled.Known || got[3].Enabled.Value {
		t.Fatalf("accounts %+v", got)
	}
}

func TestPostureSecretAttributesNeverKept(t *testing.T) {
	for _, fx := range []string{idrac8, idrac9} {
		d, _ := newDriver(t, fx)
		p := posture(t, d)
		dump := fmt.Sprintf("%#v %#v %#v", p, p.Accounts.Accounts(), p.Licenses.Licenses())
		for _, bad := range []string{"FIXTURE-SECRET", "EncryptionKey", "Community", "SHA256Password", "00:00:5E"} {
			if strings.Contains(dump, bad) {
				t.Fatalf("%s: posture keeps %q: %s", fx, bad, dump)
			}
		}
	}
}

func TestPostureAttributesForbiddenFallsBackToTheAccountWalk(t *testing.T) {
	d, s := newDriver(t, idrac8, redfishmock.WithTokenOnly(), redfishmock.WithStatus(attrs8, http.StatusUnauthorized))
	p := posture(t, d)
	if p.Attributes.State != bmc.ReadForbidden {
		t.Fatalf("attributes %+v", p.Attributes)
	}
	if a := p.Accounts; !a.List.OK() || a.ListSource != "Redfish AccountService" || len(a.Accounts()) != 3 {
		t.Fatalf("accounts from the walk: %+v %+v", a, a.Accounts())
	}
	if p.Protocols.IPMI.Source != "ManagerNetworkProtocol.IPMI" || p.Network.IPFilter.Known {
		t.Fatalf("DMTF facts only: %+v %+v", p.Protocols.IPMI, p.Network.IPFilter)
	}
	if st := s.SessionStats(); st.Created != 1 {
		t.Fatalf("a refused attribute document must not cost a login: %+v", st)
	}
}

func TestPostureAttributesAbsent(t *testing.T) {
	d, _ := newDriver(t, idrac9, redfishmock.WithMissing(attrs9OEM))
	if p := posture(t, d); p.Attributes.State != bmc.ReadAbsent || p.Accounts.ListSource != "Redfish AccountService" {
		t.Fatalf("attributes %+v accounts %q", p.Attributes, p.Accounts.ListSource)
	}
}

func TestPostureAttributesWithoutUsersKeepTheWalk(t *testing.T) {
	doc := map[string]any{"Attributes": map[string]any{
		"IPMILan.1.Enable": "Disabled", "Users.2.IpmiLanPrivilege": "Operator", "Users.2.SolEnable": "Enabled",
		"SSH.1.Port": 70000, "SNMP.1.SNMPProtocol": "odd", "VNCServer.1.SSLEncryptionBitLength": "",
		"Telnet.1.Enable": "Maybe", "IPv6.1.Enable": true,
	}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := newDriver(t, idrac9, redfishmock.WithOverlay(attrs8, string(b)))
	p := posture(t, d)
	if p.Accounts.ListSource != "Redfish AccountService" || p.Protocols.IPMI.Value {
		t.Fatalf("no user names in the attributes: the walk lists the accounts: %+v", p.Accounts)
	}
	if root := p.Accounts.Accounts()[0]; root.SOL.Known {
		t.Fatalf("Users.2 has no user name, so it describes nobody: %+v", root)
	}
	pr := p.Protocols
	if pr.SSHPort.Source != "ManagerNetworkProtocol.SSH.Port" || pr.SNMPLegacy.Known || pr.VNCTLS.Known ||
		pr.Telnet.Source != "ManagerNetworkProtocol.Telnet" {
		t.Fatalf("invalid attribute values must not override: %+v", pr)
	}
	if !p.Network.IPv6.Value || p.Network.IPv6.Source != "Dell attribute IPv6.1.Enable" {
		t.Fatalf("a JSON boolean is accepted: %+v", p.Network.IPv6)
	}
	if pr.NTPServers.Source != "ManagerNetworkProtocol.NTP.NTPServers" || pr.SyslogServers.Known {
		t.Fatalf("absent lists keep the DMTF value: %+v %+v", pr.NTPServers, pr.SyslogServers)
	}
}

func TestDellRoleNames(t *testing.T) {
	for priv, want := range map[int]string{511: "Administrator", 499: "Operator", 1: "ReadOnly", 0: "None", 51: "Custom (privilege 0x33)"} {
		if got := dellRole(priv); got != want {
			t.Errorf("dellRole(%d) = %q, want %q", priv, got, want)
		}
	}
}

func TestRangeCIDR(t *testing.T) {
	cases := map[[2]string]string{
		{"192.0.2.44", "255.255.255.254"}: "192.0.2.44/31",
		{"192.0.2.0", "255.255.255.0"}:    "192.0.2.0/24",
		{"192.0.2.9", "255.255.255.0"}:    "192.0.2.0/24",
		{"192.0.2.1", "255.0.255.0"}:      "192.0.2.1 mask 255.0.255.0",
		{"bad", "255.255.255.0"}:          "",
		{"192.0.2.1", ""}:                 "192.0.2.1",
	}
	for in, want := range cases {
		if got := rangeCIDR(in[0], in[1]); got != want {
			t.Errorf("rangeCIDR(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}

// TestPostureAttributeStringsAreCleaned: the Dell attribute strings lose format
// characters (zero-width space, bidirectional override), escapes and bells, so a user
// named "root"+U+200B is "root" and an NTP server reads as typed.
func TestPostureAttributeStringsAreCleaned(t *testing.T) {
	doc := map[string]any{"Attributes": map[string]any{
		"Users.2.UserName": "root\u200b", "Users.2.Enable": "Enabled", "Users.2.Privilege": 511,
		"Users.3.UserName": "op\u202es\u001b\u0007", "Users.3.Enable": "Enabled", "Users.3.Privilege": 499,
		"NTPConfigGroup.1.NTPEnable": "Enabled", "NTPConfigGroup.1.NTP1": "ntp\u202e.example\ufeff",
	}}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	d, _ := newDriver(t, idrac9, redfishmock.WithOverlay(attrs8, string(b)))
	p := posture(t, d)
	got := p.Accounts.Accounts()
	if p.Accounts.ListSource != "Dell attributes Users.*" || len(got) != 2 || got[0].UserName != "root" || got[1].UserName != "ops" {
		t.Fatalf("user names not cleaned: %q %+v", p.Accounts.ListSource, got)
	}
	if p.Protocols.NTPServers.Value != "ntp.example" {
		t.Fatalf("NTP server not cleaned: %+v", p.Protocols.NTPServers)
	}
}

// basicDriver is a Dell driver in Basic auth mode (no sessions: every request carries
// the password).
func basicDriver(t *testing.T, fixture string, opts ...redfishmock.Option) (*Driver, *redfishmock.Server) {
	t.Helper()
	s := redfishmock.New(t, redfishmock.FixtureDir(t, fixture), opts...)
	d, err := New(redfish.Config{Endpoint: s.URL(), Username: redfishmock.User, Password: redfishmock.Password,
		PinSHA256: s.PinSHA256(), Timeout: 2 * time.Second, Auth: redfish.AuthBasic})
	if err != nil {
		t.Fatal(err)
	}
	return d, s
}

// TestPostureBasicAuthStopsAfterARefusedAttributeDocument: the attribute document is the
// run's first optional read; refused in Basic auth mode, nothing else is read.
func TestPostureBasicAuthStopsAfterARefusedAttributeDocument(t *testing.T) {
	d, s := basicDriver(t, idrac8, redfishmock.WithStatus(attrs8, http.StatusForbidden))
	p := posture(t, d)
	if p.Attributes.State != bmc.ReadForbidden {
		t.Fatalf("attributes %+v", p.Attributes)
	}
	// (The iDRAC8 fixture has no LicenseService, so that section is absent, not read.)
	for name, sec := range map[string]bmc.Section{"manager": p.Firmware.Read, "protocols": p.Protocols.Read, "accounts": p.Accounts.Read} {
		if sec.State != bmc.ReadSkipped {
			t.Errorf("%s read after the refusal: %+v", name, sec)
		}
	}
	reqs := s.Requests()
	if last := reqs[len(reqs)-1]; last.Path != attrs8 || s.NonGET() != 0 {
		t.Fatalf("requests after the refusal: %+v", reqs)
	}
}

// TestPostureRenewsAnExpiredSessionBeforeTheAttributes: the attribute document is read
// with ReadOptional, which never logs in again, so a session the BMC expired must be
// renewed first or the IP filter, IPv6, DHCP and syslog checks read "can't read".
func TestPostureRenewsAnExpiredSessionBeforeTheAttributes(t *testing.T) {
	d, s := newDriver(t, idrac9, redfishmock.WithTokenOnly())
	_ = posture(t, d)
	s.ExpireSessions()
	p := posture(t, d)
	if !p.Attributes.OK() || !p.Network.IPv6.Known {
		t.Fatalf("attributes after an expired session: %+v network %+v", p.Attributes, p.Network)
	}
	if st := s.SessionStats(); st.Created != 2 {
		t.Fatalf("sessions %+v, want one re-login", st)
	}
}

// TestPostureVNCEncryptionModes: the iDRAC VNC SSL setting has three meanings. "Auto
// Negotiate" accepts plain-text clients too, so it is optional, not on.
func TestPostureVNCEncryptionModes(t *testing.T) {
	for value, want := range map[string]bmc.Fact[bmc.Encryption]{
		"Disabled":          bmc.FactOf(bmc.EncryptionOff, "Dell attribute VNCServer.1.SSLEncryptionBitLength"),
		"Auto Negotiate":    bmc.FactOf(bmc.EncryptionOptional, "Dell attribute VNCServer.1.SSLEncryptionBitLength"),
		"128-Bit or higher": bmc.FactOf(bmc.EncryptionRequired, "Dell attribute VNCServer.1.SSLEncryptionBitLength"),
		"256-Bit or higher": bmc.FactOf(bmc.EncryptionRequired, "Dell attribute VNCServer.1.SSLEncryptionBitLength"),
		"":                  {},
	} {
		b, err := json.Marshal(map[string]any{"Attributes": map[string]any{"VNCServer.1.SSLEncryptionBitLength": value}})
		if err != nil {
			t.Fatal(err)
		}
		d, _ := newDriver(t, idrac9, redfishmock.WithOverlay(attrs8, string(b)))
		if got := posture(t, d).Protocols.VNCTLS; got != want {
			t.Errorf("%q: %+v, want %+v", value, got, want)
		}
	}
}

// TestPostureUserWithoutEnableIsUnknown: a user slot without Enable has an unknown
// state; it is not taken as disabled.
func TestPostureUserWithoutEnableIsUnknown(t *testing.T) {
	b, err := json.Marshal(map[string]any{"Attributes": map[string]any{
		"Users.2.UserName": "root", "Users.2.Privilege": 511,
		"Users.3.UserName": "ops", "Users.3.Enable": "Disabled", "Users.3.Privilege": 499}})
	if err != nil {
		t.Fatal(err)
	}
	d, _ := newDriver(t, idrac9, redfishmock.WithOverlay(attrs8, string(b)))
	got := posture(t, d).Accounts.Accounts()
	if len(got) != 2 || got[0].Enabled.Known || !got[1].Enabled.Known || got[1].Enabled.Value {
		t.Fatalf("states %+v", got)
	}
}

// TestAttributeAllowlistDropsSecrets: the allowlist keeps the settings the checks read
// and drops everything else, the secret-bearing keys first of all, while decoding.
func TestAttributeAllowlistDropsSecrets(t *testing.T) {
	doc := map[string]json.RawMessage{}
	for _, k := range []string{"IPMILan.1.Enable", "Users.2.UserName", "Users.16.SolEnable", "IPBlocking.1.RangeAddr", "NTPConfigGroup.1.NTP3",
		"IPMILan.1.EncryptionKey", "SNMP.1.AgentCommunity", "Users.2.Password", "Users.2.SHA256Password", "Users.2.MD5v3Key",
		"Users.17.UserName", "Users.0.UserName", "Users.2.Email", "WebServer.1.Title"} {
		doc[k] = json.RawMessage(`"x"`)
	}
	kept := keepAttrs(doc)
	for _, k := range []string{"IPMILan.1.Enable", "Users.2.UserName", "Users.16.SolEnable", "IPBlocking.1.RangeAddr", "NTPConfigGroup.1.NTP3"} {
		if _, ok := kept[k]; !ok || !attrKeep(k) {
			t.Errorf("%s dropped", k)
		}
	}
	for _, k := range []string{"IPMILan.1.EncryptionKey", "SNMP.1.AgentCommunity", "Users.2.Password", "Users.2.SHA256Password",
		"Users.2.MD5v3Key", "Users.17.UserName", "Users.0.UserName", "Users.2.Email", "WebServer.1.Title"} {
		if _, ok := kept[k]; ok || attrKeep(k) {
			t.Errorf("%s kept", k)
		}
	}
	if len(kept) != 5 {
		t.Fatalf("kept %d keys: %v", len(kept), kept)
	}
}

// TestPostureRefusedManagerIsAForbiddenSection: a 403 on the Manager (after discovery)
// is a forbidden firmware/clock section, like the generic reader treats it; the run goes
// on to the attribute document and the other sections instead of failing.
func TestPostureRefusedManagerIsAForbiddenSection(t *testing.T) {
	d, s := newDriver(t, idrac9, redfishmock.WithTokenOnly())
	_ = posture(t, d) // discovery (which reads the Manager) is cached from here on
	s.SetStatus("/redfish/v1/Managers/iDRAC.Embedded.1", http.StatusForbidden)
	p := posture(t, d)
	if p.Firmware.Read.State != bmc.ReadForbidden || p.Clock.Read.State != bmc.ReadForbidden {
		t.Fatalf("manager %+v %+v", p.Firmware.Read, p.Clock.Read)
	}
	if !p.Attributes.OK() || !p.Network.IPv6.Known || !p.Protocols.Read.OK() {
		t.Fatalf("the rest of the run: attributes %+v network %+v protocols %+v", p.Attributes, p.Network, p.Protocols.Read)
	}
}
