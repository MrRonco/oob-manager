package redfish

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

// Compile-time check: the generic driver reads posture.
var _ bmc.PostureReader = (*Driver)(nil)

const (
	accountService9 = "/redfish/v1/AccountService"
	accounts9       = "/redfish/v1/AccountService/Accounts"
	netProto        = "/redfish/v1/Managers/iDRAC.Embedded.1/NetworkProtocol"
	accountService8 = "/redfish/v1/Managers/iDRAC.Embedded.1/AccountService"
	activeImage9    = "/redfish/v1/UpdateService/FirmwareInventory/Installed-25227-7.00.00.182__iDRAC.Embedded.1-1"
)

func readPosture(t *testing.T, s *redfishmock.Server, opts ...Option) bmc.RedfishPosture {
	t.Helper()
	p, err := driverFor(t, s, append([]Option{fastReauth()}, opts...)...).Posture(testCtx(t))
	if err != nil {
		t.Fatalf("Posture: %v", err)
	}
	return p
}

// onlyReads asserts that every request was a GET, apart from the one session login.
func onlyReads(t *testing.T, s *redfishmock.Server) {
	t.Helper()
	assertNoWrites(t, s)
	for _, r := range s.Requests() {
		login := r.Method == http.MethodPost && r.Path == s.SessionsURI()
		if r.Method != http.MethodGet && !login {
			t.Fatalf("posture sent %s %s", r.Method, r.Path)
		}
	}
	if st := s.SessionStats(); st.Created != 1 {
		t.Fatalf("posture must reuse one session: %+v", st)
	}
}

func TestPostureIDRAC9Protocols(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithTokenOnly())
	p := readPosture(t, s).Protocols
	if !p.Read.OK() {
		t.Fatalf("NetworkProtocol read %+v", p.Read)
	}
	want := map[string]bmc.Fact[bool]{
		"IPMI": p.IPMI, "SSH": p.SSH, "HTTP": p.HTTP, "HTTPS": p.HTTPS, "VirtualMedia": p.VirtualMedia,
		"KVMIP": p.KVMIP, "NTP": p.NTP,
	}
	for name, f := range want {
		if !f.Known || !f.Value || f.Source != "ManagerNetworkProtocol."+name {
			t.Errorf("%s = %+v, want on from ManagerNetworkProtocol", name, f)
		}
	}
	for name, f := range map[string]bmc.Fact[bool]{"Telnet": p.Telnet, "SNMP": p.SNMP, "VNC": p.VNC} {
		if !f.Known || f.Value {
			t.Errorf("%s = %+v, want off", name, f)
		}
	}
	if p.SSDP.Known || p.SNMPLegacy.Known || p.HTTPSRedirect.Known {
		t.Errorf("not reported by DMTF NetworkProtocol on this BMC: %+v %+v %+v", p.SSDP, p.SNMPLegacy, p.HTTPSRedirect)
	}
	if p.SSHPort.Value != 22 || p.HTTPPort.Value != 80 || p.HTTPSPort.Value != 443 || p.VNCPort.Value != 5901 {
		t.Errorf("ports %+v %+v %+v %+v", p.SSHPort, p.HTTPPort, p.HTTPSPort, p.VNCPort)
	}
	if p.NTPServers.Value != "192.0.2.10" {
		t.Errorf("NTP servers %+v (empty and duplicate entries are dropped)", p.NTPServers)
	}
	onlyReads(t, s)
}

func TestPostureIDRAC8ProtocolsAndNoLicenseService(t *testing.T) {
	s := mockFor(t, idrac8, redfishmock.WithTokenOnly())
	p := readPosture(t, s)
	if !p.Protocols.IPMI.Value || p.Protocols.NTPServers.Value != "pool.ntp.org" || p.Protocols.VNC.Known {
		t.Fatalf("iDRAC8 protocols %+v", p.Protocols)
	}
	if p.Licenses.Read.State != bmc.ReadAbsent {
		t.Fatalf("iDRAC8 has no LicenseService: %+v", p.Licenses.Read)
	}
	if p.Network.DHCP.Value != true || p.Network.DHCP.Source != "ManagerNetworkProtocol.DHCP" {
		t.Fatalf("DHCP %+v", p.Network.DHCP)
	}
	onlyReads(t, s)
}

func TestPostureAccountsIDRAC9(t *testing.T) {
	s := mockFor(t, idrac9)
	a := readPosture(t, s).Accounts
	if !a.Read.OK() || !a.List.OK() || a.ListSource != "Redfish AccountService" {
		t.Fatalf("accounts read %+v list %+v source %q", a.Read, a.List, a.ListSource)
	}
	if !a.MinPasswordLength.Known || a.MinPasswordLength.Value != 0 || !a.LockoutThreshold.Known || a.LockoutThreshold.Value != 0 {
		t.Fatalf("policy %+v %+v", a.MinPasswordLength, a.LockoutThreshold)
	}
	got := a.Accounts()
	if len(got) != 4 {
		t.Fatalf("want the 4 named accounts (the empty slot is skipped): %+v", got)
	}
	root := got[0]
	if root.UserName != "root" || root.Role != "Administrator" || !root.Enabled.Known || !root.Enabled.Value || !root.IPMI.Known || !root.IPMI.Value {
		t.Fatalf("root %+v", root)
	}
	if ro := got[1]; ro.UserName != "oob_ro" || ro.Role != "ReadOnly" || ro.IPMI.Value {
		t.Fatalf("read-only account %+v", ro)
	}
	if off := got[3]; off.UserName != "admin" || !off.Enabled.Known || off.Enabled.Value {
		t.Fatalf("disabled account %+v", off)
	}
	if root.SOL.Known {
		t.Fatalf("generic Redfish does not report SOL access: %+v", root.SOL)
	}
}

func TestPostureAccountsIDRAC8UnderManager(t *testing.T) {
	s := mockFor(t, idrac8)
	a := readPosture(t, s).Accounts
	got := a.Accounts()
	if !a.List.OK() || len(got) != 3 || got[0].UserName != "root" || got[0].IPMI.Known {
		t.Fatalf("iDRAC8 accounts %+v (no AccountTypes in Redfish 1.0)", got)
	}
}

func TestPostureForbiddenSectionsDoNotCostSessions(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithTokenOnly(), redfishmock.WithStatus(accountService9, http.StatusForbidden),
		redfishmock.WithStatus(netProto, http.StatusUnauthorized))
	p := readPosture(t, s)
	if p.Accounts.Read.State != bmc.ReadForbidden || p.Accounts.List.State != bmc.ReadNotTried {
		t.Fatalf("AccountService 403: %+v / %+v", p.Accounts.Read, p.Accounts.List)
	}
	if p.Protocols.Read.State != bmc.ReadForbidden || p.Protocols.IPMI.Known {
		t.Fatalf("NetworkProtocol 401: %+v", p.Protocols)
	}
	if st := s.SessionStats(); st.Created != 1 || s.LiveSessions() != 1 {
		t.Fatalf("a refused resource must not drop the session or log in again: %+v live %d", st, s.LiveSessions())
	}
	if !p.Clock.Read.OK() || !p.Firmware.Read.OK() {
		t.Fatalf("other sections are still read: %+v %+v", p.Clock.Read, p.Firmware.Read)
	}
}

func TestPostureAccountListForbidden(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithStatus("/redfish/v1/AccountService/Accounts/2", http.StatusForbidden))
	a := readPosture(t, s).Accounts
	if !a.Read.OK() || a.List.State != bmc.ReadForbidden || len(a.Accounts()) != 0 {
		t.Fatalf("a refused member makes the list unreadable: %+v %+v", a.List, a.Accounts())
	}
}

func TestPostureAccountWalkIsCapped(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"Members":[`)
	for i := range 40 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"@odata.id":"/redfish/v1/AccountService/Accounts/x` + strconv.Itoa(i) + `"}`)
	}
	b.WriteString(`]}`)
	s := mockFor(t, idrac9, redfishmock.WithOverlay(accounts9, b.String()))
	if a := readPosture(t, s).Accounts; !a.Partial {
		t.Fatal("a list cut at the cap is partial")
	}
	n := 0
	for _, r := range s.Requests() {
		if strings.HasPrefix(r.Path, accounts9+"/") {
			n++
		}
	}
	if n != maxPostureAccounts {
		t.Fatalf("read %d account members, want the cap %d", n, maxPostureAccounts)
	}
}

func TestPostureSkipAccountList(t *testing.T) {
	s := mockFor(t, idrac9)
	p, err := driverFor(t, s).PostureWith(testCtx(t), PostureOptions{SkipAccountList: true})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Accounts.Read.OK() || p.Accounts.List.State != bmc.ReadNotTried {
		t.Fatalf("policy read, list skipped: %+v %+v", p.Accounts.Read, p.Accounts.List)
	}
	for _, r := range s.Requests() {
		if strings.HasPrefix(r.Path, accounts9) {
			t.Fatalf("account list read although skipped: %s", r.Path)
		}
	}
}

func TestPostureClockAndFirmware(t *testing.T) {
	now := time.Date(2025, 3, 15, 22, 49, 30, 0, time.UTC)
	s := mockFor(t, idrac9, redfishmock.WithOverlay(activeImage9,
		`{"Id":"Installed-25227-7.00.00.182__iDRAC.Embedded.1-1","Version":"7.00.00.182","ReleaseDate":"2023-11-01T00:00:00Z"}`))
	p := readPosture(t, s, WithClock(func() time.Time { return now }))
	c := p.Clock
	if !c.Read.OK() || !c.BMCTime.Equal(time.Date(2025, 3, 15, 22, 49, 24, 0, time.UTC)) || !c.Before.Equal(now) || !c.After.Equal(now) {
		t.Fatalf("clock %+v", c)
	}
	f := p.Firmware
	if !f.Read.OK() || f.BMCVersion != "7.00.00.182" || f.BIOSVersion.Value != "2.20.0" {
		t.Fatalf("firmware %+v", f)
	}
	if !f.BMCReleased.Known || !f.BMCReleased.Value.Equal(time.Date(2023, 11, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("release date %+v", f.BMCReleased)
	}
}

func TestPostureReleaseDateDellPlaceholderIsUnknown(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithOverlay(activeImage9, `{"ReleaseDate":"00:00:00Z"}`))
	if f := readPosture(t, s).Firmware; f.BMCReleased.Known {
		t.Fatalf("a placeholder date is not a release date: %+v", f.BMCReleased)
	}
}

func TestPostureLicenses(t *testing.T) {
	s := mockFor(t, idrac9)
	l := readPosture(t, s).Licenses
	got := l.Licenses()
	if !l.Read.OK() || len(got) != 2 {
		t.Fatalf("licences %+v %+v", l.Read, got)
	}
	trial := got[0]
	if trial.Type != "Trial" || trial.Tier != bmc.LicenseEnterprise ||
		!trial.Expires.Equal(time.Date(2000, 2, 1, 0, 0, 0, 0, time.UTC)) || !strings.Contains(trial.Description, "Evaluation") {
		t.Fatalf("trial %+v", trial)
	}
	if prod := got[1]; prod.Type != "Production" || !prod.Expires.IsZero() || prod.Description != "iDRAC9 Enterprise License" {
		t.Fatalf("production %+v", prod)
	}
	for _, e := range got {
		if strings.Contains(e.Description, "REDACTED") {
			t.Fatalf("licence names and IDs are not read: %+v", e)
		}
	}
}

func TestPostureFailsWhenTheBMCIsDown(t *testing.T) {
	s := mockFor(t, idrac9)
	s.SetDown(true)
	if _, err := driverFor(t, s).Posture(testCtx(t)); err == nil {
		t.Fatal("want an error when nothing can be read")
	}
}

func TestReadOptionalKeepsTheSession(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithTokenOnly(), redfishmock.WithStatus(netProto, http.StatusUnauthorized))
	d := driverFor(t, s, fastReauth())
	var v map[string]any
	if err := d.GetJSON(testCtx(t), "/redfish/v1/Systems", &v); err != nil {
		t.Fatal(err)
	}
	if err := d.ReadOptional(testCtx(t), netProto, &v); err == nil || bmc.Classify(err) != bmc.ClassAuth {
		t.Fatalf("ReadOptional 401 = %v, want an auth error", err)
	}
	if st := s.SessionStats(); st.Created != 1 || s.LiveSessions() != 1 {
		t.Fatalf("session dropped or re-created: %+v", st)
	}
	if err := d.ReadOptional(testCtx(t), "/redfish/v1/Systems", &v); err != nil {
		t.Fatalf("the kept session still works: %v", err)
	}
	if err := d.ReadOptional(testCtx(t), "/redfish/v1/../x", &v); err == nil {
		t.Fatal("ReadOptional must refuse bad URIs")
	}
}

func TestReadOptionalBasicAuth(t *testing.T) {
	s := mockFor(t, idrac9)
	cfg := configFor(s)
	cfg.Auth = AuthBasic
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := d.ReadOptional(testCtx(t), netProto, &v); err != nil {
		t.Fatal(err)
	}
	if s.SessionStats().Created != 0 || s.NonGET() != 0 {
		t.Fatalf("basic mode must not log in: %+v", s.SessionStats())
	}
}

// TestPostureHostileStringsAreCleaned: zero-width and bidirectional format characters,
// escape sequences and bells in BMC strings never reach a fact (an account named
// "root"+U+200B must still read "root").
func TestPostureHostileStringsAreCleaned(t *testing.T) {
	account := `{"Id":"2","UserName":"svc\u200b\u202eops\u001b\u0007","RoleId":"Operator\u200b","Enabled":true,"AccountTypes":["Redfish"]}`
	np := `{"NTP":{"ProtocolEnabled":true,"NTPServers":["ntp\u200b.example\u202e"," \ufeff"]}}`
	license := `{"Description":"Ent\u200berprise\u0007","LicenseType":"Production\u202e"}`
	s := mockFor(t, idrac9, redfishmock.WithOverlay(accounts9+"/2", account), redfishmock.WithOverlay(netProto, np),
		redfishmock.WithOverlay("/redfish/v1/LicenseService/Licenses/ProductionLicense", license))
	p := readPosture(t, s)
	got := p.Accounts.Accounts()
	if len(got) != 4 || got[0].UserName != "svcops" || got[0].Role != "Operator" {
		t.Fatalf("account strings not cleaned: %+v", got)
	}
	if p.Protocols.NTPServers.Value != "ntp.example" {
		t.Fatalf("NTP servers %+v", p.Protocols.NTPServers)
	}
	var prod bmc.LicenseEntry
	for _, e := range p.Licenses.Licenses() {
		if e.Type == "Production" {
			prod = e
		}
	}
	if prod.Description != "Enterprise" {
		t.Fatalf("licence strings not cleaned: %+v", p.Licenses.Licenses())
	}
}

// TestPostureBasicAuthStopsAtTheFirstRefusal: in Basic auth mode every request carries
// the password, so a BMC may count each 401/403 as a failed login. The first refusal
// ends the run's optional reads: the sections after it are skipped, with the reason,
// and nothing else is requested. (Session mode goes on: a refusal costs no login there,
// see TestPostureForbiddenSectionsDoNotCostSessions.)
func TestPostureBasicAuthStopsAtTheFirstRefusal(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithStatus(netProto, http.StatusForbidden))
	cfg := configFor(s)
	cfg.Auth = AuthBasic
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := d.Posture(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Firmware.Read.OK() || !p.Clock.Read.OK() || p.Protocols.Read.State != bmc.ReadForbidden {
		t.Fatalf("read before the refusal, then refused: %+v %+v %+v", p.Firmware.Read, p.Clock.Read, p.Protocols.Read)
	}
	for name, sec := range map[string]bmc.Section{"accounts": p.Accounts.Read, "licences": p.Licenses.Read} {
		if sec.State != bmc.ReadSkipped || !strings.Contains(sec.Why, "Basic") {
			t.Errorf("%s after the refusal: %+v, want skipped with the reason", name, sec)
		}
	}
	if p.Firmware.BIOSVersion.Known || p.Firmware.BMCReleased.Known {
		t.Fatalf("optional facts read after the refusal: %+v", p.Firmware)
	}
	reqs := s.Requests()
	if last := reqs[len(reqs)-1]; last.Path != netProto {
		t.Fatalf("requests went on after the refusal: %+v", reqs)
	}
}

// TestPostureAbsurdLockoutDurationIsUnknown: a lockout duration that would overflow a
// time.Duration (or any value over a year) is not a fact.
func TestPostureAbsurdLockoutDurationIsUnknown(t *testing.T) {
	for _, c := range []struct {
		seconds string
		known   bool
		want    time.Duration
	}{{"300", true, 5 * time.Minute}, {"31536000", true, 365 * 24 * time.Hour}, {"31536001", false, 0},
		{"9223372036854775807", false, 0}, {"-1", false, 0}} {
		s := mockFor(t, idrac9, redfishmock.WithOverlay(accountService9,
			`{"Accounts":{"@odata.id":"`+accounts9+`"},"MinPasswordLength":8,"AccountLockoutThreshold":3,"AccountLockoutDuration":`+c.seconds+`}`))
		a := readPosture(t, s).Accounts
		if a.LockoutDuration.Known != c.known || a.LockoutDuration.Value != c.want {
			t.Errorf("AccountLockoutDuration %s: %+v", c.seconds, a.LockoutDuration)
		}
	}
}

// TestPostureNTPListAbsentIsUnknown: NTPServers is optional in DSP0268; a BMC that
// reports NTP on without the list has an unknown server list, not an empty one (which
// would read as "no server is set").
func TestPostureNTPListAbsentIsUnknown(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithOverlay(netProto, `{"NTP":{"ProtocolEnabled":true}}`))
	p := readPosture(t, s).Protocols
	if !p.NTP.Value || p.NTPServers.Known {
		t.Fatalf("absent list: %+v %+v", p.NTP, p.NTPServers)
	}
	s = mockFor(t, idrac9, redfishmock.WithOverlay(netProto, `{"NTP":{"ProtocolEnabled":true,"NTPServers":[]}}`))
	if p := readPosture(t, s).Protocols; !p.NTPServers.Known || p.NTPServers.Value != "" {
		t.Fatalf("an empty list is known and empty: %+v", p.NTPServers)
	}
}

// TestPostureAccountStateAndPartialList: an account without Enabled has an unknown
// state (not "disabled", which would hide a factory account); a collection with a next
// link, or longer than the cap, is read partially and says so.
func TestPostureAccountStateAndPartialList(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithOverlay(accounts9+"/2", `{"Id":"2","UserName":"ghost","RoleId":"Operator"}`))
	a := readPosture(t, s).Accounts
	got := a.Accounts()
	if a.Partial || len(got) != 4 || got[0].UserName != "ghost" || got[0].Enabled.Known {
		t.Fatalf("no Enabled: %+v partial %v", got, a.Partial)
	}
	if off := got[3]; off.UserName != "admin" || !off.Enabled.Known || off.Enabled.Value {
		t.Fatalf("a disabled account is known to be off: %+v", off)
	}
	s = mockFor(t, idrac9, redfishmock.WithOverlay(accounts9,
		`{"Members":[{"@odata.id":"`+accounts9+`/2"}],"Members@odata.nextLink":"`+accounts9+`?$skip=1"}`))
	if a := readPosture(t, s).Accounts; !a.Partial || !a.List.OK() || len(a.Accounts()) != 1 {
		t.Fatalf("a next link makes the list partial: %+v %+v", a.List, a.Accounts())
	}
}

// TestSNMPLegacyEitherVersion pins that v1 or v2c alone is legacy SNMP, and that
// nothing reported is unknown.
func TestSNMPLegacyEitherVersion(t *testing.T) {
	on, off := true, false
	cases := []struct {
		v1, v2c *bool
		known   bool
		want    bool
	}{{&on, &off, true, true}, {&off, &on, true, true}, {&on, &on, true, true}, {&off, &off, true, false}, {nil, &on, true, true},
		{&off, nil, true, false}, {nil, nil, false, false}}
	for _, c := range cases {
		if f := snmpLegacy(c.v1, c.v2c); f.Known != c.known || f.Value != c.want {
			t.Errorf("snmpLegacy(%v, %v) = %+v", c.v1, c.v2c, f)
		}
	}
}
