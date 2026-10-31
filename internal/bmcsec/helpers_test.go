package bmcsec

import (
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

var now = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func ok() bmc.Section { return bmc.SectionOf(nil) }

func on(v bool, src string) bmc.Fact[bool] { return bmc.FactOf(v, src) }

func goodCert() bmc.CertFacts {
	return bmc.CertFacts{SHA256: strings.Repeat("ab", 32), Subject: "CN=bmc.example", Issuer: "CN=Lab CA",
		SubjectCN: "bmc.example", NotBefore: now.Add(-24 * time.Hour), NotAfter: now.Add(365 * 24 * time.Hour),
		KeyType: "ECDSA", KeyBits: 256, Signature: "ECDSA-SHA256"}
}

func goodTLS(port int) bmc.TLSProbe {
	return bmc.TLSProbe{Read: ok(), Port: port, PinMatch: true, Cert: goodCert(), Negotiated: "TLS 1.3",
		Cipher: "TLS_AES_128_GCM_SHA256", TLS10: on(false, "p"), TLS11: on(false, "p"), TLS12: on(true, "p"),
		TLS13: on(true, "p"), WeakCipher: on(false, "p"), RSAKeyExchange: on(false, "p"), ForwardSecrecy: on(true, "p")}
}

// good is a posture where every check passes (or is informational).
func good() bmc.Posture {
	return bmc.Posture{
		Started: now.Add(-time.Minute), Duration: 3 * time.Second,
		Web: goodTLS(443), VNC: goodTLS(5901),
		SSH: bmc.SSHProbe{Read: ok(), Port: 22, Version: "SSH-2.0-OpenSSH_9.6",
			KeyExchanges: "curve25519-sha256,ecdh-sha2-nistp256,kex-strict-s-v00@openssh.com", HostKeys: "ssh-ed25519,rsa-sha2-512",
			Ciphers: "aes128-gcm@openssh.com,aes256-ctr", MACs: "hmac-sha2-256-etm@openssh.com"},
		HTTP:  bmc.HTTPProbe{Read: ok(), Port: 80, Status: 301, Redirect: true, ToHTTPS: true},
		WSMan: bmc.WSManProbe{Read: ok(), Status: 404, ControlStatus: 404},
		Redfish: bmc.RedfishPosture{
			Protocols: bmc.ProtocolFacts{Read: ok(), IPMI: on(false, "np"), Telnet: on(false, "np"), SSH: on(true, "np"),
				HTTP: on(true, "np"), HTTPS: on(true, "np"), SNMP: on(false, "np"), VirtualMedia: on(false, "np"),
				SSDP: on(false, "np"), VNC: on(false, "np"), NTP: on(true, "np"), NTPServers: bmc.FactOf("ntp.example", "np"),
				Syslog: on(true, "attr"), SyslogServers: bmc.FactOf(1, "attr"), SSHPort: bmc.FactOf(22, "np")},
			Accounts: bmc.AccountFacts{Read: ok(), List: ok(), ListSource: "Redfish AccountService",
				MinPasswordLength: bmc.FactOf(12, "as"), LockoutThreshold: bmc.FactOf(5, "as"),
				LockoutDuration: bmc.FactOf(5*time.Minute, "as")}.WithAccounts([]bmc.Account{
				{UserName: "alice", Role: "Administrator", Enabled: on(true, "e"), IPMI: on(false, "a"), SOL: on(false, "a")},
				{UserName: "svc_ro", Role: "ReadOnly", Enabled: on(true, "e"), IPMI: on(false, "a"), SOL: on(false, "a")},
			}),
			Clock:    bmc.ClockFacts{Read: ok(), BMCTime: now, Before: now, After: now},
			Firmware: bmc.FirmwareFacts{Read: ok(), BMCVersion: "7.10.30.00", BIOSVersion: bmc.FactOf("2.20.0", "cs")},
			Licenses: bmc.LicenseFacts{Read: ok()}.WithLicenses([]bmc.LicenseEntry{
				{Description: "Enterprise License", Type: "Production", Tier: bmc.LicenseEnterprise}}),
			Network: bmc.NetworkFacts{IPFilter: on(true, "attr"), IPFilterRange: bmc.FactOf("192.0.2.0/28", "attr"),
				LoginBlocking: on(true, "attr"), DHCP: on(false, "attr"), IPv6: on(false, "attr")},
			Attributes: ok(),
		},
	}
}

const goodAddr = "192.0.2.10:443"

func goodInputs() Inputs {
	return Inputs{Kind: "idrac9", MinFirmware: "7.00.00.182", VNC: true, VNCTLS: true, Address: goodAddr}
}

func evalOf(p bmc.Posture, in Inputs) Report { return Evaluate("srv", p, in, now) }

func find(t *testing.T, r Report, id string) Finding {
	t.Helper()
	f, found := r.Finding(id)
	if !found {
		t.Fatalf("check %s not in the report", id)
	}
	return f
}

// expect evaluates p and checks one finding's result and that its evidence mentions want.
func expect(t *testing.T, p bmc.Posture, in Inputs, id string, res Result, want string) Finding {
	t.Helper()
	f := find(t, evalOf(p, in), id)
	if f.Result != res {
		t.Fatalf("%s = %s %v, want %s", id, f.Result, f.Evidence, res)
	}
	if want != "" && !strings.Contains(strings.Join(f.Evidence, " "), want) {
		t.Fatalf("%s evidence %q does not mention %q", id, f.Evidence, want)
	}
	return f
}
