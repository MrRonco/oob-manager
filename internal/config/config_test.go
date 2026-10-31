package config

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// testHostKey builds a syntactically valid (but meaningless) ed25519 authorized-key line.
func testHostKey() string {
	const algo = "ssh-ed25519"
	buf := make([]byte, 0, 4+len(algo)+4+32)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(algo)))
	buf = append(buf, algo...)
	buf = binary.BigEndian.AppendUint32(buf, 32)
	buf = append(buf, make([]byte, 32)...)
	return algo + " " + base64.StdEncoding.EncodeToString(buf)
}

func validYAML() string {
	return `listen: ":8443"
tls: { cert_file: /run/secrets/tls-cert, key_file: /run/secrets/tls-key }
public_url: https://oob.example
auth:
  mode: local
  session_idle: 30m
  session_max: 12h
  stepup_window: 5m
audit:
  gelf: { address: "192.0.2.45:12201", allowed_networks: [192.0.2.0/24], transport: tcp }
poll: { interval: 60s, min_interval: 30s }
servers:
  - id: r730xd
    name: Storage node R730XD
    tags: [critical, storage]
    bmc: { address: 192.0.2.70, kind: idrac8 }
    tls_pin_sha256: "` + testPin + `"
    ssh_host_key: "` + testHostKey() + `"
    credentials: { readonly: r730xd-ro, operator: r730xd-op, vnc: r730xd-vnc }
    fan: { mode: host-lease, safe_min_pct: 30, max_lease: 2h }
    console: { serial: bmcssh, graphical: vnc }
  - id: r240
    name: Edge node R240
    tags: [critical, edge]
    bmc: { address: 192.0.2.72, kind: idrac9 }
    tls_pin_sha256: "` + testPin + `"
    ssh_host_key: "` + testHostKey() + `"
    credentials: { readonly: r240-ro, operator: r240-op }
    fan: { mode: redfishfloor, safe_min_pct: 41, max_lease: 2h }
    console: { serial: bmcssh, graphical: kvm-launch }
`
}

func mustParse(t *testing.T, src string) Config {
	t.Helper()
	cfg, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return cfg
}

func TestParseValid(t *testing.T) {
	cfg := mustParse(t, validYAML())
	if cfg.Listen != ":8443" {
		t.Errorf("listen = %q", cfg.Listen)
	}
	if cfg.Auth.SessionIdle != 30*time.Minute || cfg.Auth.SessionMax != 12*time.Hour {
		t.Errorf("session durations = %v/%v", cfg.Auth.SessionIdle, cfg.Auth.SessionMax)
	}
	if len(cfg.Servers) != 2 {
		t.Fatalf("servers = %d", len(cfg.Servers))
	}
	r240, ok := cfg.Server("r240")
	if !ok {
		t.Fatal("r240 not found")
	}
	if r240.Fan.Mode != FanRedfishFloor {
		t.Errorf("r240 fan mode = %q, want normalised %q", r240.Fan.Mode, FanRedfishFloor)
	}
	if !r240.Fan.BoostOnly() {
		t.Error("redfish-floor must be boost-only")
	}
	r730, _ := cfg.Server("r730xd")
	if r730.Fan.BoostOnly() {
		t.Error("host-lease is not boost-only")
	}
	if _, ok := cfg.Server("nope"); ok {
		t.Error("unknown server found")
	}
	if len(cfg.SHA256) != 64 {
		t.Errorf("config hash = %q", cfg.SHA256)
	}
}

func TestDefaults(t *testing.T) {
	src := strings.Replace(validYAML(), `listen: ":8443"`+"\n", "", 1)
	src = strings.Replace(src, "  session_idle: 30m\n  session_max: 12h\n  stepup_window: 5m\n", "", 1)
	src = strings.Replace(src, "poll: { interval: 60s, min_interval: 30s }\n", "", 1)
	cfg := mustParse(t, src)
	if cfg.Listen != DefaultListen {
		t.Errorf("listen default = %q", cfg.Listen)
	}
	if cfg.Poll.Interval != 60*time.Second || cfg.Poll.MinInterval != 30*time.Second {
		t.Errorf("poll defaults = %+v", cfg.Poll)
	}
	if cfg.Auth.StepUpWindow != 5*time.Minute {
		t.Errorf("stepup default = %v", cfg.Auth.StepUpWindow)
	}
	if cfg.Storage.DBPath != "/data/oob-manager.db" || !cfg.Storage.DBPathDefaulted || cfg.Storage.LeaseDir != "/leases" {
		t.Errorf("storage defaults = %+v", cfg.Storage)
	}
	// The pre-rename default stays readable (cmd/oob-manager falls back to it).
	if LegacyDBPath != "/data/oob-console.db" {
		t.Errorf("legacy db path = %q", LegacyDBPath)
	}
	explicit := mustParse(t, src+"storage: { db_path: /data/mine.db }\n")
	if explicit.Storage.DBPath != "/data/mine.db" || explicit.Storage.DBPathDefaulted {
		t.Errorf("explicit db_path = %+v", explicit.Storage)
	}
	if cfg.Secrets.CredentialsFile != "/run/secrets/bmc-credentials.age" ||
		cfg.Secrets.IdentityFile != "/run/secrets/age-identity" ||
		cfg.Secrets.AppKeysFile != "/run/secrets/app-keys.age" {
		t.Errorf("secrets defaults = %+v", cfg.Secrets)
	}
}

func TestServerReturnsCopy(t *testing.T) {
	cfg := mustParse(t, validYAML())
	s, _ := cfg.Server("r730xd")
	s.Tags[0] = "mutated"
	again, _ := cfg.Server("r730xd")
	if again.Tags[0] != "critical" {
		t.Error("Server() leaked internal slice")
	}
}

func TestParseRejects(t *testing.T) {
	tests := []struct {
		name string
		from string
		to   string
		want string
	}{
		{"unknown top-level key", "public_url:", "bogus: 1\npublic_url:", "bogus"},
		{"unknown nested key", "kind: idrac8 }", "kind: idrac8, host: bmc1 }", "host"},
		{"bad fan mode", "mode: host-lease,", "mode: turbo,", "fan.mode"},
		{"fan mode not allowed for kind", "mode: redfishfloor,", "mode: host-lease,", "not allowed"},
		{"missing pin", `tls_pin_sha256: "` + testPin + `"` + "\n    ssh_host_key", "ssh_host_key", "tls_pin_sha256"},
		{"short pin", testPin, "abcd", "tls_pin_sha256"},
		{"floor below 20", "mode: host-lease, safe_min_pct: 30", "mode: host-lease, safe_min_pct: 15", "safe_min_pct"},
		{"host-lease floor below 30", "mode: host-lease, safe_min_pct: 30", "mode: host-lease, safe_min_pct: 25", "safe_min_pct"},
		{"redfish floor below dell range", "safe_min_pct: 41", "safe_min_pct: 34", "35"},
		{"floor above 100", "safe_min_pct: 41", "safe_min_pct: 101", "safe_min_pct"},
		{"lease too long", "safe_min_pct: 30, max_lease: 2h", "safe_min_pct: 30, max_lease: 3h", "max_lease"},
		{"lease missing", "safe_min_pct: 30, max_lease: 2h", "safe_min_pct: 30", "max_lease"},
		{"duplicate id", "id: r240", "id: r730xd", "duplicate"},
		{"duplicate name", "name: Edge node R240", "name: Storage node R730XD", "duplicate"},
		{"bad id", "id: r240", "id: R2/40", "id"},
		{"hostname bmc address", "address: 192.0.2.72", "address: idrac.example", "bmc.address"},
		{"bad kind", "kind: idrac9", "kind: ilo5", "bmc.kind"},
		{"http public url", "https://oob", "http://oob", "public_url"},
		{"bad listen", `listen: ":8443"`, `listen: "8443"`, "listen"},
		{"bad auth mode", "mode: local", "mode: none", "auth.mode"},
		{"cfaccess without aud", "mode: local", "mode: cfaccess+local", "cfaccess"},
		{"idle above max", "session_idle: 30m", "session_idle: 13h", "session_idle"},
		{"poll min below 30s", "min_interval: 30s", "min_interval: 5s", "min_interval"},
		{"poll interval below min", "interval: 60s,", "interval: 31s, x: 1,", "x"},
		{"poll interval lt min", "interval: 60s,", "interval: 20s,", "poll.interval"},
		{"udp gelf", "transport: tcp", "transport: udp", "transport"},
		{"bad gelf address", `address: "192.0.2.45:12201"`, `address: "graylog"`, "gelf.address"},
		{"vnc without credential", ", vnc: r730xd-vnc }", " }", "credentials.vnc"},
		{"kvm-launch on idrac8", "graphical: vnc }", "graphical: kvm-launch }", "kvm-launch"},
		{"bad serial", "serial: bmcssh, graphical: vnc", "serial: telnet, graphical: vnc", "console.serial"},
		{"bad graphical", "graphical: vnc }", "graphical: java }", "console.graphical"},
		{"missing readonly cred", "readonly: r240-ro, ", "", "credentials.readonly"},
		{"bad cred ref", "readonly: r240-ro", "readonly: ../etc", "credentials.readonly"},
		{"bad tag", "[critical, edge]", "[Critical!]", "tags"},
		{"bad host key", "ssh_host_key: \"ssh-ed25519", "ssh_host_key: \"ssh-dss", "ssh_host_key"},
		{"missing tls cert", "cert_file: /run/secrets/tls-cert, ", "", "tls.cert_file"},
		{"relative key file", "key_file: /run/secrets/tls-key", "key_file: tls-key", "tls.key_file"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := validYAML()
			if !strings.Contains(src, tc.from) {
				t.Fatalf("fixture does not contain %q", tc.from)
			}
			_, err := Parse([]byte(strings.Replace(src, tc.from, tc.to, 1)))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

func TestParseStructural(t *testing.T) {
	tests := map[string]string{
		"empty":          "",
		"not yaml":       "listen: [",
		"two documents":  validYAML() + "---\nlisten: x\n",
		"second doc bad": validYAML() + "---\n[",
	}
	for name, src := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(src)); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestValidModesPerKind(t *testing.T) {
	ok := map[string]string{
		"none on generic redfish": strings.Replace(strings.Replace(validYAML(),
			"kind: idrac9", "kind: redfish", 1),
			"fan: { mode: redfishfloor, safe_min_pct: 41, max_lease: 2h }\n    console: { serial: bmcssh, graphical: kvm-launch }",
			"fan: { mode: none }\n    console: { serial: none, graphical: link }", 1),
		"ipmi-oem on idrac8": strings.Replace(validYAML(),
			"mode: host-lease, safe_min_pct: 30, max_lease: 2h", "mode: ipmi-oem, safe_min_pct: 30, max_lease: 60m", 1),
		"cfaccess with settings": strings.Replace(validYAML(), "mode: local\n",
			"mode: cfaccess+local\n  cfaccess: { team_domain: example.cloudflareaccess.com, aud: abc123 }\n", 1),
		"gelf disabled": strings.Replace(validYAML(), `gelf: { address: "192.0.2.45:12201", allowed_networks: [192.0.2.0/24], transport: tcp }`, "{}", 1),
	}
	for name, src := range ok {
		t.Run(name, func(t *testing.T) {
			mustParse(t, src)
		})
	}
}

func TestIpmiKind(t *testing.T) {
	src := strings.Replace(validYAML(), "kind: idrac9 }\n    tls_pin_sha256: \""+testPin+"\"\n", "kind: ipmi }\n", 1)
	src = strings.Replace(src, "fan: { mode: redfishfloor, safe_min_pct: 41, max_lease: 2h }\n    console: { serial: bmcssh, graphical: kvm-launch }",
		"fan: { mode: none }\n    console: { serial: sol, graphical: none }", 1)
	cfg := mustParse(t, src)
	s, _ := cfg.Server("r240")
	if s.BMC.Kind != KindIPMI {
		t.Errorf("kind = %q", s.BMC.Kind)
	}
	bad := strings.Replace(src, "serial: sol", "serial: bmcssh", 1)
	if _, err := Parse([]byte(bad)); err == nil || !strings.Contains(err.Error(), "bmcssh") {
		t.Errorf("bmcssh on ipmi kind: err = %v", err)
	}
}

func TestIpmiOemTooLong(t *testing.T) {
	src := strings.Replace(validYAML(),
		"mode: host-lease, safe_min_pct: 30, max_lease: 2h", "mode: ipmi-oem, safe_min_pct: 30, max_lease: 2h", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "max_lease") {
		t.Errorf("err = %v", err)
	}
}

func TestOperatorRequiredForActions(t *testing.T) {
	src := strings.Replace(validYAML(), ", operator: r240-op }", " }", 1)
	if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "credentials.operator") {
		t.Errorf("err = %v", err)
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(validYAML()), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Servers) != 2 {
		t.Errorf("servers = %d", len(cfg.Servers))
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("missing file accepted")
	}
	big := filepath.Join(dir, "big.yaml")
	if err := os.WriteFile(big, make([]byte, MaxConfigBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(big); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("oversized: err = %v", err)
	}
}

func TestErrorListsEveryProblem(t *testing.T) {
	src := strings.Replace(validYAML(), "kind: idrac9", "kind: bogus", 1)
	src = strings.Replace(src, "http", "ftp", 1)
	_, err := Parse([]byte(src))
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"bmc.kind", "public_url"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}
