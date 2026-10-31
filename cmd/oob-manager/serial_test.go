package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc/bmcssh/sshtest"
	"oob-manager/internal/config"
	"oob-manager/internal/secrets"
)

func TestBuildSerial(t *testing.T) {
	fake := sshtest.New(t, sshtest.Options{})
	mk := func(id string, kind config.BMCKind, serial config.SerialKind, key string, quirks ...config.SSHQuirk) config.Server {
		s := config.Server{ID: id, Name: id, BMC: config.BMCConfig{Address: "192.0.2.20", Kind: kind}, SSHHostKey: key,
			Credentials: config.CredentialRef{ReadOnly: id + "-ro", Operator: id + "-op"}}
		s.Console.Serial, s.Console.SSH = serial, config.SSHConfig{Port: 22, Quirks: quirks}
		return s
	}
	cfg := config.Config{Servers: []config.Server{
		mk("a", config.KindIDRAC8, config.SerialBMCSSH, fake.HostKeyLine(), config.QuirkIDRAC8LegacySSH),
		mk("b", config.KindIDRAC9, config.SerialBMCSSH, ""),
		mk("c", config.KindIPMI, config.SerialSOL, ""),
		mk("d", config.KindIDRAC9, config.SerialNone, ""),
	}, Console: config.ConsoleSettings{IdleTimeout: time.Minute, MaxSession: time.Hour}}
	creds, err := secrets.ParseCredentials([]byte("a-op: {username: " + sshtest.User + ", password: \"" + sshtest.Password + "\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	svc, err := buildSerial(cfg, creds, nopAudit{}, env{}, slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if st := svc.Status("a"); !st.Configured || !st.HasLogin || !st.HasHostKey || !st.Legacy || !st.Supported {
		t.Errorf("a = %+v", st)
	}
	if st := svc.Status("b"); !st.Configured || st.HasLogin || st.HasHostKey {
		t.Errorf("b = %+v", st)
	}
	if st := svc.Status("c"); !st.Configured || st.Supported {
		t.Errorf("c = %+v", st)
	}
	if svc.Status("d").Configured {
		t.Error("serial none configured")
	}
	for _, want := range []string{"idrac8_legacy_ssh", "ssh_host_key is not configured", "operator credential missing",
		"IPMI SOL is not implemented"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, logs.String())
		}
	}
	if strings.Contains(logs.String(), sshtest.Password) {
		t.Fatal("password logged")
	}
}
