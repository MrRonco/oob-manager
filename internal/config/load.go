package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Load reads, parses and validates the config file at path.
func Load(path string) (Config, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return Config{}, fmt.Errorf("config: open: %w", err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxConfigBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("config: read: %w", err)
	}
	if len(data) > MaxConfigBytes {
		return Config{}, fmt.Errorf("config: file too large (> %d bytes)", MaxConfigBytes)
	}
	return Parse(data)
}

// Defaults is the configuration of an install without config.yaml (plan 09): every key
// at its default, no servers, TLS and public_url unset. It carries no file hash and no
// file keys, so every runtime-managed setting is editable in the browser.
func Defaults() (Config, error) {
	cfg := normalise(withDefaults(Config{}))
	if err := Validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Parse decodes YAML strictly (unknown keys are errors), applies defaults, normalises
// aliases and validates. It returns a new Config; data is not retained.
func Parse(data []byte) (Config, error) {
	raw, err := decodeStrict(data)
	if err != nil {
		return Config{}, err
	}
	cfg := normalise(withDefaults(raw))
	if verr := Validate(cfg); verr != nil {
		return Config{}, verr
	}
	keys, err := fileKeys(data)
	if err != nil {
		return Config{}, err
	}
	cfg.FileKeys = keys
	sum := sha256.Sum256(data)
	cfg.SHA256 = hex.EncodeToString(sum[:])
	return cfg, nil
}

func decodeStrict(data []byte) (Config, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return Config{}, errors.New("config: empty file")
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var cfg Config
	if err := dec.Decode(&cfg); err != nil {
		return Config{}, fmt.Errorf("config: decode: %w", err)
	}
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case errors.Is(err, io.EOF):
		return cfg, nil
	case err != nil:
		return Config{}, fmt.Errorf("config: decode: %w", err)
	default:
		return Config{}, errors.New("config: multiple YAML documents are not allowed")
	}
}

func withDefaults(c Config) Config {
	c.Listen = orDefault(c.Listen, DefaultListen)
	c.Auth.Mode = AuthMode(orDefault(string(c.Auth.Mode), string(AuthLocal)))
	if c.Auth.SessionIdle == 0 {
		c.Auth.SessionIdle = DefaultSessionIdle
	}
	if c.Auth.SessionMax == 0 {
		c.Auth.SessionMax = DefaultSessionMax
	}
	if c.Auth.StepUpWindow == 0 {
		c.Auth.StepUpWindow = DefaultStepUpWindow
	}
	if c.Poll.Interval == 0 {
		c.Poll.Interval = DefaultPollInterval
	}
	if c.Poll.MinInterval == 0 {
		c.Poll.MinInterval = DefaultPollMinInterval
	}
	if c.Audit.GELF.Address != "" {
		c.Audit.GELF.Transport = orDefault(c.Audit.GELF.Transport, "tcp")
	}
	c.Storage.DBPathDefaulted = c.Storage.DBPath == ""
	c.Storage.DBPath = orDefault(c.Storage.DBPath, DefaultDBPath)
	c.Storage.LeaseDir = orDefault(c.Storage.LeaseDir, DefaultLeaseDir)
	c.TLS.Defaulted = c.TLS.CertFile == "" && c.TLS.KeyFile == ""
	c.Secrets.CredentialsDefaulted = c.Secrets.CredentialsFile == ""
	c.Secrets.IdentityDefaulted = c.Secrets.IdentityFile == ""
	c.Secrets.AppKeysDefaulted = c.Secrets.AppKeysFile == ""
	c.Secrets.CredentialsFile = orDefault(c.Secrets.CredentialsFile, DefaultCredentialsFile)
	c.Secrets.IdentityFile = orDefault(c.Secrets.IdentityFile, DefaultIdentityFile)
	c.Secrets.AppKeysFile = orDefault(c.Secrets.AppKeysFile, DefaultAppKeysFile)
	c.Console = consoleDefaults(c.Console)
	c.Notifications = notificationDefaults(c.Notifications)
	c.Security = securityDefaults(c.Security)
	return generalDefaults(c)
}

// normalise returns a copy with alias spellings mapped to canonical values.
func normalise(c Config) Config {
	servers := make([]Server, len(c.Servers))
	for i, s := range c.Servers {
		servers[i] = Normalise(s)
	}
	c.Servers = servers
	return c
}

// Normalise returns a copy of s with alias spellings mapped and every default filled
// in, exactly as Load does for config.yaml servers. Servers saved from the browser go
// through it before ValidateServer.
func Normalise(s Server) Server {
	n := s.clone()
	n.Fan.Mode = canonicalFanMode(s.Fan.Mode)
	n.TLSPinSHA256 = strings.ToLower(s.TLSPinSHA256)
	n.BMC = bmcDefaults(s.BMC)
	n.Console.VNC = vncDefaults(s.BMC.Kind, s.Console.VNC)
	n.Console.SSH = sshDefaults(s.BMC.Kind, s.Console.SSH)
	if n.Console.Serial == "" {
		n.Console.Serial = SerialNone
	}
	if n.Console.Graphical == "" {
		n.Console.Graphical = GraphicalNone
	}
	return n
}

func canonicalFanMode(m FanMode) FanMode {
	switch m {
	case "hostlease":
		return FanHostLease
	case "redfishfloor":
		return FanRedfishFloor
	case "ipmioem":
		return FanIPMIOEM
	case "":
		return FanNone
	default:
		return m
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
