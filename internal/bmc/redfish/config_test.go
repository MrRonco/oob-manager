package redfish

import (
	"errors"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
)

const goodPin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestConfigValidation(t *testing.T) {
	base := Config{Endpoint: "https://192.0.2.70", Username: "u", Password: "p", PinSHA256: goodPin}
	cases := []struct {
		name   string
		mutate func(*Config)
		ok     bool
	}{
		{"valid", func(*Config) {}, true},
		{"valid with port", func(c *Config) { c.Endpoint = "https://192.0.2.70:8443" }, true},
		{"colon pin", func(c *Config) { c.PinSHA256 = colonise(goodPin) }, true},
		{"upper pin", func(c *Config) { c.PinSHA256 = strings.ToUpper(goodPin) }, true},
		{"http refused", func(c *Config) { c.Endpoint = "http://192.0.2.70" }, false},
		{"path refused", func(c *Config) { c.Endpoint = "https://192.0.2.70/redfish" }, false},
		{"userinfo refused", func(c *Config) { c.Endpoint = "https://a:b@192.0.2.70" }, false},
		{"query refused", func(c *Config) { c.Endpoint = "https://192.0.2.70?x=1" }, false},
		{"no host", func(c *Config) { c.Endpoint = "https://" }, false},
		{"garbage url", func(c *Config) { c.Endpoint = "://bad" }, false},
		{"missing pin", func(c *Config) { c.PinSHA256 = "" }, false},
		{"short pin", func(c *Config) { c.PinSHA256 = "abcd" }, false},
		{"non-hex pin", func(c *Config) { c.PinSHA256 = strings.Repeat("zz", 32) }, false},
		{"missing user", func(c *Config) { c.Username = "" }, false},
		{"missing password", func(c *Config) { c.Password = "" }, false},
		{"negative timeout", func(c *Config) { c.Timeout = -time.Second }, false},
		{"huge timeout", func(c *Config) { c.Timeout = time.Hour }, false},
		{"negative cap", func(c *Config) { c.MaxBodyBytes = -1 }, false},
		{"basic auth", func(c *Config) { c.Auth = AuthBasic }, true},
		{"session auth", func(c *Config) { c.Auth = AuthSession }, true},
		{"unknown auth", func(c *Config) { c.Auth = "digest" }, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := base
			c.mutate(&cfg)
			_, err := New(cfg)
			if c.ok && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !c.ok && !errors.Is(err, bmc.ErrInvalidConfig) {
				t.Fatalf("want ErrInvalidConfig, got %v", err)
			}
		})
	}
}

func TestConfigDefaults(t *testing.T) {
	cfg, err := Config{Endpoint: "https://h", Username: "u", Password: "p", PinSHA256: goodPin}.normalised()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Timeout != DefaultTimeout || cfg.MaxBodyBytes != DefaultMaxBodyBytes || cfg.Auth != AuthSession {
		t.Fatalf("defaults not applied: %+v", cfg)
	}
}

func TestConfigErrorNeverContainsPassword(t *testing.T) {
	_, err := New(Config{Endpoint: "http://h", Username: "u", Password: "s3cret-value", PinSHA256: goodPin})
	if err == nil || strings.Contains(err.Error(), "s3cret-value") {
		t.Fatalf("error leaks secret or is nil: %v", err)
	}
}

func colonise(hexs string) string {
	var b strings.Builder
	for i := 0; i < len(hexs); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(hexs[i : i+2])
	}
	return b.String()
}
