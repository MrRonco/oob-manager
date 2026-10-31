package config

import (
	"strings"
	"testing"
)

// A store-style install (plan 09) runs without config.yaml or with a minimal one: TLS,
// the secret files and public_url may be left out, and the binary fills them in from
// the data volume. What was left out is recorded so a configured path is never replaced.

func TestDefaultsWithoutAFile(t *testing.T) {
	cfg, err := Defaults()
	if err != nil {
		t.Fatalf("Defaults: %v", err)
	}
	if !cfg.TLS.Defaulted || cfg.TLS.CertFile != "" || cfg.TLS.KeyFile != "" {
		t.Errorf("TLS = %+v, want defaulted and empty", cfg.TLS)
	}
	s := cfg.Secrets
	if !s.IdentityDefaulted || !s.AppKeysDefaulted || !s.CredentialsDefaulted {
		t.Errorf("secrets defaulted flags = %+v, want all true", s)
	}
	if s.IdentityFile != DefaultIdentityFile || s.AppKeysFile != DefaultAppKeysFile || s.CredentialsFile != DefaultCredentialsFile {
		t.Errorf("secret paths = %+v, want the mounted defaults", s)
	}
	if cfg.PublicURL != "" || cfg.SHA256 != "" || len(cfg.FileKeys) != 0 || len(cfg.Servers) != 0 {
		t.Errorf("defaults carry file state: url %q sha %q keys %v servers %d", cfg.PublicURL, cfg.SHA256, cfg.FileKeys, len(cfg.Servers))
	}
	if !cfg.Storage.DBPathDefaulted || cfg.Storage.DBPath != DefaultDBPath {
		t.Errorf("storage = %+v", cfg.Storage)
	}
}

func TestConfiguredPathsAreNotDefaulted(t *testing.T) {
	src := strings.Replace(validYAML(), "public_url:", "secrets:\n  identity_file: /run/secrets/id\n  app_keys_file: /run/secrets/keys.age\n  credentials_file: /run/secrets/creds.age\npublic_url:", 1)
	cfg := mustParse(t, src)
	if cfg.TLS.Defaulted {
		t.Error("TLS set in the file reported as defaulted")
	}
	s := cfg.Secrets
	if s.IdentityDefaulted || s.AppKeysDefaulted || s.CredentialsDefaulted {
		t.Errorf("secrets set in the file reported as defaulted: %+v", s)
	}
}

func TestEachSecretDefaultedOnItsOwn(t *testing.T) {
	src := strings.Replace(validYAML(), "public_url:", "secrets: { identity_file: /run/secrets/id }\npublic_url:", 1)
	s := mustParse(t, src).Secrets
	if s.IdentityDefaulted || !s.AppKeysDefaulted || !s.CredentialsDefaulted {
		t.Errorf("flags = %+v, want only identity configured", s)
	}
}

func TestTLSAndPublicURLOptional(t *testing.T) {
	src := strings.Replace(validYAML(), "tls: { cert_file: /run/secrets/tls-cert, key_file: /run/secrets/tls-key }\n", "", 1)
	src = strings.Replace(src, "public_url: https://oob.example\n", "", 1)
	cfg := mustParse(t, src)
	if !cfg.TLS.Defaulted || cfg.PublicURL != "" {
		t.Errorf("TLS %+v, public_url %q", cfg.TLS, cfg.PublicURL)
	}
}

func TestTLSHalfConfiguredRejected(t *testing.T) {
	for name, tls := range map[string]string{
		"cert only": "tls: { cert_file: /run/secrets/tls-cert }",
		"key only":  "tls: { key_file: /run/secrets/tls-key }",
	} {
		t.Run(name, func(t *testing.T) {
			src := strings.Replace(validYAML(), "tls: { cert_file: /run/secrets/tls-cert, key_file: /run/secrets/tls-key }", tls, 1)
			if _, err := Parse([]byte(src)); err == nil || !strings.Contains(err.Error(), "tls.") {
				t.Fatalf("err = %v, want a tls problem", err)
			}
		})
	}
}
