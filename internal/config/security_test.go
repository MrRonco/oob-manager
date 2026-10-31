package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSecurityDefaults(t *testing.T) {
	s := mustParse(t, validYAML()).Security
	if !s.On() || s.Every != DefaultSecurityEvery || s.MinFirmware != (MinFirmware{}) {
		t.Fatalf("security defaults = %+v", s)
	}
	if DefaultSecurityEvery != 6*time.Hour {
		t.Fatalf("default every = %v", DefaultSecurityEvery)
	}
}

func TestSecurityParse(t *testing.T) {
	s := mustParse(t, validYAML()+`security:
  every: 12h
  min_firmware: { idrac8: "2.86.86.86", idrac9: 7.10.30.00, redfish: "1.20" }
`).Security
	if !s.On() || s.Every != 12*time.Hour {
		t.Fatalf("security = %+v", s)
	}
	for k, want := range map[BMCKind]string{KindIDRAC8: "2.86.86.86", KindIDRAC9: "7.10.30.00", KindRedfish: "1.20", KindIPMI: ""} {
		if got := s.MinFirmware.For(k); got != want {
			t.Errorf("MinFirmware.For(%s) = %q, want %q", k, got, want)
		}
	}
	if off := mustParse(t, validYAML()+"security: { enabled: false }\n").Security; off.On() {
		t.Fatal("enabled: false is on")
	}
}

func TestSecurityRejectsBadValues(t *testing.T) {
	_, err := Parse([]byte(validYAML() + `security:
  every: 30m
  min_firmware: { idrac8: "v2.86", idrac9: "7..0", redfish: "1.2.3.4.5.6.7" }
`))
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	for _, want := range []string{"security.every 30m0s must be in [1h0m0s, 168h0m0s]", "security.min_firmware.idrac8",
		"security.min_firmware.idrac9", "security.min_firmware.redfish"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	if _, err := Parse([]byte(validYAML() + "security: { every: 200h }\n")); err == nil {
		t.Fatal("every above 7 days accepted")
	}
}

func TestSecurityRejectsUnknownKeys(t *testing.T) {
	for _, extra := range []string{"security: { interval: 6h }\n", "security: { min_firmware: { ipmi: \"1.0\" } }\n"} {
		if _, err := Parse([]byte(validYAML() + extra)); err == nil {
			t.Errorf("accepted %q", extra)
		}
	}
}
