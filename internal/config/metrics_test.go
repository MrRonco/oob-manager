package config

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestMetricsDefaultsOff(t *testing.T) {
	m := mustParse(t, validYAML()).Metrics
	if m.Enabled || m.IncludeInventory || len(m.AllowNetworks) != 0 {
		t.Fatalf("metrics defaults = %+v", m)
	}
	if got := m.Networks(); got != nil {
		t.Fatalf("no networks configured, got %v", got)
	}
}

func TestMetricsParse(t *testing.T) {
	m := mustParse(t, validYAML()+"metrics: { enabled: true, include_inventory: true, allow_networks: [192.0.2.0/24, 198.51.100.7] }\n").Metrics
	if !m.Enabled || !m.IncludeInventory {
		t.Fatalf("metrics = %+v", m)
	}
	want := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("198.51.100.7/32")}
	got := m.Networks()
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("networks = %v, want %v", got, want)
	}
}

func TestMetricsRejectsBadNetwork(t *testing.T) {
	_, err := Parse([]byte(validYAML() + "metrics: { enabled: true, allow_networks: [not-a-net, 192.0.2.0/33] }\n"))
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	if n := strings.Count(err.Error(), "metrics.allow_networks"); n != 2 {
		t.Fatalf("want 2 metrics problems, got %d: %v", n, err)
	}
}

func TestMetricsRejectsUnknownKey(t *testing.T) {
	if _, err := Parse([]byte(validYAML() + "metrics: { enabled: true, include_identity: true }\n")); err == nil {
		t.Fatal("unknown metrics key accepted")
	}
}
