package main

import (
	"log/slog"
	"strings"
	"testing"

	"oob-manager/internal/config"
)

// TestExposureNotes: serve warns when config.yaml puts the console on a public address
// (it is designed for a management LAN, deploy/README.md "Networking: keep it on the LAN").
func TestExposureNotes(t *testing.T) {
	for _, c := range []struct {
		name, listen, publicURL string
		want                    []string
	}{
		{"defaults", ":8443", "", nil},
		{"LAN url", ":8443", "https://192.0.2.20:8443/", nil},
		{"private url", ":8443", "https://[fd00::20]:8443/", nil},
		{"host name url", ":8443", "https://oob.example/", nil},
		{"loopback listen", "127.0.0.1:8443", "", nil},
		{"public url", ":8443", "https://9.9.9.9:8443/", []string{"public_url 9.9.9.9 is a public address"}},
		{"public listen", "9.9.9.9:8443", "", []string{"listen 9.9.9.9 is a public address"}},
		{"public IPv6 url", ":8443", "https://[2620:fe::fe]:8443/", []string{"public_url 2620:fe::fe is a public address"}},
		{"public IPv6 listen", "[2620:fe::fe]:8443", "", []string{"listen 2620:fe::fe is a public address"}},
		{"mapped public IPv4 listen", "[::ffff:9.9.9.9]:8443", "", []string{"listen 9.9.9.9 is a public address"}},
		{"mapped public IPv4 url", ":8443", "https://[::ffff:9.9.9.9]/", []string{"public_url 9.9.9.9 is a public address"}},
		{"unspecified IPv4", "0.0.0.0:8443", "", nil},
		{"unspecified IPv6", "[::]:8443", "", nil},
		{"port only", ":8443", "https://[::]:8443/", nil},
		{"zoned link-local", "[fe80::1%eth0]:8443", "https://[fe80::1%25eth0]:8443/", nil},
		{"garbage", "not an address", "::not a url::", nil},
		{"documentation IPv6", ":8443", "https://[2001:db8::20]/", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			notes := exposureNotes(config.Config{Listen: c.listen, PublicURL: c.publicURL})
			if len(notes) != len(c.want) {
				t.Fatalf("notes = %+v, want %d", notes, len(c.want))
			}
			for i, n := range notes {
				if n.level != slog.LevelWarn || !strings.Contains(n.msg, c.want[i]) ||
					!strings.Contains(n.msg, "keep it on the LAN") {
					t.Errorf("note %d = %+v, want a warning containing %q", i, n, c.want[i])
				}
			}
		})
	}
}
