package metrics

import (
	"strconv"

	"oob-manager/internal/bmc"
	"oob-manager/internal/fleet"
)

// SecurityCounts are a server's BMC security check results (bmcsec.Counts).
type SecurityCounts struct {
	Pass, Info, Warn, Fail, Unknown, CantRead, Accepted int
}

// addSecurity writes the check counts (from the hook) and the certificate expiry of each
// probe that read the pinned certificate (from the fleet's last posture).
func (c *Collector) addSecurity(b *builder, s fleet.ServerState, sl Label) {
	if c.cfg.Security != nil {
		if n, ok := c.cfg.Security(s.ID); ok {
			for _, r := range []struct {
				name string
				v    int
			}{{"fail", n.Fail}, {"warn", n.Warn}, {"cant-read", n.CantRead}, {"unknown", n.Unknown},
				{"info", n.Info}, {"pass", n.Pass}, {"accepted", n.Accepted}} {
				b.add("oob_security_checks", float64(r.v), sl, Label{"result", r.name})
			}
		}
	}
	if !s.HasPosture {
		return
	}
	for _, p := range []bmc.TLSProbe{s.Posture.Web, s.Posture.VNC} {
		if p.Usable() && !p.Cert.NotAfter.IsZero() {
			b.add("oob_tls_cert_expiry_timestamp_seconds", unixSeconds(p.Cert.NotAfter), sl, Label{"port", strconv.Itoa(p.Port)})
		}
	}
}
