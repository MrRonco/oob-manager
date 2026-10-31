package config

import (
	"strings"
	"testing"
)

// operatorYAML is validYAML with the R730XD's credentials, fan and console replaced.
func operatorYAML(creds, fan, console string) string {
	return strings.Replace(validYAML(),
		"credentials: { readonly: r730xd-ro, operator: r730xd-op, vnc: r730xd-vnc }\n    fan: { mode: host-lease, safe_min_pct: 30, max_lease: 2h }\n    console: { serial: bmcssh, graphical: vnc }",
		"credentials: "+creds+"\n    fan: "+fan+"\n    console: "+console, 1)
}

// TestOperatorRequirementPerFeature: the operator login is required exactly by the
// features that log in with it (redfish-floor and ipmi-oem fans, a serial console, the
// native KVM launch). host-lease fans write a file and VNC has its own credential; power
// control is optional and simply stays off without an operator login.
func TestOperatorRequirementPerFeature(t *testing.T) {
	const noOp, withVNC = "{ readonly: r730xd-ro }", "{ readonly: r730xd-ro, vnc: r730xd-vnc }"
	const consoleOff = "{ serial: none, graphical: none }"
	cases := []struct {
		name, creds, fan, console, want string
	}{
		{"host-lease only", noOp, "{ mode: host-lease, safe_min_pct: 30, max_lease: 2h }", consoleOff, ""},
		{"vnc only", withVNC, "{ mode: none }", "{ serial: none, graphical: vnc }", ""},
		{"power only", noOp, "{ mode: none }", consoleOff, ""},
		{"serial", noOp, "{ mode: none }", "{ serial: bmcssh, graphical: none }", "console.serial bmcssh"},
		{"ipmi-oem", noOp, "{ mode: ipmi-oem, safe_min_pct: 30, max_lease: 30m }", consoleOff, "fan.mode ipmi-oem"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(operatorYAML(tc.creds, tc.fan, tc.console)))
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), "credentials.operator is required for "+tc.want)):
				t.Fatalf("err = %v, want credentials.operator for %s", err, tc.want)
			}
		})
	}
	r240 := strings.Replace(validYAML(), "credentials: { readonly: r240-ro, operator: r240-op }", "credentials: { readonly: r240-ro }", 1)
	_, err := Parse([]byte(r240))
	for _, want := range []string{"fan.mode redfish-floor", "console.serial bmcssh", "console.graphical kvm-launch"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("r240 without operator: err = %v, want it to name %s", err, want)
		}
	}
}
