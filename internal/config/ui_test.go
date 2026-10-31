package config

import (
	"strings"
	"testing"
)

func TestUIInstanceName(t *testing.T) {
	src := strings.Replace(validYAML(), "public_url:", "ui: { instance_name: \"Lab OOB\" }\npublic_url:", 1)
	cfg := mustParse(t, src)
	if cfg.UI.InstanceName != "Lab OOB" {
		t.Fatalf("instance name = %q", cfg.UI.InstanceName)
	}
	if got := mustParse(t, validYAML()).UI.InstanceName; got != "" {
		t.Fatalf("default instance name = %q, want empty", got)
	}
}

func TestUIInstanceNameRejected(t *testing.T) {
	for name, value := range map[string]string{
		"too long": strings.Repeat("x", 65),
		"control":  "lab\\tOOB",
		"markup":   "<b>lab</b>",
		"spaces":   " lab ",
	} {
		t.Run(name, func(t *testing.T) {
			src := strings.Replace(validYAML(), "public_url:", "ui: { instance_name: \""+value+"\" }\npublic_url:", 1)
			_, err := Parse([]byte(src))
			if err == nil || !strings.Contains(err.Error(), "ui.instance_name") {
				t.Fatalf("err = %v, want ui.instance_name problem", err)
			}
		})
	}
}
