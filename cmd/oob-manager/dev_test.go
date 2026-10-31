//go:build e2e

package main

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"oob-manager/internal/bmc/redfishmock"
)

// devState is what `make dev` and the Playwright smoke test need to sign in. It is
// written (mode 0600) to a temp path only and removed on exit; never commit it.
type devState struct {
	URL        string `json:"url"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	TOTPSecret string `json:"totp_secret"`
	APIToken   string `json:"api_token"`
	CertFile   string `json:"cert_file"`
	// VNCDebugURL serves what the fake VNC server received (Playwright checks key events).
	VNCDebugURL string `json:"vnc_debug_url"`
	// The BMC that is not in config.yaml, for adding a server in the browser: its
	// address and the mock's fixture-only read-only login.
	ExtraAddress string `json:"extra_address"`
	ExtraUser    string `json:"extra_user"`
	ExtraPass    string `json:"extra_password"`
	// The TLS GELF input the Integrations spec pins (TEST-NET-1, reached through the
	// harness dialer); shipping is off until the spec turns it on.
	GELFTLSAddress string `json:"gelf_tls_address"`
}

// TestDevServer runs the app against the two mock BMCs until SIGINT/SIGTERM. It is a
// development tool, not a test: it only runs with OOB_DEV=1 (see `make dev`).
//
//	OOB_DEV_LISTEN  listen address (default 127.0.0.1:8443)
//	OOB_DEV_STATE   file NAME for the sign-in details, created in os.TempDir()
//	                (default: dev-credentials.json inside the temp install)
//	OOB_DEV_REFRESH opt-in auto-refresh interval, e.g. 3s (default: the UI's 60 s)
//	OOB_DEV_SHOWCASE=1 the README screenshot fixtures (e2e_showcase_harness_test.go)
func TestDevServer(t *testing.T) {
	if os.Getenv("OOB_DEV") == "" {
		t.Skip("development server; run `make dev`")
	}
	// The firmware.minimum rule of the firmware e2e stack, so the Firmware page shows a flagged row.
	fw := firmwareYAML
	if showcaseOn() {
		fw = showcaseFirmwareYAML
	}
	s := startStackMode(t, cmp.Or(os.Getenv("OOB_DEV_LISTEN"), "127.0.0.1:8443"), fw, 0, showcaseOn())
	statePath := devStatePath(os.Getenv("OOB_DEV_STATE"), s.dir)
	writeDevState(t, statePath, devState{URL: s.base + "/", Username: e2eUser, Password: e2ePassword,
		TOTPSecret: s.secret, APIToken: s.token, CertFile: s.certPath, VNCDebugURL: serveVNCDebug(t, s),
		ExtraAddress: extraAddress, ExtraUser: redfishmock.User, ExtraPass: redfishmock.Password,
		GELFTLSAddress: gelfTLSAddr})
	t.Cleanup(func() { _ = os.Remove(statePath) })

	_, _ = fmt.Fprintf(os.Stderr, "\noob-manager dev server (mock BMCs, self-signed TLS)\n"+
		"  URL:          %s/\n  Sign-in file: %s\n  Username:     %s\n"+
		"Codes for the TOTP step are printed below every 30 s. Ctrl-C stops it.\n\n",
		s.base, statePath, e2eUser)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	printCodes(ctx, t, s.secret)
}

func writeDevState(t *testing.T, path string, st devState) {
	t.Helper()
	// The password and TOTP secret are throwaway test values for this run only; the
	// file is 0600 in a temp dir and removed on exit.
	b, err := json.MarshalIndent(st, "", "  ") //nolint:gosec // G117: deliberate, see above
	if err != nil {
		t.Fatal(err)
	}
	write(t, path, b)
}

// printCodes prints the current TOTP code at every 30 s step until ctx ends.
func printCodes(ctx context.Context, t *testing.T, secret string) {
	for {
		now := time.Now()
		_, _ = fmt.Fprintf(os.Stderr, "%s  TOTP code: %s\n", now.Format(time.TimeOnly), totpCode(t, secret, now))
		next := now.Truncate(30 * time.Second).Add(30 * time.Second)
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Until(next)):
		}
	}
}

// devStatePath confines the sign-in file to the temp directory: OOB_DEV_STATE may only
// name a file, never a path, so the dev harness cannot be pointed at the repository.
func devStatePath(name, installDir string) string {
	if name == "" {
		return filepath.Join(installDir, "dev-credentials.json")
	}
	return filepath.Join(os.TempDir(), filepath.Base(filepath.Clean(name)))
}
