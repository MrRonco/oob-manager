// Command oob-manager is the out-of-band management web app (wire-up only; see docs/).
//
// Subcommands: serve, bootstrap-admin, confirm-totp, reset-totp, gen-app-keys, gen-tls, token,
// settings, catalog, version, healthcheck.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"oob-manager/internal/config"
	"oob-manager/internal/console"
	"oob-manager/internal/integrations"
	"oob-manager/internal/secprobe"
	"oob-manager/internal/tofu"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "dev"

// repoURL (-ldflags "-X main.repoURL=https://…") is the project's source URL for the
// About page; empty hides the links. Nothing installation-specific belongs here.
var repoURL = ""

// env is everything a subcommand touches outside the process, so tests can fake it.
type env struct {
	ctx       context.Context // cancelled on SIGTERM/SIGINT
	in        *bufio.Reader
	out       io.Writer
	errOut    io.Writer
	healthURL string
	// noEcho turns terminal echo off and returns the function that restores it.
	noEcho func() (restore func(), err error)
	// stdoutTTY reports whether out is a terminal; one-time secrets are refused otherwise.
	stdoutTTY func() bool
	// listen opens the UI listener (tests inject a pre-bound one).
	listen func(network, addr string) (net.Listener, error)
	// newDriver builds a BMC driver for a configured server.
	newDriver driverFactory
	// vncDial (nil: net.Dialer) and kvmEndpoint (nil: https://<bmc.address>:443; also the
	// power control endpoint) let the e2e harness point the console and power control at
	// mocks; production never sets them.
	vncDial     console.DialFunc
	kvmEndpoint func(config.Server) string
	// sshDial (nil: net.Dialer) lets the e2e harness point the serial console at a fake BMC.
	sshDial console.DialFunc
	// bmcDial (nil: net.Dialer) lets the e2e harness point fingerprint fetches and the
	// Test connection's SSH and VNC reads at fakes; production never sets it.
	bmcDial tofu.Dialer
	// gelfDial (nil: net.Dialer) lets tests point the GELF shipper at local receivers
	// while config.yaml names a policy-allowed address; production never sets it.
	gelfDial integrations.DialFunc
	// probeDial dials the security checks' handshake probes (tech_doc §31). main sets a
	// net.Dialer; nil refuses every dial, so an env that does not set it (any test) never
	// reaches the network from a probe. The e2e harness points it at the fakes.
	probeDial secprobe.Dialer
	// stepUpWindow, when > 0, replaces the step-up window in force. It is a test hook
	// only: config.yaml and Settings accept 1–5 minutes, main never sets it, and the e2e
	// harness uses it to watch a window lapse in seconds.
	stepUpWindow time.Duration
	// autoRefresh, when > 0, replaces the UI's opt-in auto-refresh interval (60 s). A
	// test hook only: the dev harness shortens it so the Playwright refresh test can
	// watch a reload happen, or not, within seconds.
	autoRefresh time.Duration
	// uiHistoryNow, when set, is the "now" the web UI's history charts are drawn for (the
	// sensor history itself keeps the real clock). A test hook only: the e2e harness
	// freezes it on its seed's grid line so sparklines and the Overview recorder draw the
	// same window in every run; main never sets it.
	uiHistoryNow func() time.Time
	// paths (zero: productionPaths) are the default config and database locations; tests
	// point them at a temp dir to exercise the pre-rename fallbacks.
	paths pathDefaults
	// catalogTLS (nil: system roots), catalogTick (0: 30 s) and catalogFirst (nil: 2–10
	// min) let the e2e harness point the firmware update check at a local TLS catalog
	// server and run it in seconds; production never sets them.
	catalogTLS   *tls.Config
	catalogTick  time.Duration
	catalogFirst func() time.Duration
	// restart (zero: the fleet defaults, 60 s quiet then a poll every 30 s) is the BMC
	// restart window's cadence. A test hook only: the e2e harness shortens it so a mock
	// BMC restart is watched in seconds.
	restart restartCadence
}

// restartCadence is the fleet's BMC restart window cadence (fleet.Config.RestartQuiet,
// RestartRetry); zero values take the defaults.
type restartCadence struct{ quiet, retry time.Duration }

func main() {
	// Owner-only files from every subcommand, before anything is created: serve, and any
	// CLI command that may create the database (bootstrap-admin, token, settings, backup),
	// the store-install marker, generated keys or TLS files (plan 06 §3.1). In main, not
	// run, so in-process tests keep their own umask.
	restrictUmask()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	code := run(os.Args, env{
		ctx: ctx, in: bufio.NewReader(os.Stdin), out: os.Stdout, errOut: os.Stderr,
		healthURL: defaultHealthURL, noEcho: stdinNoEcho, stdoutTTY: stdoutIsTerminal, listen: net.Listen,
		newDriver: newBMCDriver, probeDial: (&net.Dialer{}).DialContext,
	})
	stop()
	os.Exit(code)
}

// run dispatches subcommands and returns the process exit code.
func run(args []string, e env) int {
	if len(args) < 2 {
		usage(e.errOut)
		return 2
	}
	sub, rest := args[1], args[2:]
	switch sub {
	case "version":
		_, _ = fmt.Fprintf(e.out, "oob-manager %s\n", version)
		return 0
	case "healthcheck":
		if err := checkHealth(context.Background(), e.healthURL, healthTimeout); err != nil {
			_, _ = fmt.Fprintln(e.errOut, err)
			return 1
		}
		return 0
	case "serve":
		return exitCode(e, serveCmd(e, rest))
	case "bootstrap-admin":
		return exitCode(e, bootstrapCmd(e, rest))
	case "confirm-totp":
		return exitCode(e, confirmCmd(e, rest))
	case "gen-app-keys":
		return exitCode(e, genAppKeysCmd(e))
	case "reset-totp":
		return exitCode(e, resetTOTPCmd(e, rest))
	case "gen-tls":
		return exitCode(e, genTLSCmd(e, rest))
	case "token":
		return exitCode(e, tokenCmd(e, rest))
	case "settings":
		return exitCode(e, settingsCmd(e, rest))
	case "catalog":
		return exitCode(e, catalogCmd(e, rest))
	case "admin-recover":
		return exitCode(e, adminRecoverCmd(e, rest))
	case "backup":
		return exitCode(e, backupCmd(e, rest))
	case "verify-audit":
		return exitCode(e, verifyAuditCmd(e, rest))
	default:
		_, _ = fmt.Fprintf(e.errOut, "oob-manager: unknown command %q\n", sub)
		usage(e.errOut)
		return 2
	}
}

func exitCode(e env, err error) int {
	if err == nil {
		return 0
	}
	_, _ = fmt.Fprintln(e.errOut, "oob-manager:", err)
	return 1
}

func usage(w io.Writer) {
	_, _ = fmt.Fprint(w, `usage: oob-manager <command> [flags]
  serve            [-config path]           run the web app
  bootstrap-admin  [-config path] -username create the first admin (prints TOTP enrollment once)
  confirm-totp     [-config path] -username confirm a pending TOTP enrollment
  reset-totp       [-config path] --user <name>
                                            new TOTP secret (shown ONCE on the terminal), ends all sessions
  gen-app-keys                              print a fresh app-keys document (pipe into age)
  gen-tls          --host <ip|name> [--host ...] --out <dir> [--days 825]
                                            write a self-signed ECDSA P-256 tls.crt/tls.key
  token create     --name <label> [--expires 90d|never] [--owner user]
                                            mint a read-only API token (printed ONCE on stdout)
  token list                                list tokens (id, name, created, last used, expiry)
  token revoke     <id>                     revoke a token
  settings import  -servers id1,id2         copy config.yaml servers (and their credentials) into the database
  settings export                           print the effective settings and servers as YAML, without secrets
  catalog import   <catalog.xml.gz> [<.sign>]
                                            import a vendor firmware catalog (signature checked; read-only)
  admin-recover    [-config path] -username break glass: re-enable, make admin, clear lockout, end sessions
  backup           [-config path] <dir>     consistent copy of the database into dir (0600; never the keys)
  verify-audit     [-config path] [db]      check an audit hash chain offline (default: the configured database)
  version                                   print the version
  healthcheck                               GET https://127.0.0.1:8443/healthz (container probe)
`)
}
