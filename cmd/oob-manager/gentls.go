package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"oob-manager/internal/certgen"
)

// File names gen-tls writes; config.yaml's tls.cert_file / tls.key_file point at them.
const (
	tlsCertName = "tls.crt"
	tlsKeyName  = "tls.key"
)

// hostList is a repeatable --host flag.
type hostList []string

func (h *hostList) String() string { return strings.Join(*h, ",") }

func (h *hostList) Set(v string) error {
	*h = append(*h, strings.TrimSpace(v))
	return nil
}

type genTLSArgs struct {
	hosts []string
	out   string
	days  int
}

func parseGenTLS(args []string, stderr io.Writer) (genTLSArgs, error) {
	fs := flag.NewFlagSet("gen-tls", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var hosts hostList
	fs.Var(&hosts, "host", "IP address or DNS name the UI is reached at (repeatable, required)")
	out := fs.String("out", "", "existing directory to write tls.crt and tls.key into (required)")
	days := fs.Int("days", int(certgen.MaxValidity.Hours()/24), "validity in days (1-825)")
	pos, err := parseInterleaved(fs, args)
	if err != nil {
		return genTLSArgs{}, err
	}
	if err := wantPositional("gen-tls", pos, 0); err != nil {
		return genTLSArgs{}, err
	}
	if len(hosts) == 0 || *out == "" {
		return genTLSArgs{}, errors.New("gen-tls: --host and --out are required")
	}
	return genTLSArgs{hosts: hosts, out: *out, days: *days}, nil
}

// genTLSCmd writes a self-signed ECDSA P-256 pair: tls.key (0600) and tls.crt (0644).
// Existing files are never overwritten.
func genTLSCmd(e env, args []string) error {
	a, err := parseGenTLS(args, e.errOut)
	if err != nil {
		return err
	}
	maxDays := int(certgen.MaxValidity.Hours() / 24)
	if a.days < 1 || a.days > maxDays {
		return fmt.Errorf("gen-tls: --days must be 1-%d", maxDays)
	}
	pair, err := certgen.Generate(certgen.Request{Hosts: a.hosts, Validity: time.Duration(a.days) * 24 * time.Hour})
	if err != nil {
		return err
	}
	keyPath, certPath := filepath.Join(a.out, tlsKeyName), filepath.Join(a.out, tlsCertName)
	if err := writeNew(keyPath, pair.KeyPEM, 0o600); err != nil {
		return err
	}
	if err := writeNew(certPath, pair.CertPEM, 0o644); err != nil {
		return errors.Join(err, os.Remove(keyPath))
	}
	_, _ = fmt.Fprintf(e.out, "Wrote %s (0644) and %s (0600), valid %d days for %s.\n"+
		"SHA-256 fingerprint: %s\nconfig.yaml:\n  tls: { cert_file: <dir>/%s, key_file: <dir>/%s }\n",
		certPath, keyPath, a.days, strings.Join(a.hosts, ", "), fingerprint(pair.SHA256), tlsCertName, tlsKeyName)
	return nil
}

// writeNew creates path with mode and fails if it already exists.
func writeNew(path string, b []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode) //nolint:gosec // G304: operator-chosen output path
	if err != nil {
		return fmt.Errorf("gen-tls: %w (existing files are never overwritten)", err)
	}
	if _, err := f.Write(b); err != nil {
		return errors.Join(fmt.Errorf("gen-tls: write %s: %w", path, err), f.Close(), os.Remove(path))
	}
	// Re-apply the mode: OpenFile's is filtered by the umask.
	return errors.Join(f.Chmod(mode), f.Close())
}

// fingerprint formats hex as AA:BB:..., the way browsers and Keychain show it.
func fingerprint(hexSum string) string {
	up := strings.ToUpper(hexSum)
	parts := make([]string, 0, len(up)/2)
	for i := 0; i+1 < len(up); i += 2 {
		parts = append(parts, up[i:i+2])
	}
	return strings.Join(parts, ":")
}
