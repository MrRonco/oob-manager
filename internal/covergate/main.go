// Command covergate fails the build when statement coverage is below a minimum, for the
// module as a whole and for every package in the profile on its own (CLAUDE.md rule 1),
// so a new package is gated without editing a list.
//
//	go run ./internal/covergate -profile cover.out -min 80 -module "$(go list -m)" \
//	    -exclude "internal/bmc/redfishmock …" internal/auth internal/authz …
//
// Positional arguments are required packages: they must appear in the profile, so a
// rename cannot drop a security-relevant package from the gate. -exclude lists packages
// that are reported but not gated; each must still exist. Paths are relative to -module
// (full import paths when -module is empty). Packages without statements (test-only)
// are ignored. The profile must come from `go test -coverprofile` without -coverpkg:
// each package's figure is then its own tests' coverage of it.
//
// Exit status: 0 all gates pass, 1 a gate failed, 2 usage or input error. Standard
// library only.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("covergate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profile := fs.String("profile", "", "coverage profile written by go test -coverprofile")
	minPct := fs.Float64("min", 80, "minimum statement coverage in percent (0-100)")
	module := fs.String("module", "", "module path the package paths are relative to (go list -m)")
	exclude := fs.String("exclude", "", "space- or comma-separated packages that are not gated")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *profile == "" || *minPct < 0 || *minPct > 100 {
		_, _ = fmt.Fprintln(stderr, "covergate: need -profile and 0 <= -min <= 100")
		return 2
	}
	cov, err := readProfile(*profile)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "covergate: %v\n", err)
		return 2
	}
	g := gate{minPct: *minPct, module: *module, required: fs.Args(), exclude: splitList(*exclude)}
	report, ok := check(cov, g)
	for _, l := range report {
		_, _ = fmt.Fprintln(stdout, l)
	}
	if !ok {
		_, _ = fmt.Fprintf(stderr, "covergate: coverage below %g %% (see FAIL lines)\n", *minPct)
		return 1
	}
	return 0
}

func readProfile(name string) (coverage, error) {
	f, err := os.Open(name) // #nosec G304 -- developer-supplied profile path (Makefile)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	cov, err := parseProfile(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return cov, nil
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}
