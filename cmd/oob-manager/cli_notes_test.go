package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// blockStoreMarker makes the store marker of dataDir impossible to remove (a non-empty
// directory in its place), so every start with a config.yaml reports it.
func blockStoreMarker(t *testing.T, dataDir string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(storeMarkerPath(dataDir), "keep"), 0o700); err != nil {
		t.Fatal(err)
	}
}

// A CLI subcommand prints the start notes that report a problem to stderr (plan 09 N2):
// a store marker that cannot be removed is otherwise invisible outside serve.
func TestCLIPrintsStartProblems(t *testing.T) {
	d := newDeployment(t, "")
	blockStoreMarker(t, d.dir)
	backupDir := t.TempDir()
	for _, args := range [][]string{
		{"token", "list", "-config", d.configPath},
		{"settings", "export", "-config", d.configPath},
		{"backup", "-config", d.configPath, backupDir},
		{"verify-audit", "-config", d.configPath},
		{"bootstrap-admin", "-config", d.configPath, "-username", "owner"},
		{"confirm-totp", "-config", d.configPath, "-username", "owner"},
	} {
		_, _, errOut := runCLI(t, args...)
		if strings.Count(errOut, "could not remove "+storeMarkerPath(d.dir)) != 1 ||
			!strings.Contains(errOut, "oob-manager: warning: ") {
			t.Errorf("%v: the marker problem is not on stderr once: %q", args, errOut)
		}
	}
}

// Only problems are printed: the routine notes (pre-rename paths, running on built-in
// defaults) stay serve-only, so the CLI output of a healthy install is unchanged.
func TestPrintStartNotesOnlyProblems(t *testing.T) {
	var b strings.Builder
	printStartNotes(&b, []startNote{
		warnNote("deprecated config path: routine"),
		problemNote("could not remove the marker"),
		{level: slog.LevelError, msg: "running without config.yaml", cli: true},
	})
	want := "oob-manager: warning: could not remove the marker\noob-manager: error: running without config.yaml\n"
	if b.String() != want {
		t.Fatalf("printed %q, want %q", b.String(), want)
	}
}

// -config=none says so on the CLI too: the command ignores any config.yaml.
func TestCLIConfigNoneSaysSo(t *testing.T) {
	e, d := storeEnv(t)
	seedAccount(t, d.db)
	var out, errOut syncBuffer
	e2 := cliEnv(e.context(), strings.NewReader(""), &out, &errOut)
	e2.paths = d
	run([]string{"oob-manager", "token", "list", "-config", "none"}, e2)
	if !strings.Contains(errOut.String(), "oob-manager: error: running without config.yaml") {
		t.Fatalf("stderr %q", errOut.String())
	}
}
