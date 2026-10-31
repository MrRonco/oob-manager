//go:build e2e

package main

// Showcase mode: the README screenshots (tests/e2e/showcase.spec.ts, `make showcase`) are
// taken from the dev server with OOB_DEV_SHOWCASE=1. It changes only fixture text and the
// fake consoles, so that no screenshot shows a test artefact: a firmware note that reads
// like a real one, a host transcript on the serial console, a text-mode boot menu on the
// graphical console instead of the solid red test frame, neutral "What goes down" lines,
// and log entries moved so the newest is a few minutes old (the captured logs are years
// old) with a neutral client address. `make showcase` also stamps the release version into its own harness build.
// Every other spec and the visual baseline run without it and see none of this.

import (
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/console/rfbtest"
)

// showcaseEnv switches the dev server (TestDevServer) into showcase mode.
const showcaseEnv = "OOB_DEV_SHOWCASE"

func showcaseOn() bool { return os.Getenv(showcaseEnv) == "1" }

// showcaseFirmwareYAML is firmwareYAML's rule with a note a real config would carry.
const showcaseFirmwareYAML = `firmware:
  minimum:
    - { bmc_kind: idrac8, kind: bios, version: "2.20.0", note: "Memory training fix" }
`

// showcaseTranscript is what the R730XD host has printed when the serial console opens.
const showcaseTranscript = "\r\nDebian GNU/Linux 13 storage-node ttyS0\r\n\r\nstorage-node login: "

// showcaseFrame is the graphical console's screen (testdata/showcase/boot-menu.html,
// rendered once to the PNG next to it).
const showcaseFrame = "testdata/showcase/boot-menu.png"

// powerYAML is the power block of a server: powerYAML's, or in showcase mode the same
// tags and self-host flag with neutral "What goes down" lines.
func (s *stack) powerYAML(id string) string {
	if !s.showcase {
		return powerYAML(id)
	}
	if id == "r240" {
		return "    tags: [critical]\n    power: { impact: [\"Lab CI runners on this host stop until it boots\"] }\n"
	}
	return "    power: { self_host: true, impact: [\"Everything stored on this node is offline until it boots\"] }\n"
}

// showcaseLogAge is how old the newest log entry is in showcase mode.
const showcaseLogAge = 4 * time.Minute

// showcaseLogShift moves the captured logs (years old) so their newest entry is a few
// minutes old, keeping the spacing between entries (redfishmock.WithLogTimeShift).
func showcaseLogShift(t *testing.T) time.Duration {
	t.Helper()
	latest, err := redfishmock.LatestCreated(fixtureDirs(t)...)
	if err != nil {
		t.Fatal(err)
	}
	return time.Now().Add(-showcaseLogAge).Sub(latest).Truncate(time.Second)
}

// fixtureDirs are the captured fixtures of every e2e server.
func fixtureDirs(t *testing.T) []string {
	t.Helper()
	var dirs []string
	for _, srv := range e2eServers() {
		dirs = append(dirs, redfishmock.FixtureDir(t, srv.fixture))
	}
	return dirs
}

// showcaseMockOptions are the mock options showcase mode adds to every BMC.
func showcaseMockOptions(t *testing.T, showcase bool) []redfishmock.Option {
	t.Helper()
	if !showcase {
		return nil
	}
	return []redfishmock.Option{redfishmock.WithLogTimeShift(showcaseLogShift(t)),
		redfishmock.WithLogTextReplace(fixtureClientAddr, showcaseClientAddr)}
}

// The captured logs name the R730XD BMC's own documentation address as the client of
// every login; showcase mode names a neutral admin workstation instead.
const (
	fixtureClientAddr  = "192.0.2.10"
	showcaseClientAddr = "192.0.2.99"
)

// vncOptions is the R730XD's fake VNC server: a small solid frame for the tests, the
// boot menu in showcase mode.
func vncOptions(t *testing.T, showcase bool) rfbtest.Options {
	t.Helper()
	if !showcase {
		return rfbtest.Options{TLS: true, Width: 320, Height: 200}
	}
	return rfbtest.Options{TLS: true, Frame: loadPNG(t, filepath.Join(repoRoot(t), showcaseFrame)), Name: "storage-node"}
}

func loadPNG(t *testing.T, path string) image.Image {
	t.Helper()
	f, err := os.Open(path) //nolint:gosec // G304: a fixed path in the repository
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	img, err := png.Decode(f)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return img
}

// repoRoot is the directory holding go.mod, above the working directory (the harness
// runs from cmd/oob-manager in go test and from tests/e2e under Playwright).
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the working directory")
		}
		dir = parent
	}
}

// TestShowcaseHarness checks the showcase fixtures without starting a stack: no test
// wording, the same firmware rule as the e2e stack, a frame the size of a real console.
func TestShowcaseHarness(t *testing.T) {
	s := &stack{showcase: true}
	text := strings.ToLower(showcaseFirmwareYAML + showcaseTranscript + s.powerYAML("r730xd") + s.powerYAML("r240"))
	for _, bad := range []string{"e2e", "mock", "test", "deliberately", "gateway"} {
		if strings.Contains(text, bad) {
			t.Errorf("showcase fixture text contains %q", bad)
		}
	}
	if !strings.Contains(firmwareYAML, `version: "2.20.0"`) || !strings.Contains(showcaseFirmwareYAML, `version: "2.20.0"`) {
		t.Error("the showcase firmware rule must flag the same BIOS as the e2e one")
	}
	for _, id := range []string{"r730xd", "r240"} {
		if s.powerYAML(id) == powerYAML(id) || (&stack{}).powerYAML(id) != powerYAML(id) {
			t.Errorf("%s: power block not switched by showcase mode", id)
		}
	}
	o := vncOptions(t, true)
	if b := o.Frame.Bounds(); b.Dx() != 1024 || b.Dy() != 768 {
		t.Errorf("frame %v, want 1024x768", b)
	}
	if o := vncOptions(t, false); o.Frame != nil || o.Width != 320 {
		t.Errorf("test VNC options changed: %+v", o)
	}
	for _, srv := range e2eServers() {
		if srv.address == showcaseClientAddr {
			t.Errorf("the showcase client address %s is a BMC's", showcaseClientAddr)
		}
	}
	if showcaseClientAddr == extraAddress || e2eServers()[0].address != fixtureClientAddr {
		t.Error("the client address rewrite no longer matches the fixtures")
	}
	latest, err := redfishmock.LatestCreated(fixtureDirs(t)...)
	if err != nil {
		t.Fatal(err)
	}
	if age := time.Since(latest.Add(showcaseLogShift(t))); age < 2*time.Minute || age > 10*time.Minute {
		t.Errorf("the newest log entry would be %v old, want a few minutes", age)
	}
}

// TestShowcaseVersion checks that `make showcase` stamped the release version into the
// harness binary (the footer of every screenshot shows it). It runs only when the
// target asks for it with OOB_SHOWCASE_WANT_VERSION.
func TestShowcaseVersion(t *testing.T) {
	want := os.Getenv("OOB_SHOWCASE_WANT_VERSION")
	if want == "" {
		t.Skip("run by make showcase")
	}
	if version != want {
		t.Fatalf("version = %q, want %q: build the harness with -ldflags \"-X <pkg>.version=%s\"", version, want, want)
	}
}
