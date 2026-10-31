package repopolicy

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// firmwareUpdateWords are the Redfish identifiers of a firmware update (UpdateService
// actions and push URIs). CLAUDE.md rule 11: the firmware view reads inventory and never
// updates firmware, so no Go source outside this test may name them.
func firmwareUpdateWords() []string {
	return []string{"SimpleUpdate", "HttpPushUri", "MultipartHttpPushUri", "StartUpdate", "UpdateService/Actions",
		"UpdateService.Actions", "InstallFromRepository", "DellUpdateService"}
}

func TestNoFirmwareUpdatePath(t *testing.T) {
	self := filepath.Join("internal", "repopolicy", "firmware_readonly_test.go")
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			if rel == self {
				return nil
			}
			b, err := os.ReadFile(path) // #nosec G304 G122 -- a test walking the repository's own sources
			if err != nil {
				return err
			}
			for _, w := range firmwareUpdateWords() {
				if strings.Contains(string(b), w) {
					t.Errorf("%s names %q: firmware updates are out of scope (CLAUDE.md rule 11)", rel, w)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
