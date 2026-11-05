package ui

import (
	"io/fs"
	"regexp"
	"testing"
)

// TestTemplatesUseUSEnglish is the copy lint of UX-15: user-facing text is US English.
func TestTemplatesUseUSEnglish(t *testing.T) {
	t.Parallel()
	bad := regexp.MustCompile(`(?i)\b(licence|enrolment|colour|organis|behaviour|cancelled)`)
	err := fs.WalkDir(templateFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(templateFS, p)
		if err != nil {
			return err
		}
		if m := bad.Find(b); m != nil {
			t.Errorf("%s uses %q (US English: license, enrollment, color, ...)", p, m)
		}
		return nil
	})
	must(t, err)
}
