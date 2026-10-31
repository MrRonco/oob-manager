package repopolicy

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	// 90004	IGNORE	(reason; expires 2027-04-30)
	zapRule = regexp.MustCompile(`^(\d{4,6})\t(IGNORE|WARN|FAIL)\t\((.+); expires (\d{4}-\d{2}-\d{2})\)$`)
	// ZAP_IMAGE ?= zaproxy/zap-stable:20261008@sha256:<64 hex>
	zapImage = regexp.MustCompile(`(?m)^ZAP_IMAGE[ \t]*\?=[ \t]*zaproxy/zap-stable:\d{8}@sha256:[a-f0-9]{64}$`)
)

// TestZAPAllowlistEntriesJustified: every allowlisted ZAP rule carries a reason and an
// expiry date no more than a year ahead, and an expired entry fails, so each exception
// is re-justified or removed (plan 06 §3.2).
func TestZAPAllowlistEntriesJustified(t *testing.T) {
	today := time.Now().UTC().Truncate(24 * time.Hour)
	for _, file := range []string{"tests/zap/rules.tsv", "tests/zap/api-rules.tsv"} {
		seen := map[string]bool{}
		for i, line := range strings.Split(readRepoFile(t, file), "\n") {
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			m := zapRule.FindStringSubmatch(line)
			if m == nil {
				t.Errorf("%s:%d: want <id> TAB <IGNORE|WARN|FAIL> TAB (<reason>; expires YYYY-MM-DD): %q", file, i+1, line)
				continue
			}
			if seen[m[1]] {
				t.Errorf("%s:%d: rule %s listed twice", file, i+1, m[1])
			}
			seen[m[1]] = true
			if len(strings.TrimSpace(m[3])) < 20 {
				t.Errorf("%s:%d: rule %s needs a real reason", file, i+1, m[1])
			}
			exp, err := time.Parse(time.DateOnly, m[4])
			switch {
			case err != nil:
				t.Errorf("%s:%d: bad date %q", file, i+1, m[4])
			case exp.Before(today):
				t.Errorf("%s:%d: rule %s expired on %s: re-justify or remove it", file, i+1, m[1], m[4])
			case exp.After(today.AddDate(1, 0, 0)):
				t.Errorf("%s:%d: rule %s expires more than a year ahead (%s)", file, i+1, m[1], m[4])
			}
		}
	}
}

// TestZAPImagePinnedByDigest: the scanner image is a dated tag plus its digest, the
// form the Renovate custom manager (renovate.json) can update.
func TestZAPImagePinnedByDigest(t *testing.T) {
	if !zapImage.MatchString(readRepoFile(t, "Makefile")) {
		t.Error("Makefile ZAP_IMAGE must be zaproxy/zap-stable:<YYYYMMDD>@sha256:<digest>")
	}
	if !strings.Contains(readRepoFile(t, "renovate.json"), "ZAP_IMAGE") {
		t.Error("renovate.json has no custom manager for ZAP_IMAGE")
	}
}
