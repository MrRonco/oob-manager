package repopolicy

import (
	"encoding/json"
	"regexp"
	"slices"
	"testing"
)

// The visual baseline (tests/e2e/visual.spec.ts) runs in the image the Makefile pins as
// PW_IMAGE. That image bundles the browsers of one Playwright release, so its tag must
// name the same version as the @playwright/test the suite installs.
var pwImageLine = regexp.MustCompile(`(?m)^PW_IMAGE[ \t]*\??=[ \t]*mcr\.microsoft\.com/playwright:v([0-9]+\.[0-9]+\.[0-9]+)-noble@sha256:[a-f0-9]{64}[ \t]*$`)

const playwrightPkg = "@playwright/test"

func playwrightVersions(t *testing.T) (image, lock, manifest string) {
	t.Helper()
	m := pwImageLine.FindStringSubmatch(readRepoFile(t, "Makefile"))
	if m == nil {
		t.Fatal("Makefile: no PW_IMAGE ?= mcr.microsoft.com/playwright:v<x.y.z>-noble@sha256:<digest> line")
	}
	var lk struct {
		Packages map[string]struct {
			Version string `json:"version"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, "tests/e2e/package-lock.json")), &lk); err != nil {
		t.Fatal(err)
	}
	var pkg struct {
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal([]byte(readRepoFile(t, "tests/e2e/package.json")), &pkg); err != nil {
		t.Fatal(err)
	}
	return m[1], lk.Packages["node_modules/"+playwrightPkg].Version, pkg.DevDependencies[playwrightPkg]
}

// TestPlaywrightImageMatchesTestRunner: the PW_IMAGE tag, the locked @playwright/test
// and the exact pin in package.json are one version.
func TestPlaywrightImageMatchesTestRunner(t *testing.T) {
	image, lock, manifest := playwrightVersions(t)
	if image != lock || lock != manifest {
		t.Errorf("Playwright versions differ: PW_IMAGE v%s, package-lock %q, package.json %q", image, lock, manifest)
	}
}

// TestRenovateTracksPlaywrightImage: a Renovate regex manager extracts the PW_IMAGE tag
// and digest, and one packageRule groups it with @playwright/test, so a bump edits both.
func TestRenovateTracksPlaywrightImage(t *testing.T) {
	cfg, _ := loadRenovate(t)
	matchers, _ := customRegexes(t, cfg)
	image, _, _ := playwrightVersions(t)
	makefile := readRepoFile(t, "Makefile")
	tracked := slices.ContainsFunc(matchers, func(re *regexp.Regexp) bool {
		m := re.FindStringSubmatch(makefile)
		cv, dg := re.SubexpIndex("currentValue"), re.SubexpIndex("currentDigest")
		return m != nil && cv >= 0 && dg >= 0 && m[cv] == "v"+image+"-noble" && m[dg] != ""
	})
	if !tracked {
		t.Error("renovate.json: no regex custom manager extracts the PW_IMAGE tag and digest from the Makefile")
	}
	grouped := slices.ContainsFunc(cfg.PackageRules, func(r packageRule) bool {
		return r.GroupName != "" && slices.Contains(r.MatchPackageNames, playwrightPkg) &&
			slices.Contains(r.MatchPackageNames, "mcr.microsoft.com/playwright")
	})
	if !grouped {
		t.Error("renovate.json: no packageRule groups @playwright/test with mcr.microsoft.com/playwright")
	}
}

func TestPWImageLineParser(t *testing.T) {
	good := "X := 1\nPW_IMAGE    ?= mcr.microsoft.com/playwright:v1.63.0-noble@sha256:" + sha64 + "\n"
	if m := pwImageLine.FindStringSubmatch(good); m == nil || m[1] != "1.63.0" {
		t.Errorf("parsed %v", m)
	}
	for _, bad := range []string{
		"PW_IMAGE ?= mcr.microsoft.com/playwright:v1.63.0-noble\n",                        // no digest
		"PW_IMAGE ?= mcr.microsoft.com/playwright:latest@sha256:" + sha64 + "\n",          // no version
		"# PW_IMAGE ?= mcr.microsoft.com/playwright:v1.63.0-noble@sha256:" + sha64 + "\n", // comment
	} {
		if pwImageLine.MatchString(bad) {
			t.Errorf("accepted %q", bad)
		}
	}
}

const sha64 = "eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27"
