package repopolicy

import (
	"regexp"
	"strings"
	"testing"
)

// TestImageCarriesLicenseAndNotice: the published image is a binary distribution, so it
// carries LICENSE and NOTICE (Apache-2.0 section 4) and says its licence in the OCI label,
// and the build context lets both files in.
func TestImageCarriesLicenseAndNotice(t *testing.T) {
	if !strings.Contains(readRepoFile(t, "LICENSE"), "Apache License\n                           Version 2.0, January 2004") {
		t.Error("LICENSE is not the Apache License 2.0 text")
	}
	df := readRepoFile(t, "Dockerfile")
	if !regexp.MustCompile(`org\.opencontainers\.image\.licenses="Apache-2\.0"`).MatchString(df) {
		t.Error(`Dockerfile: want LABEL org.opencontainers.image.licenses="Apache-2.0"`)
	}
	if !regexp.MustCompile(`(?m)^COPY --from=build /src/LICENSE /src/NOTICE /usr/share/doc/oob-manager/$`).MatchString(df) {
		t.Error("Dockerfile: the runtime image must COPY LICENSE and NOTICE to /usr/share/doc/oob-manager/")
	}
	if !regexp.MustCompile(`(?m)^COPY LICENSE NOTICE \./$`).MatchString(df) {
		t.Error("Dockerfile: the build stage must COPY LICENSE NOTICE ./")
	}
	ignore := readRepoFile(t, ".dockerignore")
	for _, f := range []string{"!LICENSE", "!NOTICE"} {
		if !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(f) + `$`).MatchString(ignore) {
			t.Errorf(".dockerignore must let %s into the build context", strings.TrimPrefix(f, "!"))
		}
	}
}
