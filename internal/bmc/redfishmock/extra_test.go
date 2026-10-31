package redfishmock

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWithExtraFixtures(t *testing.T) {
	extra := t.TempDir()
	doc := `{"Id":"Current-159-2.19.0","Name":"BIOS (SYNTHETIC)"}`
	if err := os.WriteFile(filepath.Join(extra, "UpdateService_FirmwareInventory_Current-159-2.19.0.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	s := New(t, FixtureDir(t, "idrac8-r730xd"), WithExtraFixtures(extra))
	code, body := get(t, s, http.MethodGet, "/redfish/v1/UpdateService/FirmwareInventory/Current-159-2.19.0", true)
	if code != http.StatusOK || !strings.Contains(string(body), "SYNTHETIC") {
		t.Fatalf("extra fixture: %d %s", code, body)
	}
	// The main fixtures are still served, and a missing file is still a 404.
	if code, _ := get(t, s, http.MethodGet, "/redfish/v1/UpdateService/FirmwareInventory/Current-101434-2.25", true); code != http.StatusOK {
		t.Fatalf("main fixture: %d", code)
	}
	if code, _ := get(t, s, http.MethodGet, "/redfish/v1/UpdateService/FirmwareInventory/Installed-1-1", true); code != http.StatusNotFound {
		t.Fatalf("absent: %d", code)
	}
}

func TestSyntheticFirmwareFixturesAreMarked(t *testing.T) {
	for _, bmc := range []string{"idrac8-r730xd", "idrac9-r240"} {
		dir := FixtureDir(t, filepath.Join("synthetic-firmware", bmc))
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) == 0 {
			t.Fatalf("%s: %v (%d files)", dir, err, len(entries))
		}
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- a test reading the fixture tree
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), "SYNTHETIC") {
				t.Errorf("%s/%s is not marked SYNTHETIC", bmc, e.Name())
			}
			if _, err := os.Stat(filepath.Join(FixtureDir(t, bmc), e.Name())); err == nil {
				t.Errorf("%s/%s shadows a captured fixture", bmc, e.Name())
			}
		}
	}
}
