package config

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateCatalog(t *testing.T) {
	ok := CatalogConfig{URL: "https://mirror.example.net/catalog/Catalog.xml.gz", ExtraKeysFile: "/etc/keys.asc",
		AllowedNetworks: []string{"192.0.2.0/24"}, AllowUnsigned: true, Systems: map[string]string{"r1": "088F"}}
	if p := validateCatalog(nil, ok); len(p) != 0 {
		t.Fatalf("valid config refused: %v", p)
	}
	if p := validateCatalog(nil, CatalogConfig{}); len(p) != 0 {
		t.Fatalf("empty config refused: %v", p)
	}
	bad := map[string]CatalogConfig{
		"http":         {URL: "http://downloads.example.net/c.xml.gz"},
		"no host":      {URL: "https:///c.xml.gz"},
		"user info":    {URL: "https://u:p@downloads.example.net/c.xml.gz"}, //nolint:gosec // G101: a refused test URL
		"query":        {URL: "https://downloads.example.net/c.xml.gz?x=1"},
		"not a url":    {URL: "https://bad host/%zz"},
		"long url":     {URL: "https://downloads.example.net/" + strings.Repeat("a", 600)},
		"networks":     {AllowedNetworks: []string{"nonsense"}},
		"system id":    {Systems: map[string]string{"r1": "88f"}},
		"server id":    {Systems: map[string]string{"Bad ID": "088F"}},
		"keys path":    {ExtraKeysFile: strings.Repeat("a", 2000)},
		"many systems": {Systems: manySystems(MaxCatalogSystems + 1)},
	}
	for name, c := range bad {
		if p := validateCatalog(nil, c); len(p) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	nets := make([]string, maxCatalogNetworks+1)
	for i := range nets {
		nets[i] = "192.0.2.1"
	}
	if p := validateCatalog(nil, CatalogConfig{AllowedNetworks: nets}); len(p) == 0 {
		t.Error("too many networks accepted")
	}
}

func manySystems(n int) map[string]string {
	m := map[string]string{}
	for i := range n {
		m[fmt.Sprintf("s%d", i)] = "088F"
	}
	return m
}

func TestCatalogRuntimeKeys(t *testing.T) {
	cfg := mustParse(t, validYAML())
	g := cfg.General()
	if g.CatalogEnabled || g.CatalogCheckDays != 7 || g.CatalogNotify != "urgent" || cfg.FileSets(KeyCatalogEnabled) {
		t.Fatalf("defaults %+v", g)
	}
	src := validYAML() + "firmware:\n  catalog:\n    enabled: true\n    check_every: 14\n    notify: all\n"
	cfg = mustParse(t, src)
	if g := cfg.General(); !g.CatalogEnabled || g.CatalogCheckDays != 14 || g.CatalogNotify != "all" ||
		!cfg.FileSets(KeyCatalogEnabled) || !cfg.FileSets(KeyCatalogNotify) {
		t.Fatalf("from the file %+v", g)
	}
	back := cfg.WithGeneral(General{CatalogEnabled: false, CatalogCheckDays: 3, CatalogNotify: "off"})
	if *back.Firmware.Catalog.Enabled || back.Firmware.Catalog.CheckEvery != 3 || back.Firmware.Catalog.Notify != "off" ||
		cfg.Firmware.Catalog.Notify != "all" {
		t.Fatalf("WithGeneral %+v (original %+v)", back.Firmware.Catalog, cfg.Firmware.Catalog)
	}
	for _, bad := range []string{"check_every: 31", "notify: loud"} {
		if _, err := Parse([]byte(validYAML() + "firmware:\n  catalog:\n    " + bad + "\n")); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
