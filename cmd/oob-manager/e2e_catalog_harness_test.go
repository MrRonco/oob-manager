//go:build e2e

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"oob-manager/internal/firmware/catalog/catalogtest"
)

// catalogSrv serves a signed synthetic vendor catalog over TLS (plan 08 §17) and counts
// the requests, so a test can assert that nothing is fetched while the check is off.
type catalogSrv struct {
	srv  *httptest.Server
	mu   sync.Mutex
	hits []string
}

func newCatalogSrv(t *testing.T, dir string) *catalogSrv {
	t.Helper()
	key := catalogtest.RSAKey(t)
	data := catalogtest.Catalog()
	sig := key.Sign(t, data)
	write(t, filepath.Join(dir, "catalog-keys.asc"), key.PublicArmored(t))
	write(t, filepath.Join(dir, "seed.xml.gz"), data)
	write(t, filepath.Join(dir, "seed.xml.gz.sign"), sig)
	c := &catalogSrv{}
	c.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.mu.Lock()
		c.hits = append(c.hits, r.URL.Path)
		c.mu.Unlock()
		switch r.URL.Path {
		case "/catalog/Catalog.xml.gz":
			w.Header().Set("ETag", `"e2e-1"`)
			if r.Header.Get("If-None-Match") == `"e2e-1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write(data)
		case "/catalog/Catalog.xml.gz.sign":
			_, _ = w.Write(sig)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(c.srv.Close)
	return c
}

func (c *catalogSrv) requests() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.hits...)
}

// yaml is the file-only catalog configuration: the local server (a private address,
// so allowed_networks), the test signing key; the online check is left to Settings.
func (c *catalogSrv) yaml(dir string) string {
	return "  catalog:\n    url: " + c.srv.URL + "/catalog/Catalog.xml.gz\n    extra_keys_file: " +
		filepath.Join(dir, "catalog-keys.asc") + "\n    allowed_networks: [127.0.0.0/8]\n"
}

// tls trusts the server's certificate (the env hook; production uses system roots).
func (c *catalogSrv) tls() *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(c.srv.Certificate())
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

// withCatalog merges the catalog block into the stack's extra YAML (one firmware key).
func withCatalog(extra, block string) string {
	if strings.Contains(extra, "firmware:\n") {
		return strings.Replace(extra, "firmware:\n", "firmware:\n"+block, 1)
	}
	return extra + "firmware:\n" + block
}

// importSeedCatalog runs `catalog import` before serve, as an air-gapped install would:
// the pages show the Latest column from the start (the fleet is not scanned yet, so the
// first scans re-parse the cached file locally).
func (s *stack) importSeedCatalog(t *testing.T) {
	t.Helper()
	var out, errOut syncBuffer
	code := run([]string{"oob-manager", "catalog", "import", "-config", s.configPath, filepath.Join(s.dir, "seed.xml.gz"),
		filepath.Join(s.dir, "seed.xml.gz.sign")}, cliEnv(context.Background(), strings.NewReader(""), &out, &errOut))
	if code != 0 {
		t.Fatalf("catalog import: %d %s", code, errOut.String())
	}
}

// catalogCadence runs the scheduled check in seconds in the e2e stack.
const catalogTick = 200 * time.Millisecond
