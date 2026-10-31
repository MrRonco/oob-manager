package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"filippo.io/age"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/dellredfish"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/bmc/redfishmock"
	"oob-manager/internal/config"
	"oob-manager/internal/secrets"
)

const testPin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// deployment is a complete on-disk install in a temp dir: config, age identity,
// encrypted credentials and app keys, a self-signed TLS pair and one mock BMC.
type deployment struct {
	dir        string
	configPath string
	dbPath     string
	mock       *redfishmock.Server
}

func newDeployment(t *testing.T, gelfAddr string) deployment {
	t.Helper()
	dir := t.TempDir()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "identity"), []byte(id.String()+"\n"))
	write(t, filepath.Join(dir, "creds.age"), seal(t, id.Recipient(),
		"r240-ro: {username: "+redfishmock.User+", password: "+redfishmock.Password+"}\n"))
	keys, err := secrets.GenerateAppKeys()
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "app-keys.age"), seal(t, id.Recipient(), string(keys)))
	writeCert(t, dir)
	d := deployment{dir: dir, configPath: filepath.Join(dir, "config.yaml"), dbPath: filepath.Join(dir, "oob.db"),
		mock: redfishmock.New(t, redfishmock.FixtureDir(t, "idrac9-r240"))}
	write(t, d.configPath, []byte(configYAML(dir, gelfAddr)))
	return d
}

func configYAML(dir, gelfAddr string) string {
	gelf := ""
	if gelfAddr != "" {
		gelf = "audit:\n  gelf: { address: \"" + gelfAddr + "\", allowed_networks: [192.0.2.0/24] }\n"
	}
	return `listen: "127.0.0.1:8443"
tls: { cert_file: ` + dir + `/tls.crt, key_file: ` + dir + `/tls.key }
public_url: https://oob.example.test/
` + gelf + `storage: { db_path: ` + dir + `/oob.db, lease_dir: ` + dir + ` }
secrets:
  credentials_file: ` + dir + `/creds.age
  identity_file: ` + dir + `/identity
  app_keys_file: ` + dir + `/app-keys.age
servers:
  - id: r240
    name: Edge node R240
    bmc: { address: 192.0.2.72, kind: idrac9 }
    tls_pin_sha256: "` + testPin + `"
    credentials: { readonly: r240-ro }
    fan: { mode: none }
    console: { serial: none, graphical: none }
`
}

func seal(t *testing.T, r age.Recipient, plaintext string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeCert(t *testing.T, dir string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "oob.example.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(dir, "tls.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write(t, filepath.Join(dir, "tls.key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}))
}

// mockDrivers points every configured server at the deployment's mock BMC, checking
// that the read-only credential from the age file is what reaches the driver.
func (d deployment) mockDrivers(t *testing.T) driverFactory {
	return func(s config.Server, ro secrets.Credential) (bmc.Driver, error) {
		if ro.Username != redfishmock.User || ro.Password.Reveal() != redfishmock.Password {
			t.Errorf("server %s got the wrong credential", s.ID)
		}
		return dellredfish.New(redfish.Config{Endpoint: d.mock.URL(), Username: ro.Username,
			Password: ro.Password.Reveal(), PinSHA256: d.mock.PinSHA256(), Timeout: 2 * time.Second})
	}
}

// syncBuffer is a goroutine-safe output sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func cliEnv(ctx context.Context, in io.Reader, out, errOut io.Writer) env {
	return env{ctx: ctx, in: bufio.NewReader(in), out: out, errOut: errOut, healthURL: defaultHealthURL,
		noEcho: func() (func(), error) { return func() {}, nil }, stdoutTTY: func() bool { return true },
		listen: net.Listen, newDriver: newBMCDriver}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// cliExitTimeout bounds a wait for a CLI command run in a goroutine. The commands read
// stdin, so a test that leaves the pipe open after an unexpected prompt would otherwise
// block until the package timeout.
const cliExitTimeout = 30 * time.Second

// awaitExit returns the exit code sent on done, or fails the test after cliExitTimeout.
func awaitExit(t *testing.T, done <-chan int) int {
	t.Helper()
	select {
	case rc := <-done:
		return rc
	case <-time.After(cliExitTimeout):
		t.Fatal("CLI command did not exit (blocked on stdin?)")
		return -1
	}
}
