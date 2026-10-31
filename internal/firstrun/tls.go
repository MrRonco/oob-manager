package firstrun

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"time"

	"oob-manager/internal/certgen"
)

// Names of the generated UI certificate inside the data directory.
const (
	tlsDir   = "tls"
	certName = "tls.crt"
	keyName  = "tls.key"
)

// Cert is the data-volume UI certificate.
type Cert struct {
	CertFile, KeyFile string
	// SHA256 is the certificate's fingerprint (hex), shown for the first visit.
	SHA256    string
	Generated bool
	// NotAfter is the end of the certificate's validity.
	NotAfter time.Time
}

// renewWithin is how close to its end a generated certificate is reported at startup.
const renewWithin = 30 * 24 * time.Hour

// ExpiresSoon reports whether the certificate ends within renewWithin of now (or has
// ended). Nothing renews it automatically: a new one means a new fingerprint to compare.
func (c Cert) ExpiresSoon(now time.Time) bool { return !now.Add(renewWithin).Before(c.NotAfter) }

// EnsureCert returns dataDir's UI certificate, generating a self-signed one for hosts
// when there is none. Half a pair is an error, never completed.
func EnsureCert(dataDir string, hosts []string) (Cert, error) {
	dir := filepath.Join(dataDir, tlsDir)
	c := Cert{}
	c.CertFile, c.KeyFile = CertPathsIn(dataDir)
	all, none, missing, err := setState(c.CertFile, c.KeyFile)
	switch {
	case err != nil:
		return Cert{}, err
	case !all && !none:
		return Cert{}, fmt.Errorf("firstrun: incomplete certificate in %s: %s is missing; remove the directory "+
			"to generate a new pair", dir, filepath.Base(missing))
	case none:
		if err = generateCert(dataDir, hosts); err != nil {
			return Cert{}, err
		}
		c.Generated = true
	}
	pair, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return Cert{}, fmt.Errorf("firstrun: certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return Cert{}, fmt.Errorf("firstrun: certificate: %w", err)
	}
	sum := sha256.Sum256(leaf.Raw)
	c.SHA256 = hex.EncodeToString(sum[:])
	c.NotAfter = leaf.NotAfter
	return c, nil
}

// generateCert writes a self-signed pair for hosts into dataDir/tls (atomic set).
func generateCert(dataDir string, hosts []string) error {
	if err := cleanTemp(dataDir, tlsDir); err != nil {
		return err
	}
	pair, err := certgen.Generate(certgen.Request{Hosts: hosts})
	if err != nil {
		return fmt.Errorf("firstrun: certificate: %w", err)
	}
	return writeSet(dataDir, tlsDir, 0o700, []file{{certName, pair.CertPEM, 0o444}, {keyName, pair.KeyPEM, 0o400}})
}

// CertPathsIn returns the UI certificate and key paths inside dataDir.
func CertPathsIn(dataDir string) (certFile, keyFile string) {
	dir := filepath.Join(dataDir, tlsDir)
	return filepath.Join(dir, certName), filepath.Join(dir, keyName)
}
