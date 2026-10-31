// Package dell is the Dell enterprise catalog source (docs/plans/08-update-checker.md
// §4–7): its signature check against the pinned Dell key, a bounded streaming parser for
// the UTF-16 XML, and the mapping from a BMC's Dell OEM system ID to the catalog's.
package dell

import (
	"context"
	"fmt"
	"io"

	"oob-manager/internal/firmware/catalog"
)

// SourceName is the source's catalog_imports.source value.
const SourceName = "dell"

// DefaultURL is Dell's enterprise catalog; its signature is the same URL plus ".sign".
const DefaultURL = "https://downloads.dell.com/catalog/Catalog.xml.gz"

// Source is the Dell catalog source with its trusted keys.
type Source struct{ Keys Keys }

var _ catalog.UpdateSource = Source{}

// NewSource loads Dell's key and the armored extra keys (nil: none).
func NewSource(extraKeys []byte) (Source, error) {
	k, err := LoadKeys(extraKeys)
	if err != nil {
		return Source{}, err
	}
	return Source{Keys: k}, nil
}

// Name is "dell".
func (Source) Name() string { return SourceName }

// DefaultURL is Dell's enterprise catalog URL.
func (Source) DefaultURL() string { return DefaultURL }

// Verify checks the detached signature against the trusted keys.
func (s Source) Verify(artifact io.Reader, sig []byte) (catalog.Signer, error) {
	return s.Keys.Verify(artifact, sig)
}

// Parse reads the catalog (Parse).
func (Source) Parse(ctx context.Context, artifact io.Reader, want catalog.Want, lim catalog.Limits) (catalog.Snapshot, error) {
	return Parse(ctx, artifact, want, lim)
}

// SystemID is a Dell OEM SystemID (Redfish Oem.Dell.DellSystem.SystemID, an integer such
// as 2191) as the catalog writes it: four upper-case hex digits ("088F"). Out of range:
// "".
func SystemID(n int) string {
	if n <= 0 || n > 0xFFFF {
		return ""
	}
	return fmt.Sprintf("%04X", n)
}
