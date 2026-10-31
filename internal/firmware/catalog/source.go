package catalog

import (
	"context"
	"errors"
	"io"
	"strings"
	"time"
)

// Failure classes of a catalog check (catalog_checks.result). The class is all that is
// recorded or shown: never a response body or a parser's echo of the input.
var (
	ErrDownload     = errors.New("catalog: download failed")
	ErrSize         = errors.New("catalog: size limit exceeded")
	ErrSignature    = errors.New("catalog: signature check failed")
	ErrUntrustedKey = errors.New("catalog: signed by a key that is not trusted")
	ErrParse        = errors.New("catalog: not a valid catalog")
)

// Class maps an error to its catalog_checks.result value ("" for nil).
func Class(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrUntrustedKey):
		return "untrusted_key"
	case errors.Is(err, ErrSignature):
		return "signature"
	case errors.Is(err, ErrSize):
		return "size"
	case errors.Is(err, ErrParse):
		return "parse"
	default:
		return "download"
	}
}

// Limits bound the parse of an untrusted catalog (plan 08 §6.3).
type Limits struct {
	MaxDecompressed int64         // bytes after gunzip
	MaxDepth        int           // element nesting
	MaxAttr         int           // bytes per attribute value
	MaxText         int           // bytes per text node
	MaxComponents   int           // SoftwareComponent elements in the whole catalog
	MaxDevices      int           // devices per component
	MaxModels       int           // models per component
	MaxPCI          int           // PCI identities per device
	MaxEntries      int           // entries kept for the wanted systems
	ParseTime       time.Duration // wall time for the whole parse
}

// DefaultLimits are generous for the real Dell catalog (22 MiB, 1,005 components,
// depth 8) and small enough to refuse a bomb.
func DefaultLimits() Limits {
	return Limits{
		MaxDecompressed: 128 << 20, MaxDepth: 16, MaxAttr: 4 << 10, MaxText: 64 << 10,
		MaxComponents: 20000, MaxDevices: 256, MaxModels: 512, MaxPCI: 256, MaxEntries: 100000,
		ParseTime: 60 * time.Second,
	}
}

// Want is the set of systems whose entries a parse keeps: vendor system IDs and
// normalized model names (NormalizeModel) for BMCs that report only a model.
type Want struct {
	SystemIDs map[string]bool
	Models    map[string]bool
}

// Wants reports whether a system (ID and display model) is wanted.
func (w Want) Wants(systemID, model string) bool {
	return w.SystemIDs[systemID] || (model != "" && w.Models[NormalizeModel(model)])
}

// NormalizeModel folds a model name for comparison: upper case, single spaces
// ("PowerEdge  R7xx" and "POWEREDGE R7XX" are one model).
func NormalizeModel(s string) string { return strings.Join(strings.Fields(strings.ToUpper(s)), " ") }

// ResolveModel finds the one system ID whose catalog model name equals model; two or
// more (an ambiguous name) or none is no match.
func (s Snapshot) ResolveModel(model string) (string, bool) {
	want := NormalizeModel(model)
	found := ""
	for id, names := range s.Models {
		for _, n := range names {
			if NormalizeModel(n) != want {
				continue
			}
			if found != "" && found != id {
				return "", false
			}
			found = id
		}
	}
	return found, found != ""
}

// Signer is who signed a verified catalog.
type Signer struct {
	Fingerprint string // upper-case hex; "" = unsigned (accepted by configuration)
	KeyID       string // the 16-hex-digit key ID
	Legacy      bool   // a pinned legacy key (SHA-1 accepted)
}

// UpdateSource is one vendor's catalog: where it is published, how its signature is
// checked and how it is parsed. Fetching is source-independent (internal/fwcatalog).
type UpdateSource interface {
	Name() string // "dell" (a closed set)
	DefaultURL() string
	// Verify checks sig, a detached signature over the artifact's bytes, against the
	// source's trusted keys. It must be called, and succeed, before Parse.
	Verify(artifact io.Reader, sig []byte) (Signer, error)
	// Parse streams the verified artifact and keeps the entries of the wanted systems.
	Parse(ctx context.Context, artifact io.Reader, want Want, lim Limits) (Snapshot, error)
}
