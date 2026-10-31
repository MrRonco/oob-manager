// Package audit records every security-relevant action in a tamper-evident hash chain
// (row_hash = SHA-256(prev_hash ‖ canonical_row), docs/security.md T3) and ships a copy
// off-box to Graylog over GELF/TCP without ever blocking the caller.
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"oob-manager/internal/store"
)

// GenesisHash is the prev_hash of the first record.
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// hashDomain separates this hash from any other SHA-256 use of the same bytes. It keeps
// the pre-rename project name (oob-console) ON PURPOSE: every stored row_hash includes it,
// so changing it would make Verify flag the whole existing chain (TestHashDomainIsPinned).
const hashDomain = "oob-console/audit/v1"

// DefaultVerifyPage is the page size Verify uses when given 0.
const DefaultVerifyPage = 500

// ErrTampered is wrapped by every *TamperError.
var ErrTampered = errors.New("audit: chain tampered")

// TamperError identifies the first record where the chain breaks.
type TamperError struct {
	Seq    int64
	Reason string
}

func (e *TamperError) Error() string {
	return fmt.Sprintf("audit: chain tampered at seq %d: %s", e.Seq, e.Reason)
}

// Unwrap makes errors.Is(err, ErrTampered) work.
func (e *TamperError) Unwrap() error { return ErrTampered }

// Hash computes the row hash of r from PrevHash and every content field. RowHash itself
// is not an input. Fields are length-prefixed so boundary shifts cannot collide.
func Hash(r store.AuditRecord) string {
	h := sha256.New()
	fields := []string{
		hashDomain, r.PrevHash,
		strconv.FormatInt(r.Seq, 10), strconv.FormatInt(r.TS.UnixMilli(), 10),
		r.CorrelationID, r.Principal, r.AuthMethod, r.Role, r.SrcIP, r.ServerID,
		r.Action, r.ParamsJSON, r.Result, r.BMCStatus, r.ErrorClass,
	}
	var lenBuf [8]byte
	for _, f := range fields {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(f)))
		h.Write(lenBuf[:])
		h.Write([]byte(f))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyResult summarises an intact chain. Head can be compared with the last row
// hash shipped to Graylog to detect truncation of the newest rows.
type VerifyResult struct {
	Count int64
	Head  string
}

// Verify walks the whole chain in pages and returns a *TamperError at the first
// broken link: sequence gap, prev_hash mismatch or row_hash mismatch.
func Verify(ctx context.Context, repo store.AuditRepository, pageSize int) (VerifyResult, error) {
	if pageSize <= 0 {
		pageSize = DefaultVerifyPage
	}
	pageSize = min(pageSize, store.MaxAuditPage)
	state := VerifyResult{Head: GenesisHash}
	for {
		page, err := repo.List(ctx, state.Count, pageSize)
		if err != nil {
			return VerifyResult{}, fmt.Errorf("audit: verify: %w", err)
		}
		for _, r := range page {
			next, err := verifyLink(state, r)
			if err != nil {
				return VerifyResult{}, err
			}
			state = next
		}
		if len(page) < pageSize {
			return state, nil
		}
	}
}

// verifyLink checks r against the running state and returns the advanced state.
// state.Count doubles as the last verified seq because seqs must be 1..n.
func verifyLink(state VerifyResult, r store.AuditRecord) (VerifyResult, error) {
	switch {
	case r.Seq != state.Count+1:
		return VerifyResult{}, &TamperError{Seq: r.Seq, Reason: fmt.Sprintf("sequence gap: expected %d", state.Count+1)}
	case r.PrevHash != state.Head:
		return VerifyResult{}, &TamperError{Seq: r.Seq, Reason: "prev_hash does not link to the previous row"}
	case Hash(r) != r.RowHash:
		return VerifyResult{}, &TamperError{Seq: r.Seq, Reason: "row_hash does not match row contents"}
	}
	return VerifyResult{Count: r.Seq, Head: r.RowHash}, nil
}
