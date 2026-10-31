package bmc

import (
	"context"
	"errors"
)

// Sentinel errors. Drivers wrap these with %w so callers can use errors.Is.
var (
	ErrTimeout          = errors.New("bmc: timeout")
	ErrPinMismatch      = errors.New("bmc: TLS certificate does not match the configured SPKI pin")
	ErrAuth             = errors.New("bmc: authentication or authorisation failed")
	ErrBMC              = errors.New("bmc: unexpected HTTP status from BMC")
	ErrNotFound         = errors.New("bmc: resource not found")
	ErrUnsupported      = errors.New("bmc: not supported by this BMC")
	ErrUnreachable      = errors.New("bmc: unreachable")
	ErrResponseTooLarge = errors.New("bmc: response exceeds size cap")
	ErrDecode           = errors.New("bmc: response could not be decoded")
	ErrMethodNotAllowed = errors.New("bmc: request method not allowed in this phase")
	ErrInvalidConfig    = errors.New("bmc: invalid driver configuration")
	// ErrPrivilege: the BMC refused an action (HTTP 403) for an account that did log in:
	// the account lacks the privilege. Drivers wrap it together with ErrAuth, so it is
	// classified as auth.
	ErrPrivilege = errors.New("bmc: the account lacks the privilege for this action")
)

// ErrorClass is a coarse, UI-safe error category.
type ErrorClass string

// Error classes.
const (
	ClassNone        ErrorClass = ""
	ClassTimeout     ErrorClass = "timeout"
	ClassTLS         ErrorClass = "tls"
	ClassAuth        ErrorClass = "auth"
	ClassBMC         ErrorClass = "bmc"
	ClassNotFound    ErrorClass = "not_found"
	ClassUnsupported ErrorClass = "unsupported"
	ClassUnreachable ErrorClass = "unreachable"
	ClassProtocol    ErrorClass = "protocol"
	ClassConfig      ErrorClass = "config"
	ClassOther       ErrorClass = "other"
)

type classRow struct {
	err   error
	class ErrorClass
}

// classTable is built per call so there is no package-level mutable state.
func classTable() []classRow {
	return []classRow{
		{ErrTimeout, ClassTimeout},
		{context.DeadlineExceeded, ClassTimeout},
		{ErrPinMismatch, ClassTLS},
		{ErrAuth, ClassAuth},
		{ErrBMC, ClassBMC},
		{ErrNotFound, ClassNotFound},
		{ErrUnsupported, ClassUnsupported},
		{ErrUnreachable, ClassUnreachable},
		{ErrResponseTooLarge, ClassProtocol},
		{ErrDecode, ClassProtocol},
		{ErrMethodNotAllowed, ClassProtocol},
		{ErrInvalidConfig, ClassConfig},
	}
}

// Classify maps an error to its class for display ("BMC unreachable since …: timeout").
func Classify(err error) ErrorClass {
	if err == nil {
		return ClassNone
	}
	for _, row := range classTable() {
		if errors.Is(err, row.err) {
			return row.class
		}
	}
	return ClassOther
}
