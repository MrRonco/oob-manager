package secprobe

import (
	"context"
	"errors"
	"io"
	"net"
	"syscall"
	"testing"

	"oob-manager/internal/bmc"
)

// TestClassify pins the error classes: every way of not reaching the port is
// unreachable, a timeout is a timeout, the pin and protocol errors are their own.
func TestClassify(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bmc.ErrorClass
	}{
		"nil":            {nil, bmc.ClassNone},
		"refused":        {&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, bmc.ClassUnreachable},
		"host unreach":   {syscall.EHOSTUNREACH, bmc.ClassUnreachable},
		"net unreach":    {syscall.ENETUNREACH, bmc.ClassUnreachable},
		"dial other":     {&net.OpError{Op: "dial", Err: errors.New("no such device")}, bmc.ClassUnreachable},
		"deadline":       {context.DeadlineExceeded, bmc.ClassTimeout},
		"pin":            {bmc.ErrPinMismatch, bmc.ClassTLS},
		"eof":            {io.EOF, bmc.ClassProtocol},
		"unexpected eof": {io.ErrUnexpectedEOF, bmc.ClassProtocol},
		"not protocol":   {errNotProtocol, bmc.ClassProtocol},
		"read reset":     {&net.OpError{Op: "read", Err: syscall.ECONNRESET}, bmc.ClassProtocol},
	}
	for name, c := range cases {
		if got := classify(c.err); got != c.want {
			t.Errorf("%s: classify = %q, want %q", name, got, c.want)
		}
	}
}
