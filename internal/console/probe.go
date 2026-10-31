package console

import (
	"context"
	"errors"
	"io"
	"syscall"
	"time"

	"oob-manager/internal/console/rfb"
)

// ProbeState is the outcome of an RFB banner read.
type ProbeState string

// Probe states.
const (
	ProbeUnknown   ProbeState = ""          // not probed yet
	ProbeOK        ProbeState = "ok"        // an RFB server answered
	ProbeRefused   ProbeState = "refused"   // nothing listens: VNC server disabled on the BMC
	ProbePin       ProbeState = "pin"       // TLS certificate does not match the pin
	ProbeTLS       ProbeState = "tls"       // TLS handshake failed (VNC SSL setting differs?)
	ProbeNotRFB    ProbeState = "not_rfb"   // something answered that is not RFB
	ProbeUnreached ProbeState = "unreached" // timeout or network error
)

// Probe is a cached banner read.
type Probe struct {
	State     ProbeState
	Version   int // RFB minor version spoken (3, 7, 8) when State is ok
	CheckedAt time.Time
}

const bannerTimeout = 5 * time.Second

// probeBanner connects, reads the 12-byte ProtocolVersion and closes before any
// authentication, so it never counts as a failed login on the BMC.
func probeBanner(ctx context.Context, dial DialFunc, t Target, now time.Time) Probe {
	ctx, cancel := context.WithTimeout(ctx, bannerTimeout+dialTimeout)
	defer cancel()
	c, err := dialTarget(ctx, dial, t)
	if err != nil {
		return Probe{State: classifyDial(err), CheckedAt: now}
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(bannerTimeout))
	var b [12]byte
	if _, err = io.ReadFull(c, b[:]); err != nil {
		return Probe{State: ProbeUnreached, CheckedAt: now}
	}
	minor, err := rfb.ParseVersion(b[:])
	if err != nil {
		return Probe{State: ProbeNotRFB, CheckedAt: now}
	}
	return Probe{State: ProbeOK, Version: minor, CheckedAt: now}
}

func classifyDial(err error) ProbeState {
	switch {
	case errors.Is(err, ErrPinMismatch):
		return ProbePin
	case errors.Is(err, ErrTLS):
		return ProbeTLS
	case errors.Is(err, syscall.ECONNREFUSED):
		return ProbeRefused
	default:
		return ProbeUnreached
	}
}

// ProbeBanner reads t's RFB banner once and closes before any authentication (Settings
// → Servers "Test connection"). dial nil uses net.Dialer.
func ProbeBanner(ctx context.Context, dial DialFunc, t Target, now time.Time) Probe {
	if dial == nil {
		dial = defaultDial
	}
	return probeBanner(ctx, dial, t, now)
}
