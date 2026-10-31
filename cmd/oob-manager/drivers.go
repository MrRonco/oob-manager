package main

import (
	"errors"
	"fmt"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/dellredfish"
	"oob-manager/internal/bmc/redfish"
	"oob-manager/internal/config"
	"oob-manager/internal/secrets"
)

// driverFactory builds the read-only driver for one configured server.
type driverFactory func(s config.Server, ro secrets.Credential) (bmc.Driver, error)

// errNoDriver marks a server kind that has no driver yet (IPMI arrives in P2/P4).
var errNoDriver = errors.New("no driver for this BMC kind yet")

// newBMCDriver picks the driver from config only: Dell iDRACs get dellredfish, generic
// Redfish BMCs get redfish. The endpoint is built from the validated literal IP.
func newBMCDriver(s config.Server, ro secrets.Credential) (bmc.Driver, error) {
	return bmcDriverAt(s, ro, s.BMC.Endpoint())
}

// bmcDriverAt builds the driver for s against endpoint. Only tests and the e2e harness
// pass an endpoint other than the configured address (a mock BMC on a random port);
// the pin and credentials always come from config and the age file.
func bmcDriverAt(s config.Server, ro secrets.Credential, endpoint string) (bmc.Driver, error) {
	cfg := redfish.Config{
		Endpoint:  endpoint,
		Username:  ro.Username,
		Password:  ro.Password.Reveal(),
		PinSHA256: s.TLSPinSHA256,
		Timeout:   s.BMC.Timeouts.Request,
		Auth:      redfish.AuthMode(s.BMC.Auth),
	}
	switch s.BMC.Kind {
	case config.KindIDRAC8, config.KindIDRAC9:
		return dellredfish.New(cfg)
	case config.KindRedfish:
		return redfish.New(cfg)
	default:
		return nil, fmt.Errorf("server %s (%s): %w", s.ID, s.BMC.Kind, errNoDriver)
	}
}
