package redfish

import (
	"context"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

const (
	idrac8 = "idrac8-r730xd"
	idrac9 = "idrac9-r240"
)

// Compile-time check: Driver satisfies the bmc contract.
var _ bmc.Driver = (*Driver)(nil)

func mockFor(t *testing.T, fixture string, opts ...redfishmock.Option) *redfishmock.Server {
	t.Helper()
	return redfishmock.New(t, redfishmock.FixtureDir(t, fixture), opts...)
}

func configFor(s *redfishmock.Server) Config {
	return Config{
		Endpoint:  s.URL(),
		Username:  redfishmock.User,
		Password:  redfishmock.Password,
		PinSHA256: s.PinSHA256(),
		Timeout:   2 * time.Second,
	}
}

func driverFor(t *testing.T, s *redfishmock.Server, opts ...Option) *Driver {
	t.Helper()
	d, err := New(configFor(s), opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return d
}

func testCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// dellSEL mimics the fallback the dellredfish package installs (kept here so the generic
// package can test its option without importing the Dell package).
func dellSEL(manager string) []string { return []string{manager + "/Logs/Sel"} }

func assertNoWrites(t *testing.T, s *redfishmock.Server) {
	t.Helper()
	if n := s.OtherWrites(); n != 0 {
		t.Fatalf("driver sent %d non-GET requests besides session login/logout: %+v", n, s.Requests())
	}
}
