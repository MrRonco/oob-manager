package redfish

import (
	"errors"
	"net/http"
	"testing"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

const floorKey = "ThermalSettings.1.MinimumFanSpeed"

func floorPatch() Option { return WithAttributePatch(redfishmock.FanFloorAttrsPath, floorKey) }

func TestPatchAttributesOnlyThePolicy(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithFanFloor())
	d := operatorDriver(t, s, floorPatch())
	if err := d.PatchAttributes(testCtx(t), redfishmock.FanFloorAttrsPath, map[string]int{floorKey: 60}); err != nil {
		t.Fatal(err)
	}
	refused := []struct {
		uri   string
		attrs map[string]int
	}{
		{redfishmock.FanFloorAttrsPath, map[string]int{"ThermalSettings.1.FanSpeedOffset": 1}},
		{redfishmock.FanFloorAttrsPath, map[string]int{floorKey: 60, "X": 1}},
		{redfishmock.FanFloorAttrsPath, map[string]int{}},
		{"/redfish/v1/Managers/iDRAC.Embedded.1/Attributes", map[string]int{floorKey: 60}},
		{redfishmock.FanFloorAttrsPath + "/", map[string]int{floorKey: 60}},
		{"/redfish/v1/../x", map[string]int{floorKey: 60}},
	}
	for _, c := range refused {
		err := d.PatchAttributes(testCtx(t), c.uri, c.attrs)
		if !errors.Is(err, bmc.ErrMethodNotAllowed) && !errors.Is(err, bmc.ErrInvalidConfig) {
			t.Errorf("PATCH %s %v: err = %v", c.uri, c.attrs, err)
		}
	}
	if st := s.FanFloorStats(); len(st.Patches) != 1 || st.Patches[0] != 60 || st.Rejected != 0 || s.OtherWrites() != 0 {
		t.Fatalf("a refused PATCH reached the BMC: %+v %+v", st, s.Requests())
	}
	if d.allowRequest(http.MethodPatch, "/redfish/v1/Systems/System.Embedded.1") || d.allowRequest(http.MethodPut, redfishmock.FanFloorAttrsPath) {
		t.Fatal("guard allows a write outside the policy")
	}
	_ = d.Close(testCtx(t))
	if err := d.PatchAttributes(testCtx(t), redfishmock.FanFloorAttrsPath, map[string]int{floorKey: 60}); !errors.Is(err, bmc.ErrInvalidConfig) {
		t.Errorf("closed driver: %v", err)
	}
}

func TestPatchAttributesWithoutPolicyIsRefused(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithFanFloor())
	d := operatorDriver(t, s)
	if err := d.PatchAttributes(testCtx(t), redfishmock.FanFloorAttrsPath, map[string]int{floorKey: 60}); !errors.Is(err, bmc.ErrMethodNotAllowed) {
		t.Fatalf("err = %v", err)
	}
	if d.allowRequest(http.MethodPatch, redfishmock.FanFloorAttrsPath) {
		t.Fatal("guard allows PATCH without a policy")
	}
	for _, r := range s.Requests() {
		if r.Method == http.MethodPatch {
			t.Fatalf("PATCH reached the BMC: %+v", r)
		}
	}
}

func TestPatchAttributesErrors(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithFanFloor())
	ro := driverFor(t, s, floorPatch()) // read-only account: the BMC answers 403
	if err := ro.PatchAttributes(testCtx(t), redfishmock.FanFloorAttrsPath, map[string]int{floorKey: 60}); !errors.Is(err, bmc.ErrAuth) {
		t.Fatalf("err = %v", err)
	}
	op := operatorDriver(t, s, floorPatch())
	if err := op.PatchAttributes(testCtx(t), redfishmock.FanFloorAttrsPath, map[string]int{floorKey: 5}); !errors.Is(err, bmc.ErrBMC) {
		t.Fatalf("out of range: %v", err)
	}
	if _, err := New(configFor(s), WithAttributePatch("/redfish/v1/../x", floorKey)); !errors.Is(err, bmc.ErrInvalidConfig) {
		t.Errorf("bad policy URI: %v", err)
	}
	if _, err := New(configFor(s), WithAttributePatch(redfishmock.FanFloorAttrsPath)); !errors.Is(err, bmc.ErrInvalidConfig) {
		t.Errorf("policy without keys: %v", err)
	}
}
