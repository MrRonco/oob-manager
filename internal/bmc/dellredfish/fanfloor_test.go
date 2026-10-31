package dellredfish

import (
	"errors"
	"net/http"
	"testing"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

func TestFanFloorReadAndSet(t *testing.T) {
	s := redfishmock.New(t, redfishmock.FixtureDir(t, idrac9), redfishmock.WithFanFloor(), redfishmock.WithTokenOnly())
	c := NewFanFloorClient(operatorConfig(s))
	f, err := c.Read(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	if f != (FanFloor{Current: FanFloorAuto, Low: 35, High: 100}) || !f.Automatic() {
		t.Fatalf("floor = %+v", f)
	}
	if err := c.Set(ctx(t), 60); err != nil {
		t.Fatal(err)
	}
	if err := c.Set(ctx(t), FanFloorAuto); err != nil {
		t.Fatal(err)
	}
	if st := s.FanFloorStats(); len(st.Patches) != 2 || st.Patches[0] != 60 || st.Current != FanFloorAuto {
		t.Fatalf("stats %+v", st)
	}
	for _, v := range []int{-1, 0, 101, 254, 256} {
		if err := c.Set(ctx(t), v); !errors.Is(err, bmc.ErrInvalidConfig) {
			t.Errorf("Set(%d) = %v", v, err)
		}
	}
	if len(s.FanFloorStats().Patches) != 2 || s.LiveSessions() != 0 {
		t.Fatalf("refused values reached the BMC or a session leaked: %+v live %d", s.FanFloorStats(), s.LiveSessions())
	}
	// Only GET, PATCH of the one URI, and session login/logout were sent.
	for _, r := range s.Requests() {
		if r.Method == http.MethodPatch && r.Path != FanFloorAttrsURI {
			t.Fatalf("unexpected PATCH %+v", r)
		}
	}
	if s.OtherWrites() != 0 {
		t.Fatalf("other writes: %+v", s.Requests())
	}
}

func TestFanFloorReadRejectsHostileDocuments(t *testing.T) {
	docs := map[string]string{
		"absent":         `{"Attributes":{}}`,
		"current range":  `{"Attributes":{"ThermalSettings.1.MinimumFanSpeed":300,"ThermalSettings.1.MFSMinimumLimit":35,"ThermalSettings.1.MFSMaximumLimit":100}}`,
		"limits swapped": `{"Attributes":{"ThermalSettings.1.MinimumFanSpeed":255,"ThermalSettings.1.MFSMinimumLimit":90,"ThermalSettings.1.MFSMaximumLimit":40}}`,
		"limit zero":     `{"Attributes":{"ThermalSettings.1.MinimumFanSpeed":255,"ThermalSettings.1.MFSMinimumLimit":0,"ThermalSettings.1.MFSMaximumLimit":100}}`,
		"limit high":     `{"Attributes":{"ThermalSettings.1.MinimumFanSpeed":255,"ThermalSettings.1.MFSMinimumLimit":35,"ThermalSettings.1.MFSMaximumLimit":101}}`,
		"strings":        `{"Attributes":{"ThermalSettings.1.MinimumFanSpeed":"255","ThermalSettings.1.MFSMinimumLimit":35,"ThermalSettings.1.MFSMaximumLimit":100}}`,
		"not json":       `<html>`,
	}
	for name, doc := range docs {
		s := redfishmock.New(t, redfishmock.FixtureDir(t, idrac9), redfishmock.WithOverlay(FanFloorAttrsURI, doc))
		_, err := NewFanFloorClient(operatorConfig(s)).Read(ctx(t))
		if !errors.Is(err, bmc.ErrDecode) && !errors.Is(err, bmc.ErrUnsupported) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	s := redfishmock.New(t, redfishmock.FixtureDir(t, idrac9)) // iDRAC without the attributes resource
	if _, err := NewFanFloorClient(operatorConfig(s)).Read(ctx(t)); !errors.Is(err, bmc.ErrNotFound) {
		t.Errorf("absent resource: %v", err)
	}
	bad := operatorConfig(s)
	bad.Endpoint = "ftp://x"
	c := NewFanFloorClient(bad)
	if _, err := c.Read(ctx(t)); !errors.Is(err, bmc.ErrInvalidConfig) {
		t.Errorf("bad config read: %v", err)
	}
	if err := c.Set(ctx(t), 50); !errors.Is(err, bmc.ErrInvalidConfig) {
		t.Errorf("bad config set: %v", err)
	}
}

func TestFanFloorClamp(t *testing.T) {
	f := FanFloor{Current: FanFloorAuto, Low: 35, High: 100}
	cases := []struct{ want, min, out int }{{20, 20, 35}, {50, 41, 50}, {30, 41, 41}, {100, 41, 100}}
	for _, c := range cases {
		if got := f.Clamp(c.want, c.min); got != c.out {
			t.Errorf("Clamp(%d, %d) = %d, want %d", c.want, c.min, got, c.out)
		}
	}
	narrow := FanFloor{Low: 35, High: 80}
	if got := narrow.Clamp(95, 41); got != 80 {
		t.Errorf("above the BMC maximum: %d", got)
	}
	if !ValidFloorValue(60) || ValidFloorValue(254) || ValidFloorValue(0) || !ValidFloorValue(FanFloorAuto) {
		t.Error("ValidFloorValue")
	}
}
