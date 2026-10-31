package redfish

import (
	"errors"
	"net/http"
	"testing"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/redfishmock"
)

func operatorDriver(t *testing.T, s *redfishmock.Server, opts ...Option) *Driver {
	t.Helper()
	cfg := configFor(s)
	cfg.Username, cfg.Password = redfishmock.OperatorUser, redfishmock.OperatorPassword
	d, err := New(cfg, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func onlyKVM(p string) bool { return p == redfishmock.KVMActionPath }

func TestPostActionAllowedOnlyByPolicy(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithKVMSession())
	d := operatorDriver(t, s, WithActionPolicy(onlyKVM))
	var out struct{ TempUsername, TempPassword string }
	if err := d.PostAction(testCtx(t), redfishmock.KVMActionPath, map[string]string{"SessionTypeName": "x"}, &out); err != nil {
		t.Fatal(err)
	}
	if out.TempUsername == "" || out.TempPassword == "" || s.KVMStats().Launches != 1 {
		t.Fatalf("out %+v stats %+v", out, s.KVMStats())
	}
	refused := []string{redfishmock.KVMServicePath, "/redfish/v1/Systems/System.Embedded.1/Actions/ComputerSystem.Reset",
		redfishmock.KVMActionPath + "/", "/redfish/v1/../x"}
	for _, uri := range refused {
		if err := d.PostAction(testCtx(t), uri, map[string]string{}, nil); !errors.Is(err, bmc.ErrMethodNotAllowed) &&
			!errors.Is(err, bmc.ErrInvalidConfig) {
			t.Errorf("POST %s: err = %v", uri, err)
		}
	}
	if s.KVMStats().Launches != 1 || s.OtherWrites() != 0 {
		t.Fatalf("a refused POST reached the BMC: %+v", s.Requests())
	}
	_ = d.Close(testCtx(t))
}

func TestPostActionWithoutPolicyIsRefused(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithKVMSession())
	d := driverFor(t, s)
	if err := d.PostAction(testCtx(t), redfishmock.KVMActionPath, map[string]string{}, nil); !errors.Is(err, bmc.ErrMethodNotAllowed) {
		t.Fatalf("err = %v", err)
	}
	// The transport guard refuses it too, even for a hand-built request.
	if d.allowRequest(http.MethodPost, redfishmock.KVMActionPath) {
		t.Fatal("guard allows an action POST without a policy")
	}
	for _, r := range s.Requests() {
		if r.Method == http.MethodPost {
			t.Fatalf("POST reached the BMC: %+v", r)
		}
	}
}

func TestPostActionErrors(t *testing.T) {
	s := mockFor(t, idrac9, redfishmock.WithKVMSession())
	ro := driverFor(t, s, WithActionPolicy(onlyKVM)) // read-only account: the BMC answers 403
	if err := ro.PostAction(testCtx(t), redfishmock.KVMActionPath, map[string]string{"SessionTypeName": "x"}, nil); !errors.Is(err, bmc.ErrAuth) {
		t.Fatalf("err = %v", err)
	}
	if s.KVMStats().Rejected != 1 {
		t.Errorf("stats = %+v", s.KVMStats())
	}
	basic := configFor(s)
	basic.Auth = AuthBasic
	d, _ := New(basic, WithActionPolicy(onlyKVM))
	var out struct{ X int }
	if err := d.PostAction(testCtx(t), redfishmock.KVMActionPath, map[string]string{"SessionTypeName": "x"}, &out); err == nil {
		t.Error("basic-auth read-only POST accepted by mock")
	}
	if err := d.PostAction(testCtx(t), redfishmock.KVMActionPath, func() {}, nil); !errors.Is(err, bmc.ErrInvalidConfig) {
		t.Errorf("unencodable body: %v", err)
	}
	_ = d.Close(testCtx(t))
	if err := d.PostAction(testCtx(t), redfishmock.KVMActionPath, map[string]string{}, nil); !errors.Is(err, bmc.ErrInvalidConfig) {
		t.Errorf("closed driver: %v", err)
	}
}
