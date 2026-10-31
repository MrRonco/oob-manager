package credstore

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"oob-manager/internal/secrets"
)

func key(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, KeyBytes)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func binding() Binding {
	return Binding{ServerID: "edge1", Slot: SlotReadOnly, Kind: "idrac9", Address: "192.0.2.12", Port: 443, Version: 3}
}

var cred = secrets.Credential{Username: "svc_ro", Password: secrets.New("correct horse battery staple")}

func TestSealOpenRoundTrip(t *testing.T) {
	s, err := New(key(t))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := s.Seal(binding(), cred)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Open(binding(), blob)
	if err != nil || got.Username != "svc_ro" || !got.Password.Equal(cred.Password) {
		t.Fatalf("open = %+v, %v", got, err)
	}
	if bytes.Contains(blob, []byte("correct horse")) || bytes.Contains(blob, []byte("svc_ro")) {
		t.Fatal("plaintext in the sealed blob")
	}
	again, _ := s.Seal(binding(), cred)
	if bytes.Equal(again, blob) {
		t.Fatal("two seals of the same credential are identical (nonce reuse)")
	}
}

// TestAADBinding: a credential sealed for one server, slot, kind, address, port or
// version never opens under any other binding, so a moved address (or a swapped row)
// makes it undecryptable and it must be entered again.
func TestAADBinding(t *testing.T) {
	s, _ := New(key(t))
	blob, err := s.Seal(binding(), cred)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(Binding) Binding{
		"moved address": func(b Binding) Binding { b.Address = "192.0.2.13"; return b },
		"other port":    func(b Binding) Binding { b.Port = 8443; return b },
		"other kind":    func(b Binding) Binding { b.Kind = "redfish"; return b },
		"slot swap":     func(b Binding) Binding { b.Slot = SlotOperator; return b },
		"row swap":      func(b Binding) Binding { b.ServerID = "edge2"; return b },
		"old version":   func(b Binding) Binding { b.Version = 2; return b },
	}
	for name, mut := range mutations {
		if _, err := s.Open(mut(binding()), blob); !errors.Is(err, ErrUndecryptable) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestTamperAndWrongKey(t *testing.T) {
	s, _ := New(key(t))
	blob, _ := s.Seal(binding(), cred)
	bad := bytes.Clone(blob)
	bad[len(bad)-1] ^= 1
	if _, err := s.Open(binding(), bad); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("tampered: %v", err)
	}
	other, _ := New(key(t))
	if _, err := other.Open(binding(), blob); !errors.Is(err, ErrUndecryptable) {
		t.Fatalf("wrong key: %v", err)
	}
	for _, short := range [][]byte{nil, blob[:5], blob[:nonceBytes]} {
		if _, err := s.Open(binding(), short); !errors.Is(err, ErrUndecryptable) {
			t.Fatalf("short blob: %v", err)
		}
	}
}

func TestVNCPasswordOnly(t *testing.T) {
	s, _ := New(key(t))
	b := binding()
	b.Slot = SlotVNC
	blob, err := s.Seal(b, secrets.Credential{Password: secrets.New("vncpass")})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.Open(b, blob)
	if err != nil || got.Username != "" || got.Password.Reveal() != "vncpass" {
		t.Fatalf("vnc = %+v %v", got, err)
	}
}

func TestRefusals(t *testing.T) {
	if _, err := New(make([]byte, 16)); err == nil {
		t.Fatal("short key accepted")
	}
	s, _ := New(key(t))
	bad := []Binding{
		{ServerID: "", Slot: SlotReadOnly, Kind: "idrac9", Address: "192.0.2.1", Port: 443, Version: 1},
		{ServerID: "a", Slot: "admin", Kind: "idrac9", Address: "192.0.2.1", Port: 443, Version: 1},
		{ServerID: "a", Slot: SlotReadOnly, Kind: "", Address: "192.0.2.1", Port: 443, Version: 1},
		{ServerID: "a", Slot: SlotReadOnly, Kind: "idrac9", Address: "", Port: 443, Version: 1},
		{ServerID: "a", Slot: SlotReadOnly, Kind: "idrac9", Address: "192.0.2.1", Port: 0, Version: 1},
		{ServerID: "a", Slot: SlotReadOnly, Kind: "idrac9", Address: "192.0.2.1", Port: 443, Version: 0},
		{ServerID: "a|readonly", Slot: SlotReadOnly, Kind: "idrac9", Address: "192.0.2.1", Port: 443, Version: 1},
		{ServerID: "a", Slot: SlotReadOnly, Kind: "idrac9", Address: "192.0.2.1|x", Port: 443, Version: 1},
	}
	for i, b := range bad {
		if _, err := s.Seal(b, cred); !errors.Is(err, ErrBinding) {
			t.Errorf("binding %d: %v", i, err)
		}
	}
	if _, err := s.Seal(binding(), secrets.Credential{Username: "x"}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("empty password: %v", err)
	}
	b := binding()
	b.Slot = SlotOperator
	if _, err := s.Seal(b, secrets.Credential{Password: secrets.New("p")}); !errors.Is(err, ErrEmpty) {
		t.Fatalf("login slot without username: %v", err)
	}
}

func TestSlotsAndAAD(t *testing.T) {
	if got := Slots(); len(got) != 3 || got[0] != SlotReadOnly || got[2] != SlotVNC {
		t.Fatalf("slots = %v", got)
	}
	if _, err := ParseSlot("operator"); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseSlot("root"); err == nil {
		t.Fatal("unknown slot parsed")
	}
	if got := string(binding().aad()); got != "bmc-cred/v1|edge1|readonly|idrac9|192.0.2.12|443|3" {
		t.Fatalf("aad = %q", got)
	}
	if !strings.Contains(SlotVNC.Label(), "VNC") || SlotReadOnly.Label() == "" || SlotOperator.Label() == "" {
		t.Fatal("labels")
	}
}
