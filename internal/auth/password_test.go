package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// testParams keeps tests fast; production uses DefaultArgon2Params.
func testParams() Argon2Params {
	return Argon2Params{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}
}

func newTestHasher(t *testing.T) *PasswordHasher {
	t.Helper()
	h, err := NewPasswordHasher(testParams(), 2)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestDefaultArgon2ParamsMeetOWASP(t *testing.T) {
	p := DefaultArgon2Params()
	if p.Memory < 19456 || p.Time < 2 || p.Threads < 1 || p.SaltLen < 16 || p.KeyLen < 32 {
		t.Fatalf("params below OWASP minimum: %+v", p)
	}
	if _, err := NewPasswordHasher(p, 1); err != nil {
		t.Fatal(err)
	}
}

func TestHashVerifyRoundTrip(t *testing.T) {
	h := newTestHasher(t)
	ctx := context.Background()
	enc, err := h.Hash(ctx, "correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("encoding = %q", enc)
	}
	ok, rehash, err := h.Verify(ctx, "correct horse battery", enc)
	if err != nil || !ok || rehash {
		t.Fatalf("Verify good = %v %v %v", ok, rehash, err)
	}
	ok, _, err = h.Verify(ctx, "correct horse batterY", enc)
	if err != nil || ok {
		t.Fatalf("Verify bad = %v %v", ok, err)
	}
	enc2, _ := h.Hash(ctx, "correct horse battery")
	if enc2 == enc {
		t.Fatal("salt is not random")
	}
}

func TestVerifyFlagsRehash(t *testing.T) {
	old := newTestHasher(t)
	enc, _ := old.Hash(context.Background(), "pw-pw-pw-pw-pw")
	p := testParams()
	p.Time = 2
	stronger, _ := NewPasswordHasher(p, 1)
	ok, rehash, err := stronger.Verify(context.Background(), "pw-pw-pw-pw-pw", enc)
	if err != nil || !ok || !rehash {
		t.Fatalf("got ok=%v rehash=%v err=%v, want rehash", ok, rehash, err)
	}
}

func TestVerifyRejectsMalformedAndHostile(t *testing.T) {
	h := newTestHasher(t)
	cases := []string{
		"",
		"$argon2i$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=18$m=64,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=19$m=64,t=999,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=19$m=64,t=1,p=0$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=19$m=64,t=1,p=1$!!!$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$!!!",
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaA",
		"$argon2id$v=19$m=64,t=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$v=19$m=x,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
		"$argon2id$vv19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g",
	}
	for _, enc := range cases {
		ok, _, err := h.Verify(context.Background(), "x", enc)
		if ok || !errors.Is(err, ErrBadHash) {
			t.Errorf("Verify(%q) = %v, %v; want ErrBadHash", enc, ok, err)
		}
	}
}

func TestNewPasswordHasherValidates(t *testing.T) {
	bad := []Argon2Params{
		{Memory: 0, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32},
		{Memory: 64, Time: 0, Threads: 1, SaltLen: 16, KeyLen: 32},
		{Memory: 64, Time: 1, Threads: 0, SaltLen: 16, KeyLen: 32},
		{Memory: 64, Time: 1, Threads: 1, SaltLen: 4, KeyLen: 32},
		{Memory: 64, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 8},
		{Memory: 8, Time: 1, Threads: 4, SaltLen: 16, KeyLen: 32},
	}
	for _, p := range bad {
		if _, err := NewPasswordHasher(p, 1); err == nil {
			t.Errorf("params %+v accepted", p)
		}
	}
	if _, err := NewPasswordHasher(testParams(), 0); err == nil {
		t.Error("concurrency 0 accepted")
	}
}

func TestHashHonoursContextWhenSaturated(t *testing.T) {
	h, _ := NewPasswordHasher(testParams(), 1)
	h.sem <- struct{}{} // occupy the only slot
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := h.Hash(ctx, "whatever-long-pw"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Hash err = %v", err)
	}
	if _, _, err := h.Verify(ctx, "x", "$argon2id$v=19$m=64,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Verify err = %v", err)
	}
}

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		pw string
		ok bool
	}{
		{"short", false},
		{strings.Repeat("a", 11), false},
		{strings.Repeat("a", 12), true},
		{strings.Repeat("a", MaxPasswordLen), true},
		{strings.Repeat("a", MaxPasswordLen+1), false},
	}
	for _, tc := range cases {
		if err := ValidatePassword(tc.pw); (err == nil) != tc.ok {
			t.Errorf("ValidatePassword(len %d) = %v", len(tc.pw), err)
		}
	}
}

// TestHashMemoryBudget: N concurrent hashes can never exceed HashMemoryBudgetKiB, even
// when a tampered stored hash asks for the largest memory cost decodeHash accepts.
func TestHashMemoryBudget(t *testing.T) {
	if MaxHashConcurrency*maxMemoryKiB > HashMemoryBudgetKiB {
		t.Fatalf("%d × %d KiB exceeds the %d KiB budget", MaxHashConcurrency, maxMemoryKiB, HashMemoryBudgetKiB)
	}
	if _, err := NewPasswordHasher(testParams(), MaxHashConcurrency+1); err == nil {
		t.Fatal("a concurrency above the memory budget must be refused")
	}
	h, err := NewPasswordHasher(testParams(), MaxHashConcurrency)
	if err != nil {
		t.Fatal(err)
	}
	big := "$argon2id$v=19$m=65536,t=1,p=1$c2FsdHNhbHRzYWx0c2FsdA$a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2U"
	if _, _, err := h.Verify(t.Context(), "whatever-password", big); !errors.Is(err, ErrBadHash) {
		t.Fatalf("64 MiB stored hash must be refused as ErrBadHash, got %v", err)
	}
}
