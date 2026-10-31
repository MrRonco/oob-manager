package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Password length bounds in bytes. The upper bound stops multi-megabyte "passwords"
// from being fed to argon2.
const (
	MinPasswordLen = 12
	MaxPasswordLen = 256
)

// Upper bounds accepted when decoding a stored hash, so a tampered row cannot make a
// single login allocate gigabytes or spin for minutes.
const (
	maxMemoryKiB = 48 * 1024
	maxTime      = 10
	maxThreads   = 16
	minSaltLen   = 16
	maxSaltLen   = 64
	minKeyLen    = 16
	maxKeyLen    = 64
)

// Memory budget for argon2id: at most MaxHashConcurrency hashes run at once and each may
// use at most maxMemoryKiB, so concurrent logins stay under HashMemoryBudgetKiB in total
// (the container limit must leave headroom for the Go runtime, pollers and `docker exec`
// processes, which share the cgroup; see deploy/compose.yaml).
const (
	HashMemoryBudgetKiB = 100 * 1024
	MaxHashConcurrency  = HashMemoryBudgetKiB / maxMemoryKiB
)

// ErrBadHash means a stored password hash could not be parsed or is out of bounds.
var ErrBadHash = errors.New("auth: malformed password hash")

// Argon2Params are argon2id cost parameters. Memory is in KiB.
type Argon2Params struct {
	Memory  uint32
	Time    uint32
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

// DefaultArgon2Params is the OWASP Password Storage Cheat Sheet option m=19 MiB, t=2,
// p=1. It is chosen over RFC 9106's 64 MiB profile because the container runs with a
// 256 MiB memory limit; PasswordHasher also bounds concurrency (HashMemoryBudgetKiB).
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{Memory: 19456, Time: 2, Threads: 1, SaltLen: 16, KeyLen: 32}
}

func (p Argon2Params) validate() error {
	switch {
	case p.Time < 1 || p.Time > maxTime:
		return fmt.Errorf("argon2 time %d out of range", p.Time)
	case p.Threads < 1 || p.Threads > maxThreads:
		return fmt.Errorf("argon2 threads %d out of range", p.Threads)
	case p.Memory < 8*uint32(p.Threads) || p.Memory > maxMemoryKiB:
		return fmt.Errorf("argon2 memory %d KiB out of range", p.Memory)
	case p.SaltLen < minSaltLen || p.SaltLen > maxSaltLen:
		return fmt.Errorf("argon2 salt length %d out of range", p.SaltLen)
	case p.KeyLen < minKeyLen || p.KeyLen > maxKeyLen:
		return fmt.Errorf("argon2 key length %d out of range", p.KeyLen)
	}
	return nil
}

// PasswordHasher hashes and verifies passwords with argon2id. At most maxConcurrent
// hashes run at once; further callers wait (or give up when ctx ends).
type PasswordHasher struct {
	params Argon2Params
	sem    chan struct{}
	dummy  string // hash of a random password, verified for unknown users (timing)
}

// NewPasswordHasher validates params and returns a hasher.
func NewPasswordHasher(p Argon2Params, maxConcurrent int) (*PasswordHasher, error) {
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	if maxConcurrent < 1 || maxConcurrent > MaxHashConcurrency {
		return nil, fmt.Errorf("auth: maxConcurrent must be in [1, %d] (argon2 memory budget)", MaxHashConcurrency)
	}
	h := &PasswordHasher{params: p, sem: make(chan struct{}, maxConcurrent)}
	dummy, err := h.Hash(context.Background(), rand.Text())
	if err != nil {
		return nil, err
	}
	h.dummy = dummy
	return h, nil
}

// ValidatePassword enforces the length policy for new passwords.
func ValidatePassword(pw string) error {
	if len(pw) < MinPasswordLen || len(pw) > MaxPasswordLen {
		return fmt.Errorf("auth: password must be %d-%d bytes", MinPasswordLen, MaxPasswordLen)
	}
	return nil
}

// Hash returns a PHC-format string: $argon2id$v=19$m=..,t=..,p=..$salt$key.
func (h *PasswordHasher) Hash(ctx context.Context, pw string) (string, error) {
	salt := make([]byte, h.params.SaltLen)
	_, _ = rand.Read(salt) // never fails (Go 1.24+)
	key, err := h.derive(ctx, pw, salt, h.params)
	if err != nil {
		return "", err
	}
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version,
		h.params.Memory, h.params.Time, h.params.Threads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify checks pw against encoded in constant time. needsRehash is true when the hash
// was made with parameters other than the hasher's current ones.
func (h *PasswordHasher) Verify(ctx context.Context, pw, encoded string) (ok, needsRehash bool, err error) {
	p, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, false, err
	}
	got, err := h.derive(ctx, pw, salt, p)
	if err != nil {
		return false, false, err
	}
	ok = subtle.ConstantTimeCompare(got, want) == 1
	return ok, ok && p != h.params, nil
}

// burn verifies against the dummy hash so unknown usernames cost the same as known ones.
func (h *PasswordHasher) burn(ctx context.Context, pw string) {
	_, _, _ = h.Verify(ctx, pw, h.dummy)
}

func (h *PasswordHasher) derive(ctx context.Context, pw string, salt []byte, p Argon2Params) ([]byte, error) {
	select {
	case h.sem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-h.sem }()
	return argon2.IDKey([]byte(pw), salt, p.Time, p.Memory, p.Threads, p.KeyLen), nil
}

func decodeHash(encoded string) (Argon2Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return Argon2Params{}, nil, nil, ErrBadHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Argon2Params{}, nil, nil, ErrBadHash
	}
	var p Argon2Params
	n, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads)
	if err != nil || n != 3 {
		return Argon2Params{}, nil, nil, ErrBadHash
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	key, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return Argon2Params{}, nil, nil, ErrBadHash
	}
	saltLen, keyLen := len(salt), len(key)
	if saltLen > maxSaltLen || keyLen > maxKeyLen {
		return Argon2Params{}, nil, nil, ErrBadHash
	}
	p.SaltLen, p.KeyLen = uint32(saltLen), uint32(keyLen)
	if p.validate() != nil {
		return Argon2Params{}, nil, nil, ErrBadHash
	}
	return p, salt, key, nil
}
