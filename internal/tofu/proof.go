package tofu

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// ProofTTL is how long a fetched fingerprint can be confirmed.
const ProofTTL = 5 * time.Minute

// Errors from Verify.
var (
	ErrProof        = errors.New("tofu: fingerprint proof does not match")
	ErrProofExpired = errors.New("tofu: fingerprint proof expired; fetch it again")
)

// Kind is what a fingerprint pins.
type Kind string

// Kinds.
const (
	KindTLS Kind = "tls" // the HTTPS (Redfish) certificate SPKI
	KindVNC Kind = "vnc" // the VNC port's certificate SPKI, when it differs
	KindSSH Kind = "ssh" // the SSH host key
)

// Claim is what a proof binds: who fetched (the session binding), what, where, and the
// fetched value.
type Claim struct {
	Session string
	// Purpose is what the proof may be used for (the confirming form's path, which
	// names the action and the server), so a proof cannot be replayed elsewhere.
	Purpose string
	Kind    Kind
	Addr    string
	Port    int
	Value   string
}

// Prover signs and checks proofs that a fingerprint is the one the app fetched for this
// session (settings_design.md §3: pinproof = HMAC(DeriveKey(tofu/v1),
// session‖addr‖port‖value‖ts), TTL 5 min). It holds no mutable state.
type Prover struct {
	key []byte
	now func() time.Time
}

// NewProver builds a Prover from a ≥ 32-byte key (secrets.PurposeTOFU).
func NewProver(key []byte, now func() time.Time) (*Prover, error) {
	if len(key) < 32 {
		return nil, errors.New("tofu: proof key must be at least 32 bytes")
	}
	if now == nil {
		now = time.Now
	}
	return &Prover{key: append([]byte(nil), key...), now: now}, nil
}

// Sign returns "<unix seconds>.<hex mac>".
func (p *Prover) Sign(c Claim) string {
	ts := p.now().Unix()
	return strconv.FormatInt(ts, 10) + "." + hex.EncodeToString(p.mac(c, ts))
}

// Verify checks proof against c: the MAC, and an age in [0, ProofTTL].
func (p *Prover) Verify(c Claim, proof string) error {
	tsRaw, macHex, ok := strings.Cut(proof, ".")
	ts, err := strconv.ParseInt(tsRaw, 10, 64)
	if !ok || err != nil || ts <= 0 {
		return ErrProof
	}
	mac, err := hex.DecodeString(macHex)
	if err != nil || !hmac.Equal(mac, p.mac(c, ts)) {
		return ErrProof
	}
	age := p.now().Sub(time.Unix(ts, 0))
	switch {
	case age < -time.Second:
		return ErrProof
	case age > ProofTTL:
		return ErrProofExpired
	}
	return nil
}

func (p *Prover) mac(c Claim, ts int64) []byte {
	h := hmac.New(sha256.New, p.key)
	for _, part := range []string{"tofu/v1", c.Session, c.Purpose, string(c.Kind), c.Addr, strconv.Itoa(c.Port), c.Value,
		strconv.FormatInt(ts, 10)} {
		h.Write([]byte(strconv.Itoa(len(part))))
		h.Write([]byte{':'})
		h.Write([]byte(part))
	}
	return h.Sum(nil)
}
