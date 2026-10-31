// Package hostlease is the fan applier for mode host-lease: the app writes a small lease
// file into the lease directory and a host-side fan script, the single writer of fan
// commands, honours it as a floor and writes an acknowledgement back. The app never
// sends a fan command itself (CLAUDE.md rule 8). Both files are plain key=value lines so
// the host can parse them strictly with awk (deploy/host/).
//
// Lease file <server>.lease (written by the app, atomically, mode 0640):
//
//	version=1
//	server=<server id>
//	lease_id=<32 lowercase hex>      nonce; echoed in the ack
//	pct=<0-100>                      floor; the host clamps it to its own safe minimum
//	issued_at=<unix seconds>
//	expires_at=<unix seconds>        the host stops honouring the file at this time
//
// Ack file <server>.ack (written by the host on every run):
//
//	version=1
//	server=<server id>
//	lease_id=<32 hex | none>         the lease the host applied, or none
//	owner=<lease | curve | guard>    what decided the fan speed on this run
//	applied_pct=<0-100 | auto>       the speed set (auto: BMC automatic)
//	reported_at=<unix seconds>
//	reason=<[a-z_]{1,32}>            ok, none, expired, invalid, guard, …
package hostlease

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"oob-manager/internal/fan"
	"oob-manager/internal/store"
)

// MaxFileBytes caps both files; the host script applies the same cap.
const MaxFileBytes = 512

const leaseVersion = "1"

var (
	serverPattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	leaseIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)
	linePattern    = regexp.MustCompile(`^([a-z_]{1,16})=([A-Za-z0-9_-]{1,64})$`)
	epochPattern   = regexp.MustCompile(`^[0-9]{1,12}$`)
	pctPattern     = regexp.MustCompile(`^[0-9]{1,3}$`)
	reasonPattern  = regexp.MustCompile(`^[a-z_]{1,32}$`)
	errBadAck      = errors.New("hostlease: unreadable ack file")
)

// encodeLease renders the lease file. Every value is re-validated here, so nothing
// unexpected can reach the host even if a caller is wrong.
func encodeLease(l store.FanLease) ([]byte, error) {
	switch {
	case !serverPattern.MatchString(l.ServerID):
		return nil, fmt.Errorf("hostlease: server id %q", l.ServerID)
	case !leaseIDPattern.MatchString(l.LeaseID):
		return nil, errors.New("hostlease: lease id must be 32 lowercase hex characters")
	case l.Pct < 0 || l.Pct > 100:
		return nil, fmt.Errorf("hostlease: pct %d", l.Pct)
	case l.IssuedAt.Unix() <= 0 || !l.ExpiresAt.After(l.IssuedAt):
		return nil, errors.New("hostlease: lease times")
	}
	var b bytes.Buffer
	for _, kv := range [][2]string{{"version", leaseVersion}, {"server", l.ServerID}, {"lease_id", l.LeaseID},
		{"pct", strconv.Itoa(l.Pct)}, {"issued_at", strconv.FormatInt(l.IssuedAt.Unix(), 10)},
		{"expires_at", strconv.FormatInt(l.ExpiresAt.Unix(), 10)}} {
		b.WriteString(kv[0] + "=" + kv[1] + "\n")
	}
	return b.Bytes(), nil
}

// ack is a parsed acknowledgement. LeaseID is "" for "none"; HasPct is false for "auto".
type ack struct {
	LeaseID    string
	Owner      fan.Owner
	Pct        int
	HasPct     bool
	ReportedAt time.Time
	Reason     string
}

// parseAck reads an ack strictly: size cap, one key=value per line from a small
// character set, no duplicates, every required key valid, the expected server. Unknown
// keys are ignored so the host script can add fields later.
func parseAck(b []byte, serverID string) (ack, error) {
	if len(b) == 0 || len(b) > MaxFileBytes {
		return ack{}, errBadAck
	}
	kv := map[string]string{}
	for _, line := range bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n")) {
		m := linePattern.FindSubmatch(line)
		if m == nil {
			return ack{}, errBadAck
		}
		if _, dup := kv[string(m[1])]; dup {
			return ack{}, errBadAck
		}
		kv[string(m[1])] = string(m[2])
	}
	if kv["version"] != leaseVersion || kv["server"] != serverID {
		return ack{}, errBadAck
	}
	return ackFields(kv)
}

func ackFields(kv map[string]string) (ack, error) {
	var a ack
	switch id := kv["lease_id"]; {
	case id == "none":
	case leaseIDPattern.MatchString(id):
		a.LeaseID = id
	default:
		return ack{}, errBadAck
	}
	switch o := fan.Owner(kv["owner"]); o {
	case fan.OwnerLease, fan.OwnerCurve, fan.OwnerGuard:
		a.Owner = o
	default:
		return ack{}, errBadAck
	}
	switch p := kv["applied_pct"]; {
	case p == "auto":
	case pctPattern.MatchString(p):
		a.Pct, _ = strconv.Atoi(p)
		a.HasPct = a.Pct <= 100
		if !a.HasPct {
			return ack{}, errBadAck
		}
	default:
		return ack{}, errBadAck
	}
	ts := kv["reported_at"]
	if !epochPattern.MatchString(ts) || !reasonPattern.MatchString(kv["reason"]) {
		return ack{}, errBadAck
	}
	sec, _ := strconv.ParseInt(ts, 10, 64)
	a.ReportedAt, a.Reason = time.Unix(sec, 0).UTC(), kv["reason"]
	return a, nil
}
