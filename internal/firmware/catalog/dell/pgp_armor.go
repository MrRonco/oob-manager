package dell

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
)

// The small OpenPGP subset the catalog check needs (RFC 4880), on the standard library
// only: golang.org/x/crypto/openpgp is unmaintained and flagged as a whole by govulncheck
// (GO-2026-5932), so it is not used (plan 08 §5.3). Only verification is implemented:
// ASCII armor, public key packets (RSA, DSA), and v3/v4 signature packets.

var errArmor = errors.New("not valid OpenPGP armor")

// Armor block types.
const (
	armorSignature = "PGP SIGNATURE"
	armorPublicKey = "PGP PUBLIC KEY BLOCK"
)

// dearmor returns the payload of every armored block of type kind in data, in order.
// Armor headers are skipped; the CRC-24 checksum must match when present.
func dearmor(data []byte, kind string) ([][]byte, error) {
	begin, end := "-----BEGIN "+kind+"-----", "-----END "+kind+"-----"
	var out [][]byte
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != begin {
			continue
		}
		body, next, err := armorBody(lines, i+1, end)
		if err != nil {
			return nil, err
		}
		out = append(out, body)
		i = next
	}
	if len(out) == 0 {
		return nil, errArmor
	}
	return out, nil
}

// armorBody decodes one block from lines[start:] up to its end line and returns the
// index of that end line.
func armorBody(lines []string, start int, end string) ([]byte, int, error) {
	i := start
	for ; i < len(lines) && strings.TrimSpace(lines[i]) != ""; i++ { // headers ("Version: …")
		if !strings.Contains(lines[i], ":") {
			break // no header block: the base64 starts here
		}
	}
	var b64 strings.Builder
	sum, hasSum := "", false
	for ; i < len(lines); i++ {
		l := strings.TrimSpace(lines[i])
		switch {
		case l == end:
			body, err := base64.StdEncoding.DecodeString(b64.String())
			if err != nil {
				return nil, 0, errArmor
			}
			if hasSum && !crcMatches(body, sum) {
				return nil, 0, errArmor
			}
			return body, i, nil
		case l == "":
		case strings.HasPrefix(l, "="):
			sum, hasSum = l[1:], true
		default:
			b64.WriteString(l)
		}
	}
	return nil, 0, errArmor
}

func crcMatches(body []byte, sum string) bool {
	want, err := base64.StdEncoding.DecodeString(sum)
	if err != nil || len(want) != 3 {
		return false
	}
	c := crc24(body)
	return bytes.Equal(want, binary.BigEndian.AppendUint32(nil, c)[1:])
}

// crc24 is the OpenPGP armor checksum (RFC 4880 §6.1).
func crc24(b []byte) uint32 {
	const (
		init24 = 0xB704CE
		poly24 = 0x1864CFB
	)
	c := uint32(init24)
	for _, x := range b {
		c ^= uint32(x) << 16
		for range 8 {
			c <<= 1
			if c&0x1000000 != 0 {
				c ^= poly24
			}
		}
	}
	return c & 0xFFFFFF
}
