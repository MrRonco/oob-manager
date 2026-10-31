package secprobe

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/textclean"
)

// SSH transport constants (RFC 4253).
const (
	msgKexInit     = 20
	maxPacket      = 35000 // RFC 4253 §6.1: implementations must accept at least this
	maxIdentLine   = 255
	maxBannerLines = 20
	// maxNameList caps each algorithm list kept (cut at a comma).
	maxNameList = 1024
	clientIdent = "SSH-2.0-oob-manager\r\n"
)

// ScanSSH reads the server's half of an SSH key exchange: its identification string
// and its KEXINIT algorithm lists. It sends only its own identification string, then
// closes: no KEXINIT, no key exchange, no user name, no authentication. The lists come
// from an unauthenticated read and describe whatever answered at addr.
func ScanSSH(ctx context.Context, addr netip.AddrPort, o Options) bmc.SSHProbe {
	o = o.withDefaults()
	p := bmc.SSHProbe{Port: int(addr.Port())}
	c, err := o.dial(ctx, addr)
	if err != nil {
		p.Read, p.Refused = failed(err), connRefused(err)
		return p
	}
	defer c.Close()
	r := bufio.NewReaderSize(c, 4096)
	ident, err := readIdent(r)
	if err == nil {
		_, err = io.WriteString(c, clientIdent)
	}
	var lists [10]string
	if err == nil {
		lists, err = readKexInit(r)
	}
	if err != nil {
		p.Read = failed(err)
		return p
	}
	p.Read, p.Version = bmc.SectionOf(nil), textclean.Clean(ident, 64)
	p.KeyExchanges, p.HostKeys, p.Ciphers, p.MACs = capList(lists[0]), capList(lists[1]), capList(lists[2]), capList(lists[4])
	return p
}

// readIdent skips the lines a server may send before its version string (RFC 4253
// §4.2) and returns the version line. SSH 1 servers are refused.
func readIdent(r *bufio.Reader) (string, error) {
	for range maxBannerLines {
		line, err := readLine(r)
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(line, "SSH-") {
			continue
		}
		if !strings.HasPrefix(line, "SSH-2.0-") && !strings.HasPrefix(line, "SSH-1.99-") {
			return "", fmt.Errorf("%w: not SSH 2", errNotProtocol)
		}
		return line, nil
	}
	return "", fmt.Errorf("%w: no SSH identification string", errNotProtocol)
}

func readLine(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for b.Len() <= maxIdentLine {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if c == '\n' {
			return strings.TrimSuffix(b.String(), "\r"), nil
		}
		b.WriteByte(c)
	}
	return "", fmt.Errorf("%w: line too long", errNotProtocol)
}

// readKexInit reads one unencrypted binary packet and parses it as SSH_MSG_KEXINIT.
func readKexInit(r *bufio.Reader) ([10]string, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return [10]string{}, err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n < 5 || n > maxPacket {
		return [10]string{}, fmt.Errorf("%w: packet length %d", errNotProtocol, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return [10]string{}, err
	}
	pad := int(buf[0])
	if pad >= len(buf)-1 {
		return [10]string{}, fmt.Errorf("%w: padding", errNotProtocol)
	}
	return parseKexInit(buf[1 : len(buf)-pad])
}

// parseKexInit returns the ten name-lists of a KEXINIT payload.
func parseKexInit(payload []byte) ([10]string, error) {
	var out [10]string
	if len(payload) < 17 || payload[0] != msgKexInit {
		return out, fmt.Errorf("%w: not KEXINIT", errNotProtocol)
	}
	rest := payload[17:] // message type and 16-byte cookie
	for i := range out {
		if len(rest) < 4 {
			return out, fmt.Errorf("%w: truncated KEXINIT", errNotProtocol)
		}
		l := binary.BigEndian.Uint32(rest)
		rest = rest[4:]
		if uint64(l) > uint64(len(rest)) {
			return out, fmt.Errorf("%w: truncated name-list", errNotProtocol)
		}
		out[i], rest = string(rest[:l]), rest[l:]
	}
	return out, nil
}

// capList sanitizes a name-list and cuts it to maxNameList bytes at a comma.
func capList(s string) string {
	s = textclean.Clean(s, maxNameList+1)
	if len(s) <= maxNameList {
		return s
	}
	s = s[:maxNameList]
	if i := strings.LastIndexByte(s, ','); i > 0 {
		s = s[:i]
	}
	return s
}
