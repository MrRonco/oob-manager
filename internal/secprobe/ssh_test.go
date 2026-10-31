package secprobe

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"oob-manager/internal/bmc"
	"oob-manager/internal/bmc/bmcssh/sshtest"
)

func TestScanSSHModernServer(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{})
	p := ScanSSH(testCtx(t), netip.MustParseAddrPort(srv.Addr()), Options{})
	if !p.Read.OK() || !strings.HasPrefix(p.Version, "SSH-2.0-") {
		t.Fatalf("probe %+v", p)
	}
	if !strings.Contains(p.HostKeys, "ssh-ed25519") || !strings.Contains(p.KeyExchanges, "curve25519-sha256") ||
		!strings.Contains(p.Ciphers, "aes128-gcm@openssh.com") || p.MACs == "" {
		t.Fatalf("algorithms %+v", p)
	}
	if srv.AuthAttempts() != 0 || srv.Sessions() != 0 || len(srv.Requests()) != 0 {
		t.Fatalf("the probe must stop before any key exchange or login: auth %d sessions %d", srv.AuthAttempts(), srv.Sessions())
	}
}

func TestScanSSHLegacyServer(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{Legacy: true})
	p := ScanSSH(testCtx(t), netip.MustParseAddrPort(srv.Addr()), Options{})
	if p.HostKeys != "ssh-rsa" || !strings.HasPrefix(p.KeyExchanges, "diffie-hellman-group14-sha1") {
		t.Fatalf("legacy algorithms %+v", p)
	}
}

// kexInitPacket builds an unencrypted SSH_MSG_KEXINIT binary packet.
func kexInitPacket(lists ...string) []byte {
	payload := []byte{msgKexInit}
	payload = append(payload, make([]byte, 16)...) // cookie
	for i := range 10 {
		var l string
		if i < len(lists) {
			l = lists[i]
		}
		payload = binary.BigEndian.AppendUint32(payload, uint32(len(l))) //nolint:gosec // G115: test lists are short
		payload = append(payload, l...)
	}
	payload = append(payload, 0, 0, 0, 0, 0)
	pad := 4
	pkt := binary.BigEndian.AppendUint32(nil, uint32(len(payload)+pad+1)) //nolint:gosec // G115: test packet
	pkt = append(pkt, byte(pad))
	pkt = append(pkt, payload...)
	return append(pkt, make([]byte, pad)...)
}

func fakeSSH(t *testing.T, banner string, packet []byte) netip.AddrPort {
	t.Helper()
	return rawServer(t, func(c net.Conn) {
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = c.Write([]byte(banner))
		if packet == nil {
			return
		}
		line, err := bufio.NewReader(c).ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "SSH-2.0-oob-manager") {
			return
		}
		_, _ = c.Write(packet)
	})
}

func TestScanSSHPreBannerLinesAndCaps(t *testing.T) {
	long := strings.Repeat("x,", 600) + "end"
	addr := fakeSSH(t, "Welcome to the BMC\r\nAuthorized use only\r\nSSH-2.0-Fake_1.0 \x1b[31mred\r\n",
		kexInitPacket("diffie-hellman-group1-sha1", "ssh-dss", "3des-cbc", "3des-cbc", long, long))
	p := ScanSSH(testCtx(t), addr, Options{})
	if !p.Read.OK() || p.Version != "SSH-2.0-Fake_1.0 [31mred" || p.KeyExchanges != "diffie-hellman-group1-sha1" ||
		p.HostKeys != "ssh-dss" || p.Ciphers != "3des-cbc" {
		t.Fatalf("probe %+v", p)
	}
	if len(p.MACs) > maxNameList {
		t.Fatalf("name-list not capped: %d", len(p.MACs))
	}
}

func TestScanSSHRefusesGarbage(t *testing.T) {
	cases := map[string]netip.AddrPort{
		"not ssh":        fakeSSH(t, "HTTP/1.1 400 Bad Request\r\n\r\n", nil),
		"ssh 1":          fakeSSH(t, "SSH-1.5-old\r\n", nil),
		"huge packet":    fakeSSH(t, "SSH-2.0-x\r\n", []byte{0x7f, 0xff, 0xff, 0xff, 4}),
		"not kexinit":    fakeSSH(t, "SSH-2.0-x\r\n", append(binary.BigEndian.AppendUint32(nil, 6), 4, 21, 0, 0, 0, 0)),
		"truncated list": fakeSSH(t, "SSH-2.0-x\r\n", append(binary.BigEndian.AppendUint32(nil, 30), append([]byte{4, msgKexInit}, make([]byte, 28)...)...)),
	}
	for name, addr := range cases {
		if p := ScanSSH(testCtx(t), addr, Options{}); p.Read.State != bmc.ReadFailed || p.Read.Class != bmc.ClassProtocol {
			t.Errorf("%s: %+v", name, p.Read)
		}
	}
}

func TestScanSSHUnreachableAndSilent(t *testing.T) {
	if p := ScanSSH(testCtx(t), closedAddr(t), Options{}); p.Read.Class != bmc.ClassUnreachable {
		t.Fatalf("closed %+v", p.Read)
	}
	silent := rawServer(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	if p := ScanSSH(testCtx(t), silent, Options{HandshakeTimeout: 200 * time.Millisecond}); p.Read.Class != bmc.ClassTimeout {
		t.Fatalf("silent %+v", p.Read)
	}
}

// TestScanSSHStopsWhenItsContextIsCancelled: a cancelled context (no deadline) ends a
// probe that is waiting for a banner that never comes.
func TestScanSSHStopsWhenItsContextIsCancelled(t *testing.T) {
	silent := rawServer(t, func(c net.Conn) { _, _ = io.Copy(io.Discard, c) })
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start := time.Now()
	p := ScanSSH(ctx, silent, Options{HandshakeTimeout: 5 * time.Second})
	if took := time.Since(start); took > 2*time.Second || p.Read.State != bmc.ReadFailed || p.Read.Class != bmc.ClassTimeout {
		t.Fatalf("took %v, read %+v", took, p.Read)
	}
}

// TestScanSSHRefusedIsAClosedPort: a connection refused is a known closed port (Refused).
func TestScanSSHRefusedIsAClosedPort(t *testing.T) {
	p := ScanSSH(testCtx(t), closedAddr(t), Options{})
	if p.Read.State != bmc.ReadFailed || p.Read.Class != bmc.ClassUnreachable || !p.Refused {
		t.Fatalf("closed port %+v", p)
	}
}
