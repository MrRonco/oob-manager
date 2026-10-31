package rfb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

var testInit = ServerInit{Width: 640, Height: 480, PixelFormat: [16]byte{32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0}, Name: "bmc"}

// pipe returns two ends with a deadline so a protocol bug fails instead of hanging.
func pipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	a, b := net.Pipe()
	dl := time.Now().Add(5 * time.Second)
	_ = a.SetDeadline(dl)
	_ = b.SetDeadline(dl)
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

func TestClientAndServerHandshakesInteroperate(t *testing.T) {
	a, b := pipe(t)
	errc := make(chan error, 1)
	go func() { errc <- ServerHandshake(a, testInit) }()
	got, err := ClientHandshake(b, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if got != testInit {
		t.Errorf("ServerInit = %+v, want %+v", got, testInit)
	}
}

// scriptedServer plays a BMC: it writes the given steps and reads the expected number
// of bytes in between, recording what the client sent.
type step struct {
	write []byte
	read  int
}

func runScript(t *testing.T, steps []step) (*bytes.Buffer, chan error, net.Conn) {
	t.Helper()
	srv, cli := pipe(t)
	got := &bytes.Buffer{}
	done := make(chan error, 1)
	go func() {
		for _, s := range steps {
			if len(s.write) > 0 {
				if _, err := srv.Write(s.write); err != nil {
					done <- err
					return
				}
			}
			if s.read > 0 {
				buf := make([]byte, s.read)
				if _, err := io.ReadFull(srv, buf); err != nil {
					done <- err
					return
				}
				got.Write(buf)
			}
		}
		done <- nil
	}()
	return got, done, cli
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

func initBytes() []byte { return testInit.Marshal() }

func TestClientHandshakeVNCAuth38(t *testing.T) {
	var ch [16]byte
	copy(ch[:], "0123456789abcdef")
	got, done, cli := runScript(t, []step{
		{write: []byte("RFB 003.008\n"), read: 12},
		{write: []byte{2, 1, 2}, read: 1}, // None and VNC auth offered; VNC auth chosen
		{write: ch[:], read: 16},
		{write: u32(0), read: 1}, // ClientInit
		{write: initBytes()},
	})
	si, err := ClientHandshake(cli, []byte("password"))
	if err != nil || si != testInit {
		t.Fatalf("handshake = %+v, %v", si, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	want := append([]byte("RFB 003.008\n"), 2)
	resp := VNCAuthResponse(ch, []byte("password"))
	want = append(append(want, resp[:]...), 0) // shared=0
	if !bytes.Equal(got.Bytes(), want) {
		t.Errorf("client sent %q, want %q", got.Bytes(), want)
	}
}

func TestClientHandshakeVersions(t *testing.T) {
	cases := map[string]struct {
		banner, reply string
		steps         []step
	}{
		"3.3 vnc auth": {"RFB 003.003\n", "RFB 003.003\n", []step{{write: u32(2)}, {write: make([]byte, 16), read: 16}, {write: u32(0), read: 1}}},
		"3.7 none":     {"RFB 003.007\n", "RFB 003.007\n", []step{{write: []byte{1, 1}, read: 1}, {read: 1}}},
		"3.6 ultravnc": {"RFB 003.006\n", "RFB 003.003\n", []step{{write: u32(1), read: 1}}},
		"3.889 apple":  {"RFB 003.889\n", "RFB 003.008\n", []step{{write: []byte{1, 1}, read: 1}, {write: u32(0), read: 1}}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			steps := append([]step{{write: []byte(tc.banner), read: 12}}, tc.steps...)
			steps = append(steps, step{write: initBytes()})
			got, done, cli := runScript(t, steps)
			if _, err := ClientHandshake(cli, []byte("pw")); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(got.String(), tc.reply) {
				t.Errorf("client version reply %q, want %q", got.String()[:12], tc.reply)
			}
		})
	}
}

func TestClientHandshakeFailures(t *testing.T) {
	reason := append(u32(4), "nope"...)
	cases := map[string]struct {
		steps []step
		want  error
	}{
		"bad banner":        {[]step{{write: []byte("HTTP/1.1 400")}}, ErrUnsupportedVersion},
		"version 4":         {[]step{{write: []byte("RFB 004.000\n")}}, ErrUnsupportedVersion},
		"no types":          {[]step{{write: []byte("RFB 003.008\n"), read: 12}, {write: append([]byte{0}, reason...)}}, ErrNoSecurity},
		"only tight":        {[]step{{write: []byte("RFB 003.008\n"), read: 12}, {write: []byte{1, 16}}}, ErrNoSecurity},
		"auth rejected 3.8": {[]step{{write: []byte("RFB 003.008\n"), read: 12}, {write: []byte{1, 2}, read: 1}, {write: make([]byte, 16), read: 16}, {write: append(u32(1), reason...)}}, ErrAuthFailed},
		"auth rejected 3.3": {[]step{{write: []byte("RFB 003.003\n"), read: 12}, {write: u32(2)}, {write: make([]byte, 16), read: 16}, {write: u32(1)}}, ErrAuthFailed},
		"3.3 refused":       {[]step{{write: []byte("RFB 003.003\n"), read: 12}, {write: append(u32(0), reason...)}}, ErrNoSecurity},
		"3.3 unknown type":  {[]step{{write: []byte("RFB 003.003\n"), read: 12}, {write: u32(16)}}, ErrNoSecurity},
		"huge name": {[]step{{write: []byte("RFB 003.008\n"), read: 12}, {write: []byte{1, 1}, read: 1}, {write: u32(0), read: 1},
			{write: append(initBytes()[:20], u32(MaxNameLen+1)...)}}, ErrProtocol},
		"none result failed": {[]step{{write: []byte("RFB 003.008\n"), read: 12}, {write: []byte{1, 1}, read: 1}, {write: append(u32(1), reason...)}}, ErrAuthFailed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, _, cli := runScript(t, tc.steps)
			_, err := ClientHandshake(cli, []byte("password"))
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "nope") {
				t.Error("BMC-supplied reason text leaked into the error")
			}
		})
	}
}

func TestClientHandshakeNeedsPasswordForVNCAuth(t *testing.T) {
	_, _, cli := runScript(t, []step{{write: []byte("RFB 003.008\n"), read: 12}, {write: []byte{1, 2}}})
	if _, err := ClientHandshake(cli, nil); !errors.Is(err, ErrNoSecurity) {
		t.Fatalf("err = %v", err)
	}
}

func TestServerHandshakeVersions(t *testing.T) {
	for _, v := range []string{"RFB 003.003\n", "RFB 003.007\n", "RFB 003.008\n"} {
		t.Run(v[:11], func(t *testing.T) {
			srv, cli := pipe(t)
			errc := make(chan error, 1)
			go func() { errc <- ServerHandshake(srv, testInit) }()
			banner := make([]byte, 12)
			if _, err := io.ReadFull(cli, banner); err != nil || string(banner) != "RFB 003.008\n" {
				t.Fatalf("banner %q %v", banner, err)
			}
			_, _ = cli.Write([]byte(v))
			if v == "RFB 003.003\n" {
				typ := make([]byte, 4)
				_, _ = io.ReadFull(cli, typ)
				if binary.BigEndian.Uint32(typ) != SecNone {
					t.Fatalf("3.3 security type %x", typ)
				}
			} else {
				types := make([]byte, 2)
				_, _ = io.ReadFull(cli, types)
				if !bytes.Equal(types, []byte{1, SecNone}) {
					t.Fatalf("offered %v, want only None", types)
				}
				_, _ = cli.Write([]byte{SecNone})
				if v == "RFB 003.008\n" {
					res := make([]byte, 4)
					_, _ = io.ReadFull(cli, res)
				}
			}
			_, _ = cli.Write([]byte{1}) // ClientInit
			si, err := ReadServerInit(cli)
			if err != nil || si != testInit {
				t.Fatalf("ServerInit %+v %v", si, err)
			}
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestServerHandshakeRejects(t *testing.T) {
	cases := map[string][]byte{
		"bad version":    []byte("RFB 004.000\n"),
		"wrong security": append([]byte("RFB 003.008\n"), 2),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			srv, cli := pipe(t)
			errc := make(chan error, 1)
			go func() { errc <- ServerHandshake(srv, testInit) }()
			go func() { _, _ = io.Copy(io.Discard, cli) }()
			_, _ = cli.Write(input)
			if err := <-errc; err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestServerInitWithName(t *testing.T) {
	si := testInit.WithName("Intel(r) AMT KVM")
	if si.Name != "Intel(r) AMT KVM" || testInit.Name != "bmc" {
		t.Errorf("WithName = %+v (original %+v)", si, testInit)
	}
	if _, err := ReadServerInit(bytes.NewReader(initBytes()[:10])); err == nil {
		t.Error("truncated ServerInit accepted")
	}
}
