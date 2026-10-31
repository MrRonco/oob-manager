package bmcssh

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"oob-manager/internal/bmc/bmcssh/sshtest"
	"oob-manager/internal/secrets"
)

func cfgFor(srv *sshtest.Server) Config {
	return Config{ServerID: "s1", Addr: srv.Addr(), HostKey: srv.HostKeyLine(), Username: sshtest.User,
		Password: secrets.New(sshtest.Password), Timeout: 5 * time.Second}
}

func open(t *testing.T, c Config) *Session {
	t.Helper()
	s, err := Open(context.Background(), c, Size{Cols: 100, Rows: 30})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// readUntil reads from s until want appears (or fails after 5 s).
func readUntil(t *testing.T, s io.Reader, want string) string {
	t.Helper()
	var got bytes.Buffer
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for !strings.Contains(got.String(), want) {
			n, err := s.Read(buf)
			got.Write(buf[:n])
			if err != nil {
				return
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %q", want)
	}
	if !strings.Contains(got.String(), want) {
		t.Fatalf("output %q lacks %q", got.String(), want)
	}
	return got.String()
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestOpenRunsExactlyConsoleCom2WithAPTY(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{})
	s := open(t, cfgFor(srv))
	readUntil(t, s, "Connected to Serial Device 2")
	if _, err := s.Write([]byte("root\r")); err != nil {
		t.Fatal(err)
	}
	readUntil(t, s, "root\r")
	reqs := srv.Requests()
	if got := srv.RequestTypes(); !slices.Equal(got, []string{"pty-req", "exec"}) {
		t.Fatalf("requests = %v, want pty-req then exec", got)
	}
	if cmd := string(reqs[1].Payload[4:]); cmd != Command || Command != "console com2" {
		t.Errorf("exec %q", cmd)
	}
	var pty struct {
		Term             string
		Cols, Rows, W, H uint32
		Modes            string
	}
	if err := ssh.Unmarshal(reqs[0].Payload, &pty); err != nil {
		t.Fatal(err)
	}
	if pty.Cols != 100 || pty.Rows != 30 || pty.Term != "xterm" {
		t.Errorf("pty = %+v", pty)
	}
}

// The Session's exported API is the whole surface: there is no way to run another
// command, open a shell or send an arbitrary request.
func TestSessionAPIOffersNoOtherCommand(t *testing.T) {
	var names []string
	typ := reflect.TypeFor[*Session]()
	for i := range typ.NumMethod() {
		names = append(names, typ.Method(i).Name)
	}
	sort.Strings(names)
	want := []string{"Break", "Close", "Quit", "Read", "Resize", "Write"}
	if !slices.Equal(names, want) {
		t.Errorf("Session methods = %v, want %v", names, want)
	}
}

func TestWrongHostKeyIsRefusedBeforeThePasswordIsSent(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{})
	other := sshtest.New(t, sshtest.Options{})
	c := cfgFor(srv)
	c.HostKey = other.HostKeyLine()
	_, err := Open(context.Background(), c, Size{Cols: 80, Rows: 24})
	if !errors.Is(err, ErrHostKey) {
		t.Fatalf("err = %v, want ErrHostKey", err)
	}
	if n := srv.AuthAttempts(); n != 0 {
		t.Errorf("password sent %d times to an unverified host", n)
	}
	// A pinned key of another type cannot be negotiated at all.
	rsaSrv := sshtest.New(t, sshtest.Options{RSA: true})
	c = cfgFor(rsaSrv)
	c.HostKey = srv.HostKeyLine()
	if _, err = Open(context.Background(), c, Size{}); !errors.Is(err, ErrHostKey) {
		t.Fatalf("type mismatch: err = %v, want ErrHostKey", err)
	}
	if rsaSrv.AuthAttempts() != 0 {
		t.Error("password sent after a host key type mismatch")
	}
}

func TestBadConfigIsRefused(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{})
	for name, mod := range map[string]func(*Config){
		"no host key":  func(c *Config) { c.HostKey = "" },
		"bad host key": func(c *Config) { c.HostKey = "ssh-ed25519 AAAA" },
		"no user":      func(c *Config) { c.Username = "" },
		"no password":  func(c *Config) { c.Password = secrets.Secret{} },
	} {
		t.Run(name, func(t *testing.T) {
			c := cfgFor(srv)
			mod(&c)
			if _, err := Open(context.Background(), c, Size{}); !errors.Is(err, ErrConfig) {
				t.Errorf("err = %v, want ErrConfig", err)
			}
		})
	}
	if srv.AuthAttempts() != 0 {
		t.Error("a bad config reached the BMC")
	}
}

func TestWrongPasswordIsErrAuth(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{})
	c := cfgFor(srv)
	c.Password = secrets.New("wrong")
	_, err := Open(context.Background(), c, Size{})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Error("error carries the password")
	}
}

func TestKeyboardInteractiveLogin(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{KeyboardInteractive: true})
	s := open(t, cfgFor(srv))
	readUntil(t, s, "Serial Device 2")
}

func TestLegacyQuirkEnablesOnlyWhatIDRAC8Needs(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{Legacy: true})
	c := cfgFor(srv)
	_, err := Open(context.Background(), c, Size{})
	if err == nil || !errors.Is(err, ErrAlgorithms) {
		t.Fatalf("modern-only client against a legacy server: err = %v, want ErrAlgorithms", err)
	}
	c.Legacy = true
	s := open(t, c)
	readUntil(t, s, "Serial Device 2")

	a := algorithms(true, mustKey(t, srv.HostKeyLine()))
	if !slices.Contains(a.KeyExchanges, ssh.InsecureKeyExchangeDH14SHA1) || !slices.Contains(a.HostKeys, ssh.KeyAlgoRSA) {
		t.Errorf("legacy algorithms = %+v", a)
	}
	for _, insecure := range ssh.InsecureAlgorithms().Ciphers {
		if slices.Contains(a.Ciphers, insecure) {
			t.Errorf("legacy enables cipher %s", insecure)
		}
	}
	if slices.Contains(a.KeyExchanges, ssh.InsecureKeyExchangeDH1SHA1) || slices.Contains(a.MACs, ssh.InsecureHMACSHA196) {
		t.Errorf("legacy enables more than the minimum: %+v", a)
	}
	modern := algorithms(false, mustKey(t, srv.HostKeyLine()))
	for _, list := range [][]string{modern.KeyExchanges, modern.HostKeys, modern.Ciphers, modern.MACs} {
		for _, alg := range list {
			if isInsecure(alg) {
				t.Errorf("default algorithms include insecure %s", alg)
			}
		}
	}
	// ssh-rsa is never offered for a non-RSA pinned key, even with the quirk.
	ed := sshtest.New(t, sshtest.Options{})
	if slices.Contains(algorithms(true, mustKey(t, ed.HostKeyLine())).HostKeys, ssh.KeyAlgoRSA) {
		t.Error("ssh-rsa offered for an ed25519 pin")
	}
}

func isInsecure(alg string) bool {
	in := ssh.InsecureAlgorithms()
	for _, l := range [][]string{in.KeyExchanges, in.HostKeys, in.Ciphers, in.MACs} {
		if slices.Contains(l, alg) {
			return true
		}
	}
	return false
}

func mustKey(t *testing.T, line string) ssh.PublicKey {
	t.Helper()
	k, err := ParseHostKey(line)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestResizeBreakAndQuit(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{})
	s := open(t, cfgFor(srv))
	readUntil(t, s, "Serial Device 2")
	if err := s.Resize(Size{Cols: 1000, Rows: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Break(); err != nil {
		t.Fatal(err)
	}
	readUntil(t, s, "<BREAK>")
	waitFor(t, func() bool { return slices.Contains(srv.RequestTypes(), "break") })
	var wc struct{ Cols, Rows, W, H uint32 }
	for _, r := range srv.Requests() {
		if r.Type == "window-change" {
			if err := ssh.Unmarshal(r.Payload, &wc); err != nil {
				t.Fatal(err)
			}
		}
	}
	if wc.Cols != MaxCols || wc.Rows != MinRows {
		t.Errorf("window-change clamped to %dx%d, want %dx%d", wc.Cols, wc.Rows, MaxCols, MinRows)
	}
	if err := s.Quit(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return srv.Active() == 0 })
	if in := srv.Input(); !bytes.HasSuffix(in, []byte{QuitKey}) {
		t.Errorf("input %q does not end with the quit key", in)
	}
	if _, err := io.ReadAll(s); err != nil {
		t.Errorf("read after quit: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second close: %v", err)
	}
	if got := strings.Count(strings.Join(srv.RequestTypes(), ","), "exec"); got != 1 {
		t.Errorf("%d exec requests", got)
	}
}

func TestSilentHostStillConnects(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{Silent: true})
	s := open(t, cfgFor(srv))
	if _, err := s.Write([]byte("\r")); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return bytes.Equal(srv.Input(), []byte("\r")) })
}

func TestHandshakeTimeout(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, aerr := ln.Accept()
		if aerr == nil {
			defer c.Close()
			time.Sleep(3 * time.Second) // never speaks SSH
		}
	}()
	srv := sshtest.New(t, sshtest.Options{})
	c := cfgFor(srv)
	c.Addr, c.Timeout = ln.Addr().String(), 200*time.Millisecond
	start := time.Now()
	_, err = Open(context.Background(), c, Size{})
	if err == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
	if Classify(err) != "timeout" {
		t.Errorf("class = %q", Classify(err))
	}
}

func TestDialFuncAndUnreachable(t *testing.T) {
	srv := sshtest.New(t, sshtest.Options{})
	c := cfgFor(srv)
	c.Addr = "192.0.2.10:22"
	var dialled string
	c.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialled = addr
		return (&net.Dialer{}).DialContext(ctx, network, srv.Addr())
	}
	s := open(t, c)
	readUntil(t, s, "Serial Device 2")
	if dialled != "192.0.2.10:22" {
		t.Errorf("dialled %q", dialled)
	}
	c.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("refused") }
	_, err := Open(context.Background(), c, Size{})
	if Classify(err) != "unreachable" {
		t.Errorf("class = %q (%v)", Classify(err), err)
	}
}

func TestClassify(t *testing.T) {
	for err, want := range map[error]string{
		ErrHostKey: "host_key", ErrAuth: "bmc_auth", ErrAlgorithms: "algorithms", ErrRefused: "bmc_protocol",
		ErrConfig: "config", context.DeadlineExceeded: "timeout", errors.New("x"): "unreachable",
	} {
		if got := Classify(err); got != want {
			t.Errorf("Classify(%v) = %q, want %q", err, got, want)
		}
	}
}
