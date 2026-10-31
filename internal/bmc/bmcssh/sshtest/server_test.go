package sshtest

import (
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func dial(t *testing.T, s *Server, user, pw string) (*ssh.Client, error) {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s.HostKeyLine()))
	if err != nil {
		t.Fatal(err)
	}
	return ssh.Dial("tcp", s.Addr(), &ssh.ClientConfig{User: user, Auth: []ssh.AuthMethod{ssh.Password(pw),
		ssh.KeyboardInteractive(func(_, _ string, q []string, _ []bool) ([]string, error) {
			out := make([]string, len(q))
			for i := range q {
				out[i] = pw
			}
			return out, nil
		})},
		HostKeyCallback: ssh.FixedHostKey(key), Timeout: 5 * time.Second})
}

func TestFakeRefusesEverythingButConsoleCom2(t *testing.T) {
	s := New(t, Options{})
	c, err := dial(t, s, User, Password)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, run := range []func(*ssh.Session) error{
		func(x *ssh.Session) error { return x.Shell() },
		func(x *ssh.Session) error { return x.Start("racadm getsysinfo") },
		func(x *ssh.Session) error { return x.RequestSubsystem("sftp") },
	} {
		sess, nerr := c.NewSession()
		if nerr != nil {
			t.Fatal(nerr)
		}
		if rerr := run(sess); rerr == nil {
			t.Error("fake accepted a request other than console com2")
		}
		_ = sess.Close()
	}
	if _, _, oerr := c.OpenChannel("direct-tcpip", nil); oerr == nil {
		t.Error("fake accepted a non-session channel")
	}
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := sess.StdoutPipe()
	in, _ := sess.StdinPipe()
	if err := sess.Start(Command); err != nil {
		t.Fatal(err)
	}
	if ok, _ := sess.SendRequest("exec", true, ssh.Marshal(struct{ C string }{"console com1"})); ok {
		t.Error("second exec accepted")
	}
	_, _ = in.Write([]byte("hi\x1c"))
	b, _ := io.ReadAll(out)
	if !strings.HasPrefix(string(b), Banner) || !strings.HasSuffix(string(b), "hi") {
		t.Errorf("output %q", b)
	}
	if s.Sessions() != 1 || !slices.Contains(s.RequestTypes(), "shell") {
		t.Errorf("sessions %d, requests %v", s.Sessions(), s.RequestTypes())
	}
	if execCommand([]byte{0, 0}) != "" || execCommand([]byte{0, 0, 0, 9, 'x'}) != "" {
		t.Error("malformed exec payload parsed")
	}
}

func TestFakeAuth(t *testing.T) {
	for _, o := range []Options{{}, {KeyboardInteractive: true}, {Legacy: true}, {RSA: true, Silent: true}} {
		s := New(t, o)
		if o.Legacy {
			continue // modern clients cannot negotiate with it; bmcssh tests cover it
		}
		if _, err := dial(t, s, User, "wrong"); err == nil {
			t.Error("wrong password accepted")
		}
		c, err := dial(t, s, User, Password)
		if err != nil {
			t.Fatalf("%+v: %v", o, err)
		}
		_ = c.Close()
		if s.AuthAttempts() < 2 {
			t.Errorf("auth attempts %d", s.AuthAttempts())
		}
	}
}

func TestFakeWritesTranscriptAfterBanner(t *testing.T) {
	const transcript = "\r\nhost login: "
	for _, o := range []Options{{Transcript: transcript}, {Transcript: transcript, Silent: true}} {
		s := New(t, o)
		c, err := dial(t, s, User, Password)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := c.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		out, _ := sess.StdoutPipe()
		in, _ := sess.StdinPipe()
		if err := sess.Start(Command); err != nil {
			t.Fatal(err)
		}
		_, _ = in.Write([]byte{quitKey})
		b, _ := io.ReadAll(out)
		want := Banner + transcript
		if o.Silent {
			want = ""
		}
		if string(b) != want {
			t.Errorf("silent=%v: output %q, want %q", o.Silent, b, want)
		}
		_ = c.Close()
	}
}
