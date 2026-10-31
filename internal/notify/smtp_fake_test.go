package notify

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeSMTP is a minimal SMTP server for tests: EHLO, STARTTLS, AUTH PLAIN, MAIL, RCPT,
// DATA, QUIT. It records the transcript (with AUTH payloads) and every message.
type fakeSMTP struct {
	ln       net.Listener
	tlsCfg   *tls.Config
	pool     *x509.CertPool
	implicit bool // TLS from the first byte (port 465 style)
	starttls bool // offer STARTTLS
	auth     bool // offer AUTH PLAIN
	rcptCode string

	mu       sync.Mutex
	messages []string
	authed   []string // decoded AUTH PLAIN credentials
	sawTLS   bool
	wg       sync.WaitGroup
}

func newFakeSMTP(t *testing.T, implicit, starttls, auth bool) *fakeSMTP {
	t.Helper()
	cert := httptest.NewTLSServer(nil) // only for its certificate
	cfg := &tls.Config{Certificates: cert.TLS.Certificates, MinVersion: tls.VersionTLS12}
	pool := x509.NewCertPool()
	pool.AddCert(cert.Certificate())
	cert.Close()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, tlsCfg: cfg, pool: pool, implicit: implicit, starttls: starttls, auth: auth, rcptCode: "250"}
	f.wg.Go(f.serve)
	t.Cleanup(func() { _ = ln.Close(); f.wg.Wait() })
	return f
}

func (f *fakeSMTP) url() string { return "smtp://" + f.ln.Addr().String() }

func (f *fakeSMTP) transport() Transport {
	return Transport{Policy: Policy{Allowed: loopback}, TLS: &tls.Config{RootCAs: f.pool, MinVersion: tls.VersionTLS12},
		Timeout: 3 * time.Second}
}

func (f *fakeSMTP) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.wg.Go(func() { f.session(c) })
	}
}

func (f *fakeSMTP) session(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if f.implicit {
		tc := tls.Server(c, f.tlsCfg)
		if tc.HandshakeContext(context.Background()) != nil {
			return
		}
		c = tc
		f.setTLS()
	}
	rw := bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
	say := func(s string) { _, _ = rw.WriteString(s + "\r\n"); _ = rw.Flush() }
	say("220 fake.example ESMTP")
	for {
		line, err := rw.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"), strings.HasPrefix(cmd, "HELO"):
			f.ehlo(say, c)
		case cmd == "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, f.tlsCfg)
			if tc.HandshakeContext(context.Background()) != nil {
				return
			}
			c = tc
			f.setTLS()
			rw = bufio.NewReadWriter(bufio.NewReader(c), bufio.NewWriter(c))
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			f.recordAuth(strings.TrimSpace(line)[len("AUTH PLAIN"):])
			say("235 ok")
		case strings.HasPrefix(cmd, "MAIL FROM"):
			say("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO"):
			say(f.rcptCode + " rcpt")
		case cmd == "DATA":
			say("354 send")
			f.readData(rw)
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			return
		default:
			say("502 unknown")
		}
	}
}

func (f *fakeSMTP) ehlo(say func(string), c net.Conn) {
	_, isTLS := c.(*tls.Conn)
	var ext []string
	if f.starttls && !isTLS {
		ext = append(ext, "STARTTLS")
	}
	if f.auth {
		ext = append(ext, "AUTH PLAIN")
	}
	if len(ext) == 0 {
		say("250 fake.example")
		return
	}
	say("250-fake.example")
	for i, e := range ext {
		sep := "-"
		if i == len(ext)-1 {
			sep = " "
		}
		say("250" + sep + e)
	}
}

func (f *fakeSMTP) setTLS() {
	f.mu.Lock()
	f.sawTLS = true
	f.mu.Unlock()
}

func (f *fakeSMTP) recordAuth(b64 string) {
	raw, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	f.mu.Lock()
	f.authed = append(f.authed, strings.ReplaceAll(string(raw), "\x00", "|"))
	f.mu.Unlock()
}

func (f *fakeSMTP) readData(rw *bufio.ReadWriter) {
	var b strings.Builder
	for {
		line, err := rw.ReadString('\n')
		if err != nil || line == ".\r\n" {
			break
		}
		b.WriteString(line)
	}
	f.mu.Lock()
	f.messages = append(f.messages, b.String())
	f.mu.Unlock()
}

func (f *fakeSMTP) snapshot() (msgs, auths []string, sawTLS bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.messages...), append([]string(nil), f.authed...), f.sawTLS
}
