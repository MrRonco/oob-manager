package sshtest

import (
	"encoding/binary"
	"errors"
	"net"
	"slices"

	"golang.org/x/crypto/ssh"
)

func (s *Server) config() *ssh.ServerConfig {
	c := &ssh.ServerConfig{}
	if s.opts.KeyboardInteractive {
		c.KeyboardInteractiveCallback = func(m ssh.ConnMetadata, ask ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ans, err := ask("", "", []string{"Password: "}, []bool{false})
			if err != nil {
				return nil, err
			}
			return s.check(m.User(), ans...)
		}
	} else {
		c.PasswordCallback = func(m ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			return s.check(m.User(), string(pw))
		}
	}
	if s.opts.Legacy {
		c.KeyExchanges = []string{ssh.InsecureKeyExchangeDH14SHA1}
	}
	c.AddHostKey(s.signer)
	return c
}

func (s *Server) check(user string, answers ...string) (*ssh.Permissions, error) {
	s.mu.Lock()
	s.authN++
	s.mu.Unlock()
	if user == s.opts.User && len(answers) == 1 && answers[0] == s.opts.Password {
		return &ssh.Permissions{}, nil
	}
	return nil, errors.New("sshtest: access denied")
}

func (s *Server) accept() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns = append(s.conns, c)
		s.mu.Unlock()
		go s.serve(c)
	}
}

func (s *Server) serve(c net.Conn) {
	defer c.Close()
	sc, chans, reqs, err := ssh.NewServerConn(c, s.config())
	if err != nil {
		return
	}
	defer sc.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go s.session(ch, creqs)
	}
}

func (s *Server) record(r *ssh.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests = append(s.requests, Request{Type: r.Type, Payload: slices.Clone(r.Payload)})
}

// session answers channel requests like an iDRAC: pty-req, window-change and break are
// accepted, exec only for Command; shell, subsystem, env and a second exec are refused.
func (s *Server) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	started := false
	for r := range reqs {
		s.record(r)
		ok := false
		switch r.Type {
		case "pty-req", "window-change":
			ok = true
		case "break":
			ok = started
			if started && !s.opts.Silent {
				_, _ = ch.Write([]byte("<BREAK>"))
			}
		case "exec":
			ok = !started && execCommand(r.Payload) == Command
		}
		if r.WantReply {
			_ = r.Reply(ok, nil)
		}
		switch {
		case r.Type == "exec" && !ok && !started:
			return
		case r.Type == "exec" && ok:
			started = true
			go s.console(ch)
		}
	}
}

func execCommand(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	n := binary.BigEndian.Uint32(payload)
	if int(n) != len(payload)-4 {
		return ""
	}
	return string(payload[4:])
}

// console echoes input until the quit key or EOF, then reports exit status 0 and
// closes the channel (the iDRAC ends `console com2` the same way).
func (s *Server) console(ch ssh.Channel) {
	s.mu.Lock()
	s.sessions++
	s.active++
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.active--
		s.mu.Unlock()
	}()
	if !s.opts.Silent {
		_, _ = ch.Write([]byte(Banner + s.opts.Transcript))
	}
	buf := make([]byte, 4096)
	for {
		n, err := ch.Read(buf)
		if n > 0 {
			s.mu.Lock()
			s.input = append(s.input, buf[:n]...)
			s.mu.Unlock()
			if i := slices.Index(buf[:n], quitKey); i >= 0 {
				s.echo(ch, buf[:i])
				break
			}
			s.echo(ch, buf[:n])
		}
		if err != nil {
			break
		}
	}
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
	_ = ch.Close()
}

func (s *Server) echo(ch ssh.Channel, p []byte) {
	if !s.opts.Silent && len(p) > 0 {
		_, _ = ch.Write(p)
	}
}
