package bmcssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"oob-manager/internal/secrets"
)

// Command is the only command this package ever runs on a BMC.
const Command = "console com2"

// QuitKey is the iDRAC serial console's escape key (Ctrl-\): it ends `console com2`.
const QuitKey byte = 0x1c

// Terminal size bounds and defaults (characters).
const (
	DefaultCols = 80
	DefaultRows = 24
	MinCols     = 20
	MaxCols     = 400
	MinRows     = 5
	MaxRows     = 200
	termType    = "xterm"
	// breakMillis is the RFC 4335 break length.
	breakMillis    = 500
	defaultTimeout = 10 * time.Second
)

// DialFunc opens a TCP connection; nil uses net.Dialer.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Config is one BMC's SSH endpoint and login, built from validated config and the
// secrets file.
type Config struct {
	ServerID string
	// Addr is the literal IP and port of the BMC's SSH service.
	Addr string
	// HostKey is the pinned host key as an authorized-key line (config ssh_host_key).
	HostKey  string
	Username string
	Password secrets.Secret
	// Legacy is the idrac8_legacy_ssh quirk.
	Legacy  bool
	Dial    DialFunc
	Timeout time.Duration // dial + SSH handshake + login + console start; default 10 s
}

// Size is a terminal size in characters.
type Size struct{ Cols, Rows int }

func (s Size) clamp() Size {
	if s.Cols == 0 {
		s.Cols = DefaultCols
	}
	if s.Rows == 0 {
		s.Rows = DefaultRows
	}
	return Size{Cols: min(max(s.Cols, MinCols), MaxCols), Rows: min(max(s.Rows, MinRows), MaxRows)}
}

// Session is one running `console com2`. Read returns the console output (stdout and
// stderr merged); Write sends keystrokes unchanged. It is safe to call Resize, Break,
// Quit and Close concurrently with Read and Write.
type Session struct {
	client *ssh.Client
	sess   *ssh.Session
	stdin  io.WriteCloser
	out    *io.PipeReader
	outW   *io.PipeWriter
	once   sync.Once
}

// Open connects, verifies the host key, logs in and starts `console com2` on a PTY of
// the given size (zero fields take 80x24). Nothing is sent to the BMC before the host
// key is verified: the password goes only to the pinned host.
func Open(ctx context.Context, c Config, size Size) (*Session, error) {
	key, err := c.validate()
	if err != nil {
		return nil, err
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client, err := connect(ctx, c, key)
	if err != nil {
		return nil, err
	}
	s, err := start(ctx, client, size.clamp())
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	return s, nil
}

func (c Config) validate() (ssh.PublicKey, error) {
	if c.HostKey == "" {
		return nil, fmt.Errorf("%w: no ssh_host_key for %s", ErrConfig, c.ServerID)
	}
	key, err := ParseHostKey(c.HostKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %w", ErrConfig, c.ServerID, err)
	}
	if c.Username == "" || c.Password.IsZero() {
		return nil, fmt.Errorf("%w: no operator login for %s", ErrConfig, c.ServerID)
	}
	return key, nil
}

// ParseHostKey parses an authorized-key line ("<algorithm> <base64> [comment]").
func ParseHostKey(line string) (ssh.PublicKey, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, errors.New("bmcssh: ssh_host_key is not a valid authorized-key line")
	}
	return key, nil
}

// connect dials and runs the SSH handshake and login, all bounded by ctx: the
// connection's deadline follows ctx so a BMC that never answers cannot hang it.
func connect(ctx context.Context, c Config, key ssh.PublicKey) (*ssh.Client, error) {
	dial := c.Dial
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	conn, err := dial(ctx, "tcp", c.Addr)
	if err != nil {
		return nil, fmt.Errorf("bmcssh: dial %s: %w", c.ServerID, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	sc, chans, reqs, err := ssh.NewClientConn(conn, c.Addr, clientConfig(c, key))
	if err != nil {
		_ = conn.Close()
		return nil, classifyHandshake(ctx, c.ServerID, err)
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(sc, chans, reqs), nil
}

func clientConfig(c Config, key ssh.PublicKey) *ssh.ClientConfig {
	a := algorithms(c.Legacy, key)
	pw := c.Password.Reveal()
	return &ssh.ClientConfig{
		Config: ssh.Config{KeyExchanges: a.KeyExchanges, Ciphers: a.Ciphers, MACs: a.MACs},
		User:   c.Username,
		Auth: []ssh.AuthMethod{ssh.Password(pw),
			ssh.KeyboardInteractive(func(_, _ string, questions []string, echos []bool) ([]string, error) {
				return answerPassword(pw, questions, echos)
			})},
		HostKeyCallback:   pinned(key),
		HostKeyAlgorithms: a.HostKeys,
		ClientVersion:     "SSH-2.0-oob-manager",
	}
}

// answerPassword answers a keyboard-interactive round only when it is a single hidden
// prompt (the BMC asking for the password); anything else gets no answer.
func answerPassword(pw string, questions []string, echos []bool) ([]string, error) {
	switch {
	case len(questions) == 0:
		return nil, nil
	case len(questions) == 1 && !echos[0]:
		return []string{pw}, nil
	default:
		return nil, errors.New("bmcssh: unexpected keyboard-interactive prompt")
	}
}

// start requests the PTY and runs Command. Stdout and stderr share one pipe.
func start(ctx context.Context, client *ssh.Client, size Size) (*Session, error) {
	type result struct {
		s   *Session
		err error
	}
	done := make(chan result, 1)
	go func() {
		s, err := startSession(client, size)
		done <- result{s, err}
	}()
	select {
	case r := <-done:
		return r.s, r.err
	case <-ctx.Done():
		_ = client.Close() // unblocks startSession
		<-done
		return nil, fmt.Errorf("bmcssh: console start: %w", ctx.Err())
	}
}

func startSession(client *ssh.Client, size Size) (*Session, error) {
	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("%w: session: %w", ErrRefused, err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("%w: stdin: %w", ErrRefused, err)
	}
	pr, pw := io.Pipe()
	sess.Stdout, sess.Stderr = pw, pw
	modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 115200, ssh.TTY_OP_OSPEED: 115200}
	if err = sess.RequestPty(termType, size.Rows, size.Cols, modes); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("%w: pty: %w", ErrRefused, err)
	}
	if err = sess.Start(Command); err != nil {
		_ = sess.Close()
		return nil, fmt.Errorf("%w: exec: %w", ErrRefused, err)
	}
	go func() { _ = pw.CloseWithError(waitErr(sess.Wait())) }()
	return &Session{client: client, sess: sess, stdin: stdin, out: pr, outW: pw}, nil
}

// waitErr: the console ending (exit status or channel close) is a normal EOF.
func waitErr(err error) error {
	var exit *ssh.ExitError
	var missing *ssh.ExitMissingError
	if err == nil || errors.As(err, &exit) || errors.As(err, &missing) {
		return io.EOF
	}
	return err
}

// Read returns console output.
func (s *Session) Read(p []byte) (int, error) { return s.out.Read(p) }

// Write sends keystrokes to the console.
func (s *Session) Write(p []byte) (int, error) { return s.stdin.Write(p) }

// Resize changes the PTY size (clamped to [MinCols, MaxCols] x [MinRows, MaxRows]).
func (s *Session) Resize(size Size) error {
	sz := size.clamp()
	return s.sess.WindowChange(sz.Rows, sz.Cols)
}

// Break sends an RFC 4335 break (a serial line break on the host's COM port, where the
// BMC supports it).
func (s *Session) Break() error {
	_, err := s.sess.SendRequest("break", false, ssh.Marshal(struct{ Millis uint32 }{breakMillis}))
	return err
}

// Quit sends the console's quit key so the BMC ends `console com2` cleanly, then closes.
func (s *Session) Quit() error {
	_, err := s.stdin.Write([]byte{QuitKey})
	return errors.Join(err, s.Close())
}

// Close ends the session and the connection. It is idempotent.
func (s *Session) Close() error {
	s.once.Do(func() {
		_ = s.stdin.Close()
		_ = s.sess.Close()
		_ = s.client.Close()
		_ = s.outW.CloseWithError(io.EOF)
	})
	return nil
}
