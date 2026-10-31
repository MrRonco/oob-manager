package notify

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// buildEmail renders an RFC 5322 message: plain text, UTF-8, quoted-printable. Every
// header value is a fixed string or one line without control characters.
func buildEmail(t Target, e Event, now time.Time) ([]byte, error) {
	var b bytes.Buffer
	host := t.EmailFrom[strings.LastIndexByte(t.EmailFrom, '@')+1:]
	hdr := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	hdr("From", t.EmailFrom)
	hdr("To", strings.Join(t.EmailTo, ", "))
	hdr("Subject", mime.QEncoding.Encode("utf-8", clip(oneLine(e.Title), 200)))
	hdr("Date", now.UTC().Format(time.RFC1123Z))
	hdr("Message-ID", "<"+messageID()+"@"+host+">")
	hdr("MIME-Version", "1.0")
	hdr("Content-Type", "text/plain; charset=utf-8")
	hdr("Content-Transfer-Encoding", "quoted-printable")
	hdr("Auto-Submitted", "auto-generated")
	hdr("X-OOB-Event", string(e.Class))
	b.WriteString("\r\n")
	qp := quotedprintable.NewWriter(&b)
	text := strings.ReplaceAll(body(e), "\n", "\r\n") + "\r\n\r\n-- \r\noob-manager\r\n"
	if _, err := qp.Write([]byte(text)); err != nil {
		return nil, fmt.Errorf("notify: email: %w", err)
	}
	if err := qp.Close(); err != nil {
		return nil, fmt.Errorf("notify: email: %w", err)
	}
	return b.Bytes(), nil
}

func messageID() string {
	var r [12]byte
	_, _ = rand.Read(r[:])
	return hex.EncodeToString(r[:])
}

// sendEmail delivers msg through the target's SMTP server. STARTTLS is required when
// configured (a server that does not offer it is a failure, never a silent downgrade);
// implicit TLS wraps the connection first; plaintext is LAN-only and never
// authenticates.
func (t Transport) sendEmail(ctx context.Context, tg Target, sec Secrets, msg []byte) error {
	t = t.withDefaults()
	host, port, err := smtpHostPort(tg.URL)
	if err != nil {
		return failed(classBlocked, false, "notify: bad SMTP server")
	}
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()
	conn, err := t.dialChecked(ctx, net.JoinHostPort(host, port), tg.EmailSecurity == EmailNone)
	if err != nil {
		return err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	if tg.EmailSecurity == EmailTLS {
		tc := tls.Client(conn, t.tlsConfig(host))
		if err := tc.HandshakeContext(ctx); err != nil {
			return err
		}
		conn = tc
	}
	return t.smtpSession(conn, host, tg, sec, msg)
}

func (t Transport) smtpSession(conn net.Conn, host string, tg Target, sec Secrets, msg []byte) error {
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		return smtpFailure(err)
	}
	defer c.Close()
	if err := c.Hello("oob-manager"); err != nil {
		return smtpFailure(err)
	}
	if tg.EmailSecurity == EmailSTARTTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return failed(classTLS, false, "notify: SMTP server does not offer STARTTLS")
		}
		if err := c.StartTLS(t.tlsConfig(host)); err != nil {
			return err
		}
	}
	if err := smtpAuth(c, host, tg, sec); err != nil {
		return err
	}
	if err := smtpSend(c, tg, msg); err != nil {
		return err
	}
	return smtpFailure(c.Quit())
}

func smtpAuth(c *smtp.Client, host string, tg Target, sec Secrets) error {
	if sec.User.IsZero() {
		return nil
	}
	if _, tlsOn := c.TLSConnectionState(); !tlsOn || tg.EmailSecurity == EmailNone {
		return failed(classTLS, false, "notify: SMTP authentication needs TLS")
	}
	if ok, _ := c.Extension("AUTH"); !ok {
		return failed(classSMTP, false, "notify: SMTP server does not offer AUTH")
	}
	return smtpFailure(c.Auth(smtp.PlainAuth("", sec.User.Reveal(), sec.Password.Reveal(), host)))
}

func smtpSend(c *smtp.Client, tg Target, msg []byte) error {
	if err := c.Mail(tg.EmailFrom); err != nil {
		return smtpFailure(err)
	}
	for _, to := range tg.EmailTo {
		if err := c.Rcpt(to); err != nil {
			return smtpFailure(err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return smtpFailure(err)
	}
	if _, err := w.Write(msg); err != nil {
		return smtpFailure(err)
	}
	return smtpFailure(w.Close())
}

// smtpFailure classifies an SMTP reply: 4xx is temporary (retry), 5xx permanent. The
// server's text is not kept (it can echo addresses).
func smtpFailure(err error) error {
	if err == nil {
		return nil
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return err
	}
	msg := err.Error()
	if len(msg) >= 3 && msg[0] == '4' {
		return failed(classSMTP, true, "notify: SMTP temporary failure (%s)", msg[:3])
	}
	if len(msg) >= 3 && msg[0] == '5' {
		return failed(classSMTP, false, "notify: SMTP refused (%s)", msg[:3])
	}
	return failed(classSMTP, true, "notify: SMTP protocol error")
}
