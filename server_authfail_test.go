package smtp_test

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// In-memory spy backend used to verify which backend methods the server
// invokes (and in which order) around failed/successful AUTH commands.

type authSpyMessage struct {
	from string
	to   []string
	auth bool // whether the session was authenticated when MAIL was issued
}

type authSpyBackend struct {
	sessions []*authSpySession
}

func (be *authSpyBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	s := &authSpySession{backend: be}
	be.sessions = append(be.sessions, s)
	return s, nil
}

type authSpySession struct {
	backend *authSpyBackend

	authenticated bool

	authCalls int // Auth(mech) invocations, i.e. SASL rounds started
	resets    int // Session.Reset invocations (transaction cleanups)
	mails     int // Session.Mail invocations
	rcpts     int // Session.Rcpt invocations

	msgs []*authSpyMessage
	cur  *authSpyMessage
}

var _ smtp.AuthSession = (*authSpySession)(nil)

func (s *authSpySession) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

func (s *authSpySession) Auth(mech string) (sasl.Server, error) {
	s.authCalls++
	return sasl.NewPlainServer(func(identity, username, password string) error {
		if identity != "" && identity != username {
			return errors.New("Invalid identity")
		}
		if username != "username" || password != "password" {
			return errors.New("Invalid username or password")
		}
		s.authenticated = true
		return nil
	}), nil
}

func (s *authSpySession) Reset() {
	s.resets++
	s.cur = nil
}

func (s *authSpySession) Logout() error {
	return nil
}

func (s *authSpySession) Mail(from string, opts *smtp.MailOptions) error {
	s.mails++
	s.cur = &authSpyMessage{from: from, auth: s.authenticated}
	s.msgs = append(s.msgs, s.cur)
	return nil
}

func (s *authSpySession) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.rcpts++
	if s.cur != nil {
		s.cur.to = append(s.cur.to, to)
	}
	return nil
}

func (s *authSpySession) Data(r io.Reader) error {
	_, err := io.Copy(io.Discard, r)
	return err
}

// Protocol fixture helpers.

var goodAuthIR = base64.StdEncoding.EncodeToString([]byte("\x00username\x00password"))
var badAuthIR = base64.StdEncoding.EncodeToString([]byte("\x00username\x00wrongpass"))

func authTestServer(t *testing.T, authFailureReset bool) (be *authSpyBackend, s *smtp.Server, c net.Conn, scanner *bufio.Scanner) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	be = new(authSpyBackend)
	s = smtp.NewServer(be)
	s.Domain = "localhost"
	s.AllowInsecureAuth = true
	s.AuthFailureReset = authFailureReset

	go s.Serve(l)
	t.Cleanup(func() { s.Close() })

	c, err = net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	scanner = bufio.NewScanner(c)

	scanner.Scan()
	if scanner.Text() != "220 localhost ESMTP Service Ready" {
		t.Fatal("Invalid greeting:", scanner.Text())
	}
	return
}

// sendCmd writes one command and expects a single-line reply with the
// given status code prefix, returning the reply text.
func sendCmd(t *testing.T, c net.Conn, scanner *bufio.Scanner, prefix, cmd string) string {
	t.Helper()
	io.WriteString(c, cmd+"\r\n")
	if !scanner.Scan() {
		t.Fatalf("No reply for %q", cmd)
	}
	reply := scanner.Text()
	if !strings.HasPrefix(reply, prefix) {
		t.Fatalf("Invalid reply for %q: %q (want prefix %q)", cmd, reply, prefix)
	}
	return reply
}

// sendEhlo issues EHLO and consumes the multi-line reply, returning the
// advertised capabilities.
func sendEhlo(t *testing.T, c net.Conn, scanner *bufio.Scanner) map[string]bool {
	t.Helper()
	io.WriteString(c, "EHLO localhost\r\n")

	caps := make(map[string]bool)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "250-") {
			caps[strings.TrimPrefix(line, "250-")] = true
		} else if strings.HasPrefix(line, "250 ") {
			caps[strings.TrimPrefix(line, "250 ")] = true
			break
		} else {
			t.Fatal("Invalid EHLO reply:", line)
		}
	}
	return caps
}

// Acceptance sequence: AUTH failure -> MAIL/RCPT -> EHLO renegotiation ->
// valid AUTH. The spy verifies backend calls and replies at each step.
func TestServerAuthFailureIsolation(t *testing.T) {
	be, _, c, scanner := authTestServer(t, true)

	caps := sendEhlo(t, c, scanner)
	if !caps["AUTH PLAIN"] {
		t.Fatal("AUTH PLAIN capability missing")
	}
	if len(be.sessions) != 1 {
		t.Fatal("Expected exactly one session")
	}
	sess := be.sessions[0]

	// 1. Failed AUTH: rejected, and no Mail/Rcpt backend call may have
	//    happened before or during the failure.
	sendCmd(t, c, scanner, "454 ", "AUTH PLAIN "+badAuthIR)
	if sess.authCalls != 1 {
		t.Fatal("Expected 1 SASL round, got:", sess.authCalls)
	}
	if sess.mails != 0 || sess.rcpts != 0 {
		t.Fatalf("Mail/Rcpt backend called before failed AUTH completed: mails=%d rcpts=%d", sess.mails, sess.rcpts)
	}
	if sess.authenticated {
		t.Fatal("Session must not be authenticated after failed AUTH")
	}
	if sess.resets != 1 {
		t.Fatal("Failed AUTH must trigger exactly one transaction cleanup, got:", sess.resets)
	}

	// 2. MAIL/RCPT after the failure work on a clean transaction.
	sendCmd(t, c, scanner, "250 ", "MAIL FROM:<alice@example.org>")
	sendCmd(t, c, scanner, "250 ", "RCPT TO:<bob@example.org>")
	if sess.mails != 1 || sess.rcpts != 1 {
		t.Fatalf("Expected 1 Mail and 1 Rcpt call, got mails=%d rcpts=%d", sess.mails, sess.rcpts)
	}
	if sess.msgs[0].auth {
		t.Fatal("Message sent before authentication must be recorded as anonymous")
	}

	// 3. EHLO re-negotiation is still possible after the failed AUTH.
	caps = sendEhlo(t, c, scanner)
	if !caps["AUTH PLAIN"] {
		t.Fatal("AUTH PLAIN capability missing after re-EHLO")
	}
	if sess.resets != 2 {
		t.Fatal("EHLO must reset the transaction, expected 2 resets, got:", sess.resets)
	}

	// 4. Valid AUTH succeeds on the renegotiated session.
	sendCmd(t, c, scanner, "235 ", "AUTH PLAIN "+goodAuthIR)
	if !sess.authenticated {
		t.Fatal("Session must be authenticated after valid AUTH")
	}
	if sess.authCalls != 2 {
		t.Fatal("Expected 2 SASL rounds, got:", sess.authCalls)
	}

	// 5. A new message is now recorded as authenticated.
	sendCmd(t, c, scanner, "250 ", "MAIL FROM:<alice@example.org>")
	if !sess.msgs[1].auth {
		t.Fatal("Message sent after authentication must be recorded as authenticated")
	}
}

// An authenticated session must not be silently downgraded by another
// (failing) AUTH attempt.
func TestServerAuthFailureNoDowngrade(t *testing.T) {
	be, _, c, scanner := authTestServer(t, true)

	sendEhlo(t, c, scanner)
	sess := be.sessions[0]

	sendCmd(t, c, scanner, "235 ", "AUTH PLAIN "+goodAuthIR)
	if !sess.authenticated {
		t.Fatal("Session must be authenticated")
	}

	sendCmd(t, c, scanner, "250 ", "MAIL FROM:<alice@example.org>")
	resetsBefore := sess.resets
	authCallsBefore := sess.authCalls

	// Repeated AUTH attempts (failing credentials and valid ones) are
	// rejected with 503 before any backend or cleanup interaction.
	sendCmd(t, c, scanner, "503 ", "AUTH PLAIN "+badAuthIR)
	sendCmd(t, c, scanner, "503 ", "AUTH PLAIN "+goodAuthIR)

	if sess.authCalls != authCallsBefore {
		t.Fatal("Repeated AUTH must not start a new SASL round")
	}
	if sess.resets != resetsBefore {
		t.Fatal("Repeated AUTH must not reset the transaction of an authenticated session")
	}
	if !sess.authenticated {
		t.Fatal("Authenticated session was downgraded by repeated AUTH")
	}

	// The session is still fully usable and authenticated.
	sendCmd(t, c, scanner, "250 ", "MAIL FROM:<alice@example.org>")
	if !sess.msgs[len(sess.msgs)-1].auth {
		t.Fatal("Message after repeated AUTH must still be recorded as authenticated")
	}
}

// With the option disabled (default), the historical interface behavior
// is preserved: no transaction cleanup on failure, and the original
// command flow keeps working.
func TestServerAuthFailureDefaultUnchanged(t *testing.T) {
	be, _, c, scanner := authTestServer(t, false)

	sendEhlo(t, c, scanner)
	sess := be.sessions[0]

	sendCmd(t, c, scanner, "454 ", "AUTH PLAIN "+badAuthIR)
	if sess.resets != 0 {
		t.Fatal("No transaction cleanup must happen when AuthFailureReset is disabled, got:", sess.resets)
	}
	if sess.mails != 0 || sess.rcpts != 0 {
		t.Fatal("Mail/Rcpt backend must not be called by failed AUTH")
	}

	// Original flow still works: MAIL is accepted and AUTH can be retried.
	sendCmd(t, c, scanner, "250 ", "MAIL FROM:<alice@example.org>")
	sendCmd(t, c, scanner, "235 ", "AUTH PLAIN "+goodAuthIR)
	if !sess.authenticated {
		t.Fatal("Session must be authenticated after valid AUTH retry")
	}
}
