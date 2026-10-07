package smtp_test

import (
	"bufio"
	"encoding/base64"
	"io"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// spyBackend is an in-memory SMTP backend recording every backend invocation.
// It lets the acceptance tests prove that, after a failed AUTH with command
// isolation enabled, the Mail/Rcpt/Data backend methods are never reached.
type spyBackend struct {
	mu sync.Mutex

	newSessionCalls int
	authCalls       int
	mailCalls       int
	rcptCalls       int
	dataCalls       int
	resetCalls      int

	messages []*spyMessage
}

type spyMessage struct {
	from          string
	rcpts         []string
	data          []byte
	authenticated bool
}

func (b *spyBackend) NewSession(_ *smtp.Conn) (smtp.Session, error) {
	b.mu.Lock()
	b.newSessionCalls++
	b.mu.Unlock()
	return &spySession{backend: b}, nil
}

type spyCounters struct {
	newSession, auth, mail, rcpt, data, reset, messages int
}

func (b *spyBackend) snapshot() spyCounters {
	b.mu.Lock()
	defer b.mu.Unlock()
	return spyCounters{
		newSession: b.newSessionCalls,
		auth:       b.authCalls,
		mail:       b.mailCalls,
		rcpt:       b.rcptCalls,
		data:       b.dataCalls,
		reset:      b.resetCalls,
		messages:   len(b.messages),
	}
}

type spySession struct {
	backend *spyBackend

	authenticated bool
	msg           *spyMessage
}

var _ smtp.AuthSession = (*spySession)(nil)

func (s *spySession) AuthMechanisms() []string {
	return []string{sasl.Plain}
}

func (s *spySession) Auth(mech string) (sasl.Server, error) {
	s.backend.mu.Lock()
	s.backend.authCalls++
	s.backend.mu.Unlock()

	if mech != sasl.Plain {
		return nil, smtp.ErrAuthUnknownMechanism
	}
	return sasl.NewPlainServer(func(identity, username, password string) error {
		if identity != "" && identity != username {
			return smtp.ErrAuthFailed
		}
		if username != "username" || password != "password" {
			return smtp.ErrAuthFailed
		}
		s.authenticated = true
		return nil
	}), nil
}

func (s *spySession) Reset() {
	s.backend.mu.Lock()
	s.backend.resetCalls++
	s.backend.mu.Unlock()
	s.msg = &spyMessage{authenticated: s.authenticated}
}

func (s *spySession) Logout() error { return nil }

func (s *spySession) Mail(from string, _ *smtp.MailOptions) error {
	s.backend.mu.Lock()
	s.backend.mailCalls++
	s.backend.mu.Unlock()

	// MAIL opens a new transaction, whose authentication status is the
	// current session status (not the one captured by an earlier Reset).
	s.msg = &spyMessage{authenticated: s.authenticated, from: from}
	return nil
}

func (s *spySession) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.backend.mu.Lock()
	s.backend.rcptCalls++
	s.backend.mu.Unlock()

	if s.msg == nil {
		s.msg = &spyMessage{authenticated: s.authenticated}
	}
	s.msg.rcpts = append(s.msg.rcpts, to)
	return nil
}
func (s *spySession) Data(r io.Reader) error {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	s.backend.mu.Lock()
	defer s.backend.mu.Unlock()
	s.backend.dataCalls++
	if s.msg == nil {
		s.msg = &spyMessage{authenticated: s.authenticated}
	}
	s.msg.data = b
	// Keep an independent copy: the server calls Reset() right after Data,
	// which starts a fresh transaction on the session.
	stored := *s.msg
	stored.rcpts = append([]string(nil), s.msg.rcpts...)
	s.backend.messages = append(s.backend.messages, &stored)
	return nil
}

// --- small in-memory loopback protocol fixture ----------------------------

func newIsolationServer(t *testing.T, enable bool) (*spyBackend, *smtp.Server, net.Conn, *bufio.Scanner) {
	t.Helper()

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	be := new(spyBackend)
	srv := smtp.NewServer(be)
	srv.Domain = "localhost"
	srv.AllowInsecureAuth = true
	srv.EnableAuthFailureIsolation = enable

	go srv.Serve(l)

	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		l.Close()
		t.Fatal(err)
	}

	sc := bufio.NewScanner(c)
	if !sc.Scan() {
		t.Fatal("missing server greeting:", sc.Err())
	}
	if sc.Text() != "220 localhost ESMTP Service Ready" {
		t.Fatal("invalid greeting:", sc.Text())
	}
	return be, srv, c, sc
}

func sendLine(t *testing.T, c net.Conn, line string) {
	t.Helper()
	if _, err := io.WriteString(c, line+"\r\n"); err != nil {
		t.Fatalf("write %q: %v", line, err)
	}
}

func readCode(t *testing.T, sc *bufio.Scanner) string {
	t.Helper()
	if !sc.Scan() {
		t.Fatal("missing response:", sc.Err())
	}
	return sc.Text()
}

func expectCode(t *testing.T, sc *bufio.Scanner, prefix string) string {
	t.Helper()
	line := readCode(t, sc)
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("expected %q response, got %q", prefix, line)
	}
	return line
}

func ehlo(t *testing.T, c net.Conn, sc *bufio.Scanner) {
	t.Helper()
	sendLine(t, c, "EHLO localhost")
	line := expectCode(t, sc, "250")
	if !strings.HasPrefix(line, "250-") {
		t.Fatalf("invalid first EHLO response: %q", line)
	}
	for {
		line := readCode(t, sc)
		if strings.HasPrefix(line, "250 ") {
			return
		}
		if !strings.HasPrefix(line, "250-") {
			t.Fatalf("invalid EHLO capability line: %q", line)
		}
	}
}

func plainInitialResponse(creds string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + creds))
}

const (
	goodCreds = "username\x00password"
	badCreds  = "username\x00wrong"
)

// TestAuthFailureIsolation_Flow exercises the required acceptance sequence:
// a failing AUTH, a rejected MAIL (backend untouched), EHLO re-negotiation,
// a successful AUTH and a delivered message, and finally a repeat AUTH on the
// already authenticated session.
func TestAuthFailureIsolation_Flow(t *testing.T) {
	be, srv, c, sc := newIsolationServer(t, true)
	defer srv.Close()
	defer c.Close()

	ehlo(t, c, sc)

	// 1. AUTH fails: an exchange is started, but no mail transaction backend
	//    method is invoked and the temporary auth state is cleaned up.
	sendLine(t, c, "AUTH PLAIN "+plainInitialResponse(badCreds))
	expectCode(t, sc, "535")

	snap := be.snapshot()
	if snap.auth != 1 {
		t.Fatalf("expected 1 Auth() backend call, got %d", snap.auth)
	}
	if snap.mail != 0 || snap.rcpt != 0 || snap.data != 0 || snap.messages != 0 {
		t.Fatalf("no mail backend calls expected right after failed AUTH, got %+v", snap)
	}

	// 2. MAIL/RCPT/DATA are rejected before the backend is consulted.
	sendLine(t, c, "MAIL FROM:<bad@example.org>")
	expectCode(t, sc, "503")
	sendLine(t, c, "RCPT TO:<to@example.org>")
	expectCode(t, sc, "503")
	sendLine(t, c, "DATA")
	expectCode(t, sc, "503")
	snap = be.snapshot()
	if snap.mail != 0 || snap.rcpt != 0 || snap.data != 0 {
		t.Fatalf("backend Mail/Rcpt/Data must not be called while isolated, got %+v", snap)
	}

	// A repeat AUTH without re-negotiation is also rejected and must not
	// create a new backend SASL exchange.
	sendLine(t, c, "AUTH PLAIN "+plainInitialResponse(goodCreds))
	expectCode(t, sc, "503")
	if got := be.snapshot().auth; got != 1 {
		t.Fatalf("isolated AUTH must not reach the backend, got %d Auth calls", got)
	}

	// 3. EHLO clears the isolation state and allows re-negotiation.
	ehlo(t, c, sc)

	// 4. Legitimate authentication now succeeds.
	sendLine(t, c, "AUTH PLAIN "+plainInitialResponse(goodCreds))
	expectCode(t, sc, "235")

	// 5. Authenticated mail transaction is delivered through the backend.
	sendLine(t, c, "MAIL FROM:<good@example.org>")
	expectCode(t, sc, "250")
	sendLine(t, c, "RCPT TO:<to@example.org>")
	expectCode(t, sc, "250")
	sendLine(t, c, "DATA")
	expectCode(t, sc, "354")
	sendLine(t, c, "hello isolation")
	sendLine(t, c, ".")
	expectCode(t, sc, "250")

	snap = be.snapshot()
	if snap.mail != 1 || snap.rcpt != 1 || snap.data != 1 || snap.messages != 1 {
		t.Fatalf("expected one delivered authenticated message, got %+v", snap)
	}
	if !be.messages[0].authenticated {
		t.Fatal("message should have been accepted on an authenticated session")
	}
	if got := string(be.messages[0].data); got != "hello isolation\r\n" {
		t.Fatalf("unexpected message data: %q", got)
	}

	// 6. Repeat AUTH on the authenticated session is rejected with 503 and
	//    the authenticated state is preserved (no silent downgrade).
	sendLine(t, c, "AUTH PLAIN "+plainInitialResponse(goodCreds))
	expectCode(t, sc, "503")
	if got := be.snapshot().auth; got != 2 {
		t.Fatalf("repeat AUTH should not create a new exchange, got %d Auth calls", got)
	}

	sendLine(t, c, "MAIL FROM:<good@example.org>")
	expectCode(t, sc, "250")
	sendLine(t, c, "RCPT TO:<to@example.org>")
	expectCode(t, sc, "250")
	sendLine(t, c, "DATA")
	expectCode(t, sc, "354")
	sendLine(t, c, "still authenticated")
	sendLine(t, c, ".")
	expectCode(t, sc, "250")
	snap = be.snapshot()
	if snap.messages != 2 || !be.messages[1].authenticated {
		t.Fatalf("authenticated session must survive a rejected repeat AUTH: %+v", snap)
	}
}

// TestAuthFailureIsolation_NoDowngrade proves that a failing AUTH after a
// successful one does not silently downgrade the established authenticated
// session and does not invoke the backend again.
func TestAuthFailureIsolation_NoDowngrade(t *testing.T) {
	be, srv, c, sc := newIsolationServer(t, true)
	defer srv.Close()
	defer c.Close()

	ehlo(t, c, sc)

	sendLine(t, c, "AUTH PLAIN "+plainInitialResponse(goodCreds))
	expectCode(t, sc, "235")
	authAfterSuccess := be.snapshot().auth

	// Another (bad) AUTH on the authenticated session is refused before a new
	// SASL exchange is created.
	sendLine(t, c, "AUTH PLAIN "+plainInitialResponse(badCreds))
	expectCode(t, sc, "503")

	snap := be.snapshot()
	if snap.auth != authAfterSuccess {
		t.Fatalf("failed repeat AUTH must not invoke backend Auth: %d != %d", snap.auth, authAfterSuccess)
	}

	// The authenticated session continues to accept mail: it was not
	// downgraded into the isolation state.
	sendLine(t, c, "MAIL FROM:<good@example.org>")
	expectCode(t, sc, "250")
	sendLine(t, c, "RCPT TO:<to@example.org>")
	expectCode(t, sc, "250")
	sendLine(t, c, "DATA")
	expectCode(t, sc, "354")
	sendLine(t, c, "downgrade check")
	sendLine(t, c, ".")
	expectCode(t, sc, "250")

	snap = be.snapshot()
	if snap.messages != 1 || !be.messages[0].authenticated {
		t.Fatalf("authenticated session was downgraded by a failed repeat AUTH: %+v", snap)
	}
}

// TestAuthFailureIsolation_RsetRecovery shows that RSET also clears the
// isolation state defined by RFC 4954 section 4.
func TestAuthFailureIsolation_RsetRecovery(t *testing.T) {
	be, srv, c, sc := newIsolationServer(t, true)
	defer srv.Close()
	defer c.Close()

	ehlo(t, c, sc)

	sendLine(t, c, "AUTH PLAIN "+plainInitialResponse(badCreds))
	expectCode(t, sc, "535")

	sendLine(t, c, "MAIL FROM:<bad@example.org>")
	expectCode(t, sc, "503")

	sendLine(t, c, "RSET")
	expectCode(t, sc, "250")

	sendLine(t, c, "AUTH PLAIN "+plainInitialResponse(goodCreds))
	expectCode(t, sc, "235")

	if snap := be.snapshot(); snap.auth != 2 {
		t.Fatalf("expected two backend Auth calls after RSET recovery, got %d", snap.auth)
	}
}

// TestAuthFailureIsolation_CancelAndMalformed covers the "*" cancellation and
// malformed base64 continuation paths, both entering isolation.
func TestAuthFailureIsolation_CancelAndMalformed(t *testing.T) {
	be, srv, c, sc := newIsolationServer(t, true)
	defer srv.Close()
	defer c.Close()

	ehlo(t, c, sc)

	// Cancelled negotiation.
	sendLine(t, c, "AUTH PLAIN")
	expectCode(t, sc, "334")
	sendLine(t, c, "*")
	expectCode(t, sc, "501")
	sendLine(t, c, "MAIL FROM:<bad@example.org>")
	expectCode(t, sc, "503")

	ehlo(t, c, sc)

	// Malformed base64 in the continuation.
	sendLine(t, c, "AUTH PLAIN")
	expectCode(t, sc, "334")
	sendLine(t, c, "!!!not-base64!!!")
	expectCode(t, sc, "454")
	sendLine(t, c, "MAIL FROM:<bad@example.org>")
	expectCode(t, sc, "503")

	if snap := be.snapshot(); snap.mail != 0 {
		t.Fatalf("Mail backend must never be called, got %d calls", snap.mail)
	}
}

// TestAuthFailureIsolation_DefaultLegacyInterface is the default-interface
// regression: with the option left disabled, a failed AUTH does not isolate
// commands and an anonymous MAIL transaction still reaches the backend.
func TestAuthFailureIsolation_DefaultLegacyInterface(t *testing.T) {
	be, srv, c, sc := newIsolationServer(t, false)
	defer srv.Close()
	defer c.Close()

	ehlo(t, c, sc)

	sendLine(t, c, "AUTH PLAIN "+plainInitialResponse(badCreds))
	expectCode(t, sc, "535")

	// Historical behavior: MAIL is still accepted without re-negotiation and
	// reaches the backend as an anonymous transaction.
	sendLine(t, c, "MAIL FROM:<anon@example.org>")
	expectCode(t, sc, "250")
	sendLine(t, c, "RCPT TO:<to@example.org>")
	expectCode(t, sc, "250")
	sendLine(t, c, "DATA")
	expectCode(t, sc, "354")
	sendLine(t, c, "legacy body")
	sendLine(t, c, ".")
	expectCode(t, sc, "250")

	snap := be.snapshot()
	if snap.mail != 1 || snap.rcpt != 1 || snap.data != 1 || snap.messages != 1 {
		t.Fatalf("legacy default interface behavior changed: %+v", snap)
	}
	if be.messages[0].authenticated {
		t.Fatal("legacy transaction should remain anonymous after failed AUTH")
	}

	// Re-negotiation followed by a successful AUTH keeps working.
	ehlo(t, c, sc)
	sendLine(t, c, "AUTH PLAIN "+plainInitialResponse(goodCreds))
	expectCode(t, sc, "235")
}

// TestAuthFailureIsolation_TransactionDiscarded verifies that an in-progress
// transaction (a MAIL issued anonymously) is explicitly discarded when the
// subsequent AUTH fails: no Data backend call is ever made, the backend
// Reset runs, and after EHLO + successful AUTH a fresh transaction works.
func TestAuthFailureIsolation_TransactionDiscarded(t *testing.T) {
	be, srv, c, sc := newIsolationServer(t, true)
	defer srv.Close()
	defer c.Close()

	ehlo(t, c, sc)

	// An anonymous MAIL starts (but does not finish) a transaction.
	sendLine(t, c, "MAIL FROM:<anon@example.org>")
	expectCode(t, sc, "250")
	sendLine(t, c, "RCPT TO:<to@example.org>")
	expectCode(t, sc, "250")

	// AUTH PLAIN with bad credentials mid-transaction.
	sendLine(t, c, "AUTH PLAIN "+plainInitialResponse(badCreds))
	expectCode(t, sc, "535")

	// The failed AUTH must have discarded the in-progress transaction:
	// DATA is isolated and the backend never sees the message.
	sendLine(t, c, "DATA")
	expectCode(t, sc, "503")

	snap := be.snapshot()
	if snap.data != 0 || snap.messages != 0 {
		t.Fatalf("failed AUTH must discard the in-progress transaction, got %+v", snap)
	}
	if snap.reset == 0 {
		t.Fatal("backend Reset must be invoked as the explicit transaction cleanup")
	}

	// Re-negotiate, authenticate and complete a fresh transaction.
	ehlo(t, c, sc)
	sendLine(t, c, "AUTH PLAIN "+plainInitialResponse(goodCreds))
	expectCode(t, sc, "235")
	sendLine(t, c, "MAIL FROM:<good@example.org>")
	expectCode(t, sc, "250")
	sendLine(t, c, "RCPT TO:<to@example.org>")
	expectCode(t, sc, "250")
	sendLine(t, c, "DATA")
	expectCode(t, sc, "354")
	sendLine(t, c, "fresh after cleanup")
	sendLine(t, c, ".")
	expectCode(t, sc, "250")

	snap = be.snapshot()
	if snap.messages != 1 || !be.messages[0].authenticated {
		t.Fatalf("expected one authenticated message after cleanup, got %+v", snap)
	}
}
