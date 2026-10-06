package smtp_test

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// txnBackend is a test backend that rejects specific recipients and records
// the state of each session.
type txnBackend struct {
	mu       sync.Mutex
	sessions []*txnSession
	rcptErr  map[string]error
}

func newTxnBackend() *txnBackend {
	return &txnBackend{rcptErr: make(map[string]error)}
}

func (be *txnBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	s := &txnSession{be: be}
	be.mu.Lock()
	be.sessions = append(be.sessions, s)
	be.mu.Unlock()
	return s, nil
}

func (be *txnBackend) sessionAt(i int) *txnSession {
	be.mu.Lock()
	defer be.mu.Unlock()
	if i < 0 || i >= len(be.sessions) {
		return nil
	}
	return be.sessions[i]
}

// txnSession records every backend call so the test can verify that the
// server only invokes the backend at valid transaction phases.
type txnSession struct {
	be *txnBackend

	mu          sync.Mutex
	from        string
	recipients  []string
	data        []byte
	resetCount  int
	logoutCount int
	dataCount   int
}

var _ smtp.AuthSession = (*txnSession)(nil)

func (s *txnSession) AuthMechanisms() []string { return []string{sasl.Plain} }

func (s *txnSession) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		if username == "user" && password == "pass" {
			return nil
		}
		return errors.New("invalid credentials")
	}), nil
}

func (s *txnSession) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetCount++
	s.from = ""
	s.recipients = nil
}

func (s *txnSession) Logout() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logoutCount++
	return nil
}

func (s *txnSession) Mail(from string, opts *smtp.MailOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.from = from
	return nil
}

func (s *txnSession) Rcpt(to string, opts *smtp.RcptOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.be.rcptErr[to]; err != nil {
		return err
	}
	s.recipients = append(s.recipients, to)
	return nil
}

func (s *txnSession) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data = b
	s.dataCount++
	return nil
}

// pipeListener is an in-memory listener that accepts net.Pipe connections,
// avoiding any real TCP socket.
type pipeListener struct {
	connCh chan net.Conn
	addr   net.Addr
	closed chan struct{}
	once   sync.Once
}

func newPipeListener(addr net.Addr) *pipeListener {
	return &pipeListener{
		connCh: make(chan net.Conn, 8),
		addr:   addr,
		closed: make(chan struct{}),
	}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.connCh:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return l.addr }

func newPipeServer(t *testing.T, be smtp.Backend) (*smtp.Server, *pipeListener) {
	t.Helper()
	l := newPipeListener(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1})
	srv := smtp.NewServer(be)
	srv.Domain = "localhost"
	srv.AllowInsecureAuth = true
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return srv, l
}

func pipeConn(t *testing.T, l *pipeListener) (net.Conn, *bufio.Scanner) {
	t.Helper()
	client, server := net.Pipe()
	t.Cleanup(func() { client.Close() })
	l.connCh <- server
	return client, bufio.NewScanner(client)
}

// readResponse reads a complete SMTP reply, handling multi-line responses.
func readResponse(t *testing.T, scanner *bufio.Scanner) (int, string) {
	t.Helper()
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) < 4 {
			t.Fatalf("malformed SMTP response: %q", line)
		}
		code, err := strconv.Atoi(line[:3])
		if err != nil {
			t.Fatalf("non-numeric SMTP code in: %q", line)
		}
		if line[3] == '-' {
			continue // multi-line reply
		}
		return code, line[4:]
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("reading SMTP response: %v", err)
	}
	t.Fatal("unexpected end of SMTP response")
	return 0, ""
}

// cmd writes a command and returns the reply code and text.
func cmd(t *testing.T, w io.Writer, scanner *bufio.Scanner, format string, args ...interface{}) (int, string) {
	t.Helper()
	if _, err := io.WriteString(w, fmt.Sprintf(format, args...)); err != nil {
		t.Fatal(err)
	}
	return readResponse(t, scanner)
}

// TestTransactionStateGate exercises the full command sequence: a rejected
// RCPT does not pollute the accepted recipients, DATA only delivers accepted
// items, RSET clears the transaction without losing auth, and stage errors
// use the real 503 reply code.
func TestTransactionStateGate(t *testing.T) {
	be := newTxnBackend()
	be.rcptErr["reject@example.com"] = &smtp.SMTPError{
		Code:         550,
		EnhancedCode: smtp.EnhancedCode{5, 1, 1},
		Message:      "User unknown",
	}

	_, l := newPipeServer(t, be)
	client, scanner := pipeConn(t, l)

	// Greeting
	if code, _ := readResponse(t, scanner); code != 220 {
		t.Fatalf("greeting: got %d, want 220", code)
	}

	// EHLO
	if code, _ := cmd(t, client, scanner, "EHLO localhost\r\n"); code != 250 {
		t.Fatalf("EHLO: got %d, want 250", code)
	}

	// AUTH PLAIN
	if code, _ := cmd(t, client, scanner, "AUTH PLAIN\r\n"); code != 334 {
		t.Fatalf("AUTH: got %d, want 334", code)
	}
	if code, _ := cmd(t, client, scanner, "AHVzZXIAcGFzcw==\r\n"); code != 235 {
		t.Fatalf("AUTH creds: got %d, want 235", code)
	}

	// MAIL FROM
	if code, _ := cmd(t, client, scanner, "MAIL FROM:<sender@example.com>\r\n"); code != 250 {
		t.Fatalf("MAIL: got %d, want 250", code)
	}

	// One RCPT rejected, one accepted.
	if code, _ := cmd(t, client, scanner, "RCPT TO:<reject@example.com>\r\n"); code != 550 {
		t.Fatalf("RCPT reject: got %d, want 550", code)
	}
	if code, _ := cmd(t, client, scanner, "RCPT TO:<accept@example.com>\r\n"); code != 250 {
		t.Fatalf("RCPT accept: got %d, want 250", code)
	}

	// DATA: only the accepted recipient is delivered.
	if code, _ := cmd(t, client, scanner, "DATA\r\n"); code != 354 {
		t.Fatalf("DATA: got %d, want 354", code)
	}
	io.WriteString(client, "Subject: hello\r\n\r\nbody\r\n.\r\n")
	if code, _ := readResponse(t, scanner); code != 250 {
		t.Fatalf("DATA content: got %d, want 250", code)
	}

	sess := be.sessionAt(0)
	if sess == nil {
		t.Fatal("no session created")
	}
	sess.mu.Lock()
	if got := sess.recipients; len(got) != 1 || got[0] != "accept@example.com" {
		sess.mu.Unlock()
		t.Fatalf("DATA recipients: got %v, want [accept@example.com]", got)
	}
	if got := string(sess.data); got != "Subject: hello\r\n\r\nbody\r\n" {
		sess.mu.Unlock()
		t.Fatalf("DATA content: got %q", got)
	}
	sess.mu.Unlock()

	// RSET clears the transaction...
	if code, _ := cmd(t, client, scanner, "RSET\r\n"); code != 250 {
		t.Fatalf("RSET: got %d, want 250", code)
	}

	// ...new transaction has no old recipients: DATA without RCPT is rejected.
	if code, _ := cmd(t, client, scanner, "MAIL FROM:<sender@example.com>\r\n"); code != 250 {
		t.Fatalf("MAIL after RSET: got %d, want 250", code)
	}
	if code, msg := cmd(t, client, scanner, "DATA\r\n"); code != 503 {
		t.Fatalf("DATA after RSET (no RCPT): got %d %q, want 503 5.5.1", code, msg)
	} else if !strings.HasPrefix(msg, "5.5.1") {
		t.Fatalf("DATA after RSET: got %q, want enhanced code 5.5.1", msg)
	}

	// ...but authentication state is preserved: AUTH again is rejected.
	if code, _ := cmd(t, client, scanner, "AUTH PLAIN\r\n"); code != 503 {
		t.Fatalf("AUTH after RSET: got %d, want 503 (already authenticated)", code)
	}

	// Duplicate MAIL (transaction already in progress) is rejected.
	if code, _ := cmd(t, client, scanner, "MAIL FROM:<other@example.com>\r\n"); code != 503 {
		t.Fatalf("duplicate MAIL: got %d, want 503", code)
	}

	// Record the reset count before disconnecting. Both DATA completion and
	// RSET call Reset, so the count is 2 here.
	sess.mu.Lock()
	resetBeforeQuit := sess.resetCount
	sess.mu.Unlock()

	// QUIT: disconnect only logs out, does not reset again.
	if code, _ := cmd(t, client, scanner, "QUIT\r\n"); code != 221 {
		t.Fatalf("QUIT: got %d, want 221", code)
	}
	// Wait for the server to close the connection after QUIT so that the
	// Logout call has completed before we inspect the session.
	for scanner.Scan() {
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	sess.mu.Lock()
	resetAfterQuit := sess.resetCount
	logoutCount := sess.logoutCount
	sess.mu.Unlock()
	if resetAfterQuit != resetBeforeQuit {
		t.Fatalf("Reset count changed on disconnect: got %d, want %d (disconnect must not call Reset)", resetAfterQuit, resetBeforeQuit)
	}
	if logoutCount != 1 {
		t.Fatalf("Logout count: got %d, want 1 (disconnect)", logoutCount)
	}
}

// TestTransactionStageErrors verifies that commands issued at the wrong
// phase use the real 503 reply code and that the backend is never called
// out of phase.
func TestTransactionStageErrors(t *testing.T) {
	be := newTxnBackend()
	_, l := newPipeServer(t, be)
	client, scanner := pipeConn(t, l)

	readResponse(t, scanner) // greeting

	// MAIL before EHLO -> 503
	if code, msg := cmd(t, client, scanner, "MAIL FROM:<a@b.com>\r\n"); code != 503 {
		t.Fatalf("MAIL before EHLO: got %d %q, want 503", code, msg)
	}

	cmd(t, client, scanner, "EHLO localhost\r\n")

	// RCPT before MAIL -> 503
	if code, msg := cmd(t, client, scanner, "RCPT TO:<a@b.com>\r\n"); code != 503 {
		t.Fatalf("RCPT before MAIL: got %d %q, want 503", code, msg)
	}

	// DATA before RCPT -> 503
	if code, msg := cmd(t, client, scanner, "DATA\r\n"); code != 503 {
		t.Fatalf("DATA before RCPT: got %d %q, want 503", code, msg)
	}

	// Backend must not have been called for the out-of-phase commands.
	sess := be.sessionAt(0)
	if sess == nil {
		t.Fatal("no session created")
	}
	sess.mu.Lock()
	if sess.from != "" || len(sess.recipients) != 0 || sess.dataCount != 0 {
		sess.mu.Unlock()
		t.Fatalf("backend called out of phase: from=%q recipients=%v data=%d", sess.from, sess.recipients, sess.dataCount)
	}
	sess.mu.Unlock()
}

// TestTransactionAllRcptsRejected verifies that when every RCPT is rejected,
// DATA is rejected too (no accepted recipients to deliver to).
func TestTransactionAllRcptsRejected(t *testing.T) {
	be := newTxnBackend()
	be.rcptErr["bad@example.com"] = &smtp.SMTPError{
		Code:         550,
		EnhancedCode: smtp.EnhancedCode{5, 1, 1},
		Message:      "User unknown",
	}

	_, l := newPipeServer(t, be)
	client, scanner := pipeConn(t, l)

	readResponse(t, scanner)
	cmd(t, client, scanner, "EHLO localhost\r\n")
	cmd(t, client, scanner, "MAIL FROM:<sender@example.com>\r\n")

	if code, _ := cmd(t, client, scanner, "RCPT TO:<bad@example.com>\r\n"); code != 550 {
		t.Fatalf("RCPT reject: got %d, want 550", code)
	}

	// No accepted recipients: DATA must be rejected.
	if code, _ := cmd(t, client, scanner, "DATA\r\n"); code != 503 {
		t.Fatalf("DATA with no accepted recipients: got %d, want 503", code)
	}

	sess := be.sessionAt(0)
	sess.mu.Lock()
	if len(sess.recipients) != 0 || sess.dataCount != 0 {
		sess.mu.Unlock()
		t.Fatalf("backend delivered with no accepted recipients: recipients=%v data=%d", sess.recipients, sess.dataCount)
	}
	sess.mu.Unlock()
}

// TestTransactionDuplicateMailDuringBdat verifies that once a BDAT transfer
// has started, a duplicate MAIL (without RSET) is rejected.
func TestTransactionDuplicateMailDuringBdat(t *testing.T) {
	be := newTxnBackend()
	_, l := newPipeServer(t, be)
	client, scanner := pipeConn(t, l)

	readResponse(t, scanner)
	cmd(t, client, scanner, "EHLO localhost\r\n")
	cmd(t, client, scanner, "MAIL FROM:<sender@example.com>\r\n")
	cmd(t, client, scanner, "RCPT TO:<rcpt@example.com>\r\n")

	// Start a BDAT transfer (non-LAST). The server reads the chunk before
	// writing the response, so write the command and chunk together.
	io.WriteString(client, "BDAT 4\r\nbody")
	if code, _ := readResponse(t, scanner); code != 250 {
		t.Fatalf("BDAT start: got %d, want 250", code)
	}

	// Duplicate MAIL during the transfer -> 503.
	if code, _ := cmd(t, client, scanner, "MAIL FROM:<other@example.com>\r\n"); code != 503 {
		t.Fatalf("duplicate MAIL during BDAT: got %d, want 503", code)
	}

	// RSET aborts the transfer and returns to a clean state.
	if code, _ := cmd(t, client, scanner, "RSET\r\n"); code != 250 {
		t.Fatalf("RSET: got %d, want 250", code)
	}

	// A new transaction can be started.
	if code, _ := cmd(t, client, scanner, "MAIL FROM:<sender@example.com>\r\n"); code != 250 {
		t.Fatalf("MAIL after RSET: got %d, want 250", code)
	}
}

// TestTransactionDisconnectIsolation verifies that disconnecting one
// connection only clears its own transaction and never calls another
// session's Reset.
func TestTransactionDisconnectIsolation(t *testing.T) {
	be := newTxnBackend()
	_, l := newPipeServer(t, be)

	// Connection A: full transaction then disconnect.
	clientA, scannerA := pipeConn(t, l)
	readResponse(t, scannerA)
	cmd(t, clientA, scannerA, "EHLO localhost\r\n")
	cmd(t, clientA, scannerA, "MAIL FROM:<a@example.com>\r\n")
	cmd(t, clientA, scannerA, "RCPT TO:<a1@example.com>\r\n")
	cmd(t, clientA, scannerA, "DATA\r\n")
	io.WriteString(clientA, "bodyA\r\n.\r\n")
	readResponse(t, scannerA)
	cmd(t, clientA, scannerA, "QUIT\r\n") // disconnect A

	// Connection B: transaction in progress (MAIL + RCPT, no DATA yet).
	clientB, scannerB := pipeConn(t, l)
	readResponse(t, scannerB)
	cmd(t, clientB, scannerB, "EHLO localhost\r\n")
	cmd(t, clientB, scannerB, "MAIL FROM:<b@example.com>\r\n")
	cmd(t, clientB, scannerB, "RCPT TO:<b1@example.com>\r\n")

	// A has disconnected. B's transaction must be intact: DATA succeeds.
	if code, _ := cmd(t, clientB, scannerB, "DATA\r\n"); code != 354 {
		t.Fatalf("B DATA after A disconnect: got %d, want 354 (B transaction must be intact)", code)
	}
	io.WriteString(clientB, "bodyB\r\n.\r\n")
	if code, _ := readResponse(t, scannerB); code != 250 {
		t.Fatalf("B DATA content after A disconnect: got %d, want 250", code)
	}

	// B's recipient was delivered: its transaction was not cleared by A.
	sessB := be.sessionAt(1)
	if sessB == nil {
		t.Fatal("no session B created")
	}
	sessB.mu.Lock()
	if got := string(sessB.data); got != "bodyB\r\n" {
		sessB.mu.Unlock()
		t.Fatalf("B data: got %q, want \"bodyB\\r\\n\"", got)
	}
	sessB.mu.Unlock()
}
