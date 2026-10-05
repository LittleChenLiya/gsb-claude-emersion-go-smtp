package smtp

import (
	"bufio"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
)

// gateBackend creates gateSession instances and remembers every session it
// created so tests can verify that one connection never touches the session
// (Reset/Logout) of another connection.
type gateBackend struct {
	sessions []*gateSession
}

func (be *gateBackend) NewSession(c *Conn) (Session, error) {
	s := &gateSession{}
	be.sessions = append(be.sessions, s)
	return s, nil
}

// gateSession records every backend call. It rejects recipients in the
// reject.example domain so tests can verify that a failed RCPT does not
// pollute the accepted recipients of the transaction.
type gateSession struct {
	authed      bool
	mailCalls   int
	from        string
	rcpts       []string
	dataCalls   int
	data        []byte
	resetCalls  int
	logoutCalls int
	loggedOut   chan struct{}
}

func (s *gateSession) AuthMechanisms() []string { return []string{sasl.Plain} }

func (s *gateSession) Auth(mech string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(identity, username, password string) error {
		if username != "user" || password != "pass" {
			return errors.New("bad credentials")
		}
		s.authed = true
		return nil
	}), nil
}

func (s *gateSession) Mail(from string, opts *MailOptions) error {
	s.mailCalls++
	s.from = from
	return nil
}

func (s *gateSession) Rcpt(to string, opts *RcptOptions) error {
	if strings.HasSuffix(to, "@reject.example") {
		return &SMTPError{Code: 550, EnhancedCode: EnhancedCode{5, 1, 1}, Message: "No such user"}
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *gateSession) Data(r io.Reader) error {
	s.dataCalls++
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}
	s.data = b
	return nil
}

func (s *gateSession) Reset() { s.resetCalls++ }

func (s *gateSession) Logout() error {
	s.logoutCalls++
	if s.loggedOut != nil {
		select {
		case <-s.loggedOut:
		default:
			close(s.loggedOut)
		}
	}
	return nil
}

// newGatePipe creates an in-memory server connection driven through a
// net.Pipe. It returns the server-side Conn (for state inspection), the
// client end of the pipe and a textproto reader for replies.
func newGatePipe(t *testing.T, be *gateBackend) (*Conn, net.Conn, *textproto.Reader) {
	t.Helper()

	s := NewServer(be)
	s.AllowInsecureAuth = true
	s.Domain = "gate.test"

	srv, cli := net.Pipe()
	conn := newConn(srv, s)
	go s.handleConn(conn)

	tp := textproto.NewReader(bufio.NewReader(cli))
	return conn, cli, tp
}

func expectReply(t *testing.T, tp *textproto.Reader, want int) string {
	t.Helper()
	code, msg, err := tp.ReadResponse(0)
	if err != nil {
		t.Fatalf("expected %d, got read error: %v", want, err)
	}
	if code != want {
		t.Fatalf("expected %d, got %d (%s)", want, code, msg)
	}
	return msg
}

func sendCmd(t *testing.T, c net.Conn, tp *textproto.Reader, want int, cmd string) string {
	t.Helper()
	if _, err := io.WriteString(c, cmd+"\r\n"); err != nil {
		t.Fatalf("failed to send %q: %v", cmd, err)
	}
	return expectReply(t, tp, want)
}

func sendData(t *testing.T, c net.Conn, tp *textproto.Reader, data string) {
	t.Helper()
	sendCmd(t, c, tp, 354, "DATA")
	if _, err := io.WriteString(c, data+"\r\n.\r\n"); err != nil {
		t.Fatalf("failed to send DATA payload: %v", err)
	}
	expectReply(t, tp, 250)
	// The final DATA reply is sent before the server resets the
	// transaction state, so synchronize with a NOOP round-trip before
	// inspecting the server-side state.
	sendCmd(t, c, tp, 250, "NOOP")
}

// TestTransactionGateSequence drives a full command sequence over an
// in-memory connection and verifies the explicit transaction state gate:
// real protocol codes for phase errors, failed RCPT not polluting accepted
// recipients, duplicate MAIL rejection, RSET clearing only the transaction
// (not the authentication state) and the backend only being called in valid
// phases.
func TestTransactionGateSequence(t *testing.T) {
	be := &gateBackend{}
	conn, cli, tp := newGatePipe(t, be)
	defer cli.Close()

	// Greeting.
	expectReply(t, tp, 220)
	if conn.phase != phaseGreet {
		t.Fatalf("expected GREET phase, got %v", conn.phase)
	}

	// Phase errors before HELO carry the real 503 protocol code and never
	// reach the backend.
	sendCmd(t, cli, tp, 503, "MAIL FROM:<a@example.com>")
	sendCmd(t, cli, tp, 503, "RCPT TO:<b@ok.example>")
	sendCmd(t, cli, tp, 503, "DATA")

	sendCmd(t, cli, tp, 250, "EHLO client.example")
	if conn.phase != phaseReady {
		t.Fatalf("expected READY phase after EHLO, got %v", conn.phase)
	}
	sess := be.sessions[0]

	// No transaction in progress: RCPT/DATA are sequence errors.
	sendCmd(t, cli, tp, 503, "RCPT TO:<b@ok.example>")
	sendCmd(t, cli, tp, 503, "DATA")
	if sess.mailCalls != 0 || len(sess.rcpts) != 0 || sess.dataCalls != 0 {
		t.Fatal("backend called during an invalid phase")
	}

	// Authenticate; the auth state must survive RSET later.
	sendCmd(t, cli, tp, 235, "AUTH PLAIN AHVzZXIAcGFzcw==")
	if !sess.authed || !conn.didAuth {
		t.Fatal("expected session to be authenticated")
	}

	// Start a transaction.
	sendCmd(t, cli, tp, 250, "MAIL FROM:<sender@example.com>")
	if conn.phase != phaseMail {
		t.Fatalf("expected MAIL phase, got %v", conn.phase)
	}

	// A second MAIL within the same transaction is rejected.
	sendCmd(t, cli, tp, 503, "MAIL FROM:<other@example.com>")
	if sess.mailCalls != 1 {
		t.Fatalf("backend Mail called %d times, want 1", sess.mailCalls)
	}

	// One RCPT is rejected by the backend, another is accepted. The
	// rejected one must not pollute the accepted recipients.
	sendCmd(t, cli, tp, 550, "RCPT TO:<bad@reject.example>")
	sendCmd(t, cli, tp, 250, "RCPT TO:<good@ok.example>")
	if conn.phase != phaseRcpt {
		t.Fatalf("expected RCPT phase, got %v", conn.phase)
	}
	if len(conn.recipients) != 1 || conn.recipients[0] != "good@ok.example" {
		t.Fatalf("rejected RCPT polluted recipients: %v", conn.recipients)
	}
	if len(sess.rcpts) != 1 || sess.rcpts[0] != "good@ok.example" {
		t.Fatalf("backend saw wrong recipients: %v", sess.rcpts)
	}

	// DATA only delivers the accepted recipient set.
	sendData(t, cli, tp, "Subject: one\r\n\r\nfirst")
	if sess.dataCalls != 1 {
		t.Fatalf("backend Data called %d times, want 1", sess.dataCalls)
	}
	if conn.phase != phaseReady || conn.fromReceived || len(conn.recipients) != 0 {
		t.Fatal("transaction state not cleared after DATA")
	}

	// A new transaction may start after DATA completed.
	sendCmd(t, cli, tp, 250, "MAIL FROM:<sender2@example.com>")
	sendCmd(t, cli, tp, 250, "RCPT TO:<good2@ok.example>")

	// RSET clears the current transaction but keeps the session and its
	// authentication state.
	sendCmd(t, cli, tp, 250, "RSET")
	if conn.phase != phaseReady || conn.fromReceived || len(conn.recipients) != 0 {
		t.Fatal("RSET did not clear the transaction state")
	}
	if !conn.didAuth || !sess.authed {
		t.Fatal("RSET dropped the session authentication state")
	}

	// The new transaction has no old recipients: DATA and RCPT are
	// sequence errors again, and the backend is not called.
	dataCalls, mailCalls := sess.dataCalls, sess.mailCalls
	sendCmd(t, cli, tp, 503, "DATA")
	sendCmd(t, cli, tp, 503, "RCPT TO:<good2@ok.example>")
	if sess.dataCalls != dataCalls || sess.mailCalls != mailCalls {
		t.Fatal("backend called during an invalid phase after RSET")
	}

	// Authentication is still in effect: a second AUTH is rejected and a
	// fresh transaction completes without re-authenticating.
	sendCmd(t, cli, tp, 503, "AUTH PLAIN AHVzZXIAcGFzcw==")
	sendCmd(t, cli, tp, 250, "MAIL FROM:<sender3@example.com>")
	sendCmd(t, cli, tp, 250, "RCPT TO:<good3@ok.example>")
	sendData(t, cli, tp, "Subject: two\r\n\r\nsecond")
	if sess.dataCalls != 2 {
		t.Fatalf("backend Data called %d times, want 2", sess.dataCalls)
	}
	if len(sess.rcpts) != 3 || sess.rcpts[2] != "good3@ok.example" {
		t.Fatalf("backend saw wrong recipients: %v", sess.rcpts)
	}

	sendCmd(t, cli, tp, 221, "QUIT")
}

// TestTransactionGateBdat verifies the state gate while a BDAT message
// transfer is in progress: MAIL, RCPT and DATA are rejected, and only
// continuation BDAT chunks of the current transaction are accepted.
func TestTransactionGateBdat(t *testing.T) {
	be := &gateBackend{}
	conn, cli, tp := newGatePipe(t, be)
	defer cli.Close()

	expectReply(t, tp, 220)
	sendCmd(t, cli, tp, 250, "EHLO client.example")
	sendCmd(t, cli, tp, 250, "MAIL FROM:<sender@example.com>")
	sendCmd(t, cli, tp, 250, "RCPT TO:<good@ok.example>")

	// Begin the message transfer.
	if _, err := io.WriteString(cli, "BDAT 5\r\nhello"); err != nil {
		t.Fatal(err)
	}
	expectReply(t, tp, 250)
	if conn.phase != phaseData {
		t.Fatalf("expected DATA phase during BDAT, got %v", conn.phase)
	}

	// No new MAIL/RCPT/DATA commands while the transfer is in progress.
	sendCmd(t, cli, tp, 503, "MAIL FROM:<other@example.com>")
	sendCmd(t, cli, tp, 503, "RCPT TO:<good2@ok.example>")
	sendCmd(t, cli, tp, 503, "DATA")

	// The final chunk of the current transaction is accepted.
	if _, err := io.WriteString(cli, "BDAT 5 LAST\r\nworld"); err != nil {
		t.Fatal(err)
	}
	expectReply(t, tp, 250)
	// Synchronize with the server before inspecting its state: the final
	// BDAT reply is sent before the transaction state is reset.
	sendCmd(t, cli, tp, 250, "NOOP")

	sess := be.sessions[0]
	if sess.dataCalls != 1 || string(sess.data) != "helloworld" {
		t.Fatalf("backend got %d data calls, payload %q", sess.dataCalls, sess.data)
	}
	if conn.phase != phaseReady {
		t.Fatalf("expected READY phase after BDAT LAST, got %v", conn.phase)
	}
}

// TestTransactionDisconnectIsolation verifies that closing a connection
// only aborts its own transaction and logs out its own session - it never
// calls Session.Reset or Session.Logout of other connections' sessions.
func TestTransactionDisconnectIsolation(t *testing.T) {
	be := &gateBackend{}

	_, cliA, tpA := newGatePipe(t, be)
	defer cliA.Close()
	expectReply(t, tpA, 220)
	sendCmd(t, cliA, tpA, 250, "EHLO a.example")
	sendCmd(t, cliA, tpA, 250, "MAIL FROM:<a@example.com>")
	sendCmd(t, cliA, tpA, 250, "RCPT TO:<good@ok.example>")
	sessA := be.sessions[0]
	sessA.loggedOut = make(chan struct{})

	_, cliB, tpB := newGatePipe(t, be)
	defer cliB.Close()
	expectReply(t, tpB, 220)
	sendCmd(t, cliB, tpB, 250, "EHLO b.example")
	sendCmd(t, cliB, tpB, 250, "MAIL FROM:<b@example.com>")
	sessB := be.sessions[1]

	// Disconnect A in the middle of its transaction.
	if err := cliA.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-sessA.loggedOut:
	case <-time.After(5 * time.Second):
		t.Fatal("session A was not logged out on disconnect")
	}
	if sessA.logoutCalls != 1 {
		t.Fatalf("session A Logout called %d times, want 1", sessA.logoutCalls)
	}
	// Disconnect aborts the transaction without calling Session.Reset.
	if sessA.resetCalls != 0 {
		t.Fatalf("disconnect called Session.Reset %d times", sessA.resetCalls)
	}

	// Session B is untouched by A's disconnect and its transaction is
	// still alive.
	if sessB.resetCalls != 0 || sessB.logoutCalls != 0 {
		t.Fatal("disconnect of connection A touched session B")
	}
	sendCmd(t, cliB, tpB, 250, "RCPT TO:<good@ok.example>")
	sendData(t, cliB, tpB, "Subject: b\r\n\r\nstill alive")
	if sessB.dataCalls != 1 {
		t.Fatalf("session B Data called %d times, want 1", sessB.dataCalls)
	}
}
