package smtp_test

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

func enableStrictDataReader(s *smtp.Server) {
	s.StrictDataReader = true
}

// Four data lines, one of them dot-stuffed, followed by a pipelined NOOP.
// The stuffed line must be unstuffed and the NOOP must be handled as a
// command, not swallowed into the message.
func TestServerStrictData(t *testing.T) {
	be, s, c, scanner, _ := testServerEhlo(t, enableStrictDataReader)
	defer s.Close()

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
	scanner.Scan()
	io.WriteString(c, "DATA\r\n")
	scanner.Scan()

	io.WriteString(c, "From: alice@example.org\r\n")
	io.WriteString(c, "To: bob@example.net\r\n")
	io.WriteString(c, "\r\n")
	io.WriteString(c, "..hello\r\n")
	io.WriteString(c, ".\r\n")
	io.WriteString(c, "NOOP\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid DATA response:", scanner.Text())
	}

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid NOOP response:", scanner.Text())
	}

	if len(be.anonmsgs) != 1 {
		t.Fatal("Invalid number of sent messages:", len(be.anonmsgs))
	}

	expected := "From: alice@example.org\r\n" +
		"To: bob@example.net\r\n" +
		"\r\n" +
		".hello\r\n"
	if msg := string(be.anonmsgs[0].Data); msg != expected {
		t.Fatalf("Invalid mail data: %q", msg)
	}
}

// The <CRLF>.<CRLF> terminator and stuffed dots must be detected even
// when split across multiple input chunks.
func TestServerStrictData_chunkedTerminator(t *testing.T) {
	be, s, c, scanner, _ := testServerEhlo(t, enableStrictDataReader)
	defer s.Close()

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
	scanner.Scan()
	io.WriteString(c, "DATA\r\n")
	scanner.Scan()

	chunks := []string{"hel", "lo\r", "\n.", ".", "world\r", "\n", ".", "\r", "\n"}
	for _, chunk := range chunks {
		io.WriteString(c, chunk)
		time.Sleep(5 * time.Millisecond)
	}

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid DATA response:", scanner.Text())
	}

	if len(be.anonmsgs) != 1 {
		t.Fatal("Invalid number of sent messages:", len(be.anonmsgs))
	}

	expected := "hello\r\n.world\r\n"
	if msg := string(be.anonmsgs[0].Data); msg != expected {
		t.Fatalf("Invalid mail data: %q", msg)
	}
}

// A connection EOF before the <CRLF>.<CRLF> terminator (short EOF) is not
// a successful end of data: the truncated message must not be accepted.
func TestServerStrictData_shortEOF(t *testing.T) {
	be, s, c, scanner, _ := testServerEhlo(t, enableStrictDataReader)
	defer s.Close()

	be.dataErrors = make(chan error, 1)

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
	scanner.Scan()
	io.WriteString(c, "DATA\r\n")
	scanner.Scan()

	io.WriteString(c, "hello\r\n")
	c.Close()

	select {
	case err := <-be.dataErrors:
		if err != io.ErrUnexpectedEOF {
			t.Fatal("Invalid DATA error:", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for the DATA error")
	}

	if len(be.anonmsgs) != 0 {
		t.Fatal("Truncated message was accepted:", len(be.anonmsgs))
	}
}

// A content line longer than MaxLineLength (counted on the wire form,
// before dot-unstuffing, excluding CRLF) fails the transaction without
// marking the message as accepted. The rest of the message is consumed
// up to the terminator and trailing commands stay in the connection
// reader.
func TestServerStrictData_lineTooLong(t *testing.T) {
	be, s, c, scanner, _ := testServerEhlo(t, func(s *smtp.Server) {
		s.StrictDataReader = true
		s.MaxLineLength = 40
	})
	defer s.Close()

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
	scanner.Scan()
	io.WriteString(c, "DATA\r\n")
	scanner.Scan()

	io.WriteString(c, strings.Repeat("A", 50)+"\r\n")
	io.WriteString(c, ".\r\n")
	io.WriteString(c, "NOOP\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "552 ") {
		t.Fatal("Invalid DATA response, expected an error but got:", scanner.Text())
	}

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid NOOP response:", scanner.Text())
	}

	if len(be.anonmsgs) != 0 {
		t.Fatal("Over-limit message was accepted:", len(be.anonmsgs))
	}
}

// A message bigger than MaxMessageBytes fails the transaction and is not
// marked as accepted.
func TestServerStrictData_tooLongMessage(t *testing.T) {
	be, s, c, scanner, _ := testServerEhlo(t, func(s *smtp.Server) {
		s.StrictDataReader = true
		s.MaxMessageBytes = 50
	})
	defer s.Close()

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
	scanner.Scan()
	io.WriteString(c, "DATA\r\n")
	scanner.Scan()

	io.WriteString(c, "This is a very long message.\r\n")
	io.WriteString(c, "Much longer than you can possibly imagine.\r\n")
	io.WriteString(c, "And much longer than the server's MaxMessageBytes.\r\n")
	io.WriteString(c, ".\r\n")
	io.WriteString(c, "NOOP\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "552 ") {
		t.Fatal("Invalid DATA response, expected an error but got:", scanner.Text())
	}

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid NOOP response:", scanner.Text())
	}

	if len(be.anonmsgs) != 0 {
		t.Fatal("Over-limit message was accepted:", len(be.anonmsgs))
	}
}

// A single dot at the beginning of a line that is neither the terminator
// nor a stuffed dot is rejected. The transaction is still cleaned up in a
// controlled way: the rest of the message is consumed up to the
// terminator and trailing commands are handled as commands.
func TestServerStrictData_invalidDot(t *testing.T) {
	be, s, c, scanner, _ := testServerEhlo(t, enableStrictDataReader)
	defer s.Close()

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
	scanner.Scan()
	io.WriteString(c, "DATA\r\n")
	scanner.Scan()

	io.WriteString(c, ".foo\r\n")
	io.WriteString(c, ".\r\n")
	io.WriteString(c, "NOOP\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "554 ") {
		t.Fatal("Invalid DATA response, expected an error but got:", scanner.Text())
	}

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid NOOP response:", scanner.Text())
	}

	if len(be.anonmsgs) != 0 {
		t.Fatal("Invalid message was accepted:", len(be.anonmsgs))
	}
}

// When the backend fails to consume the message, the transaction is
// cleaned up in a controlled way: the remaining data is drained up to the
// terminator and commands pipelined after it are still handled.
func TestServerStrictData_backendError(t *testing.T) {
	be, s, c, scanner, _ := testServerEhlo(t, enableStrictDataReader)
	defer s.Close()

	be.dataErr = errors.New("backend is on fire")

	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
	scanner.Scan()
	io.WriteString(c, "DATA\r\n")
	scanner.Scan()

	io.WriteString(c, "hello\r\n")
	io.WriteString(c, ".\r\n")
	io.WriteString(c, "NOOP\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "554 ") {
		t.Fatal("Invalid DATA response, expected an error but got:", scanner.Text())
	}

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid NOOP response:", scanner.Text())
	}

	if len(be.anonmsgs) != 0 {
		t.Fatal("Failed message was accepted:", len(be.anonmsgs))
	}
}
