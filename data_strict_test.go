package smtp_test

import (
	"io"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

var strictData = func(s *smtp.Server) {
	s.StrictDataReader = true
}

// Sends MAIL/RCPT/DATA and checks the 354 response.
func strictDataBegin(t *testing.T, c io.Writer, scanner interface {
	Scan() bool
	Text() string
}) {
	t.Helper()

	io.WriteString(c, "HELO localhost\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid HELO response:", scanner.Text())
	}
	io.WriteString(c, "MAIL FROM:<root@nsa.gov>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid MAIL response:", scanner.Text())
	}
	io.WriteString(c, "RCPT TO:<root@gchq.gov.uk>\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid RCPT response:", scanner.Text())
	}
	io.WriteString(c, "DATA\r\n")
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "354 ") {
		t.Fatal("Invalid DATA response:", scanner.Text())
	}
}

// Four data lines are delivered with dot-unstuffing applied ("..hello"
// becomes ".hello"), and a NOOP pipelined right after the terminator is
// not swallowed into the mail.
func TestServerStrictData(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t, strictData)
	defer s.Close()
	defer c.Close()

	strictDataBegin(t, c, scanner)

	io.WriteString(c, "Subject: test\r\n")
	io.WriteString(c, "\r\n")
	io.WriteString(c, "..hello\r\n")
	io.WriteString(c, "last line\r\n")
	// Terminator and the next command are sent in a single write.
	io.WriteString(c, ".\r\nNOOP\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid DATA response:", scanner.Text())
	}

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("NOOP after DATA terminator was swallowed:", scanner.Text())
	}

	if len(be.anonmsgs) != 1 {
		t.Fatal("Invalid number of sent messages:", len(be.anonmsgs))
	}
	msg := be.anonmsgs[0]
	want := "Subject: test\r\n\r\n.hello\r\nlast line\r\n"
	if string(msg.Data) != want {
		t.Fatalf("Invalid mail data: got %q, want %q", string(msg.Data), want)
	}
}

// The terminator split across multiple writes must still end the message.
func TestServerStrictData_chunkedTerminator(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t, strictData)
	defer s.Close()
	defer c.Close()

	strictDataBegin(t, c, scanner)

	io.WriteString(c, "body\r")
	io.WriteString(c, "\n")
	io.WriteString(c, ".")
	io.WriteString(c, "\r")
	io.WriteString(c, "\n")
	io.WriteString(c, "NOOP\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("Invalid DATA response:", scanner.Text())
	}
	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("NOOP after chunked terminator was swallowed:", scanner.Text())
	}

	if len(be.anonmsgs) != 1 {
		t.Fatal("Invalid number of sent messages:", len(be.anonmsgs))
	}
	if string(be.anonmsgs[0].Data) != "body\r\n" {
		t.Fatalf("Invalid mail data: %q", string(be.anonmsgs[0].Data))
	}
}

// A content line over MaxLineLength fails the transaction even though the
// backend reports no error, and the connection stays usable.
func TestServerStrictData_tooLongLine(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t, strictData, func(s *smtp.Server) {
		s.MaxLineLength = 40
	})
	defer s.Close()
	defer c.Close()

	strictDataBegin(t, c, scanner)

	io.WriteString(c, strings.Repeat("x", 50)+"\r\n")
	io.WriteString(c, ".\r\n")
	io.WriteString(c, "NOOP\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "552 ") {
		t.Fatal("Invalid DATA response, expected an error but got:", scanner.Text())
	}

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("NOOP after failed DATA was swallowed:", scanner.Text())
	}

	if len(be.anonmsgs) != 0 {
		t.Fatal("Over-limit message was marked as successful")
	}
}

// A message over MaxMessageBytes fails the transaction and the remainder
// of the payload is discarded without swallowing the next command.
func TestServerStrictData_tooLongMessage(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t, strictData, func(s *smtp.Server) {
		s.MaxMessageBytes = 10
	})
	defer s.Close()
	defer c.Close()

	strictDataBegin(t, c, scanner)

	io.WriteString(c, "way more than ten bytes of content\r\n")
	io.WriteString(c, ".\r\n")
	io.WriteString(c, "NOOP\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "552 ") {
		t.Fatal("Invalid DATA response, expected an error but got:", scanner.Text())
	}

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("NOOP after failed DATA was swallowed:", scanner.Text())
	}

	if len(be.anonmsgs) != 0 {
		t.Fatal("Over-limit message was marked as successful")
	}
}

// When the backend fails without consuming the payload, the server
// discards the rest of the DATA stream (controlled cleanup) and the
// connection stays in sync for the next command.
func TestServerStrictData_backendError(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t, strictData)
	defer s.Close()
	defer c.Close()

	be.dataErr = &smtp.SMTPError{
		Code:         555,
		EnhancedCode: smtp.EnhancedCode{5, 0, 0},
		Message:      "I failed",
	}

	strictDataBegin(t, c, scanner)

	io.WriteString(c, "some data the backend will not read\r\n")
	io.WriteString(c, ".\r\n")
	io.WriteString(c, "NOOP\r\n")

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "555 ") {
		t.Fatal("Invalid DATA response, expected backend error but got:", scanner.Text())
	}

	scanner.Scan()
	if !strings.HasPrefix(scanner.Text(), "250 ") {
		t.Fatal("NOOP after failed DATA was swallowed:", scanner.Text())
	}

	if len(be.anonmsgs) != 0 {
		t.Fatal("Failed message was marked as successful")
	}
}

// A connection closed in the middle of DATA is a short EOF: the backend
// sees io.ErrUnexpectedEOF and the message is not accepted.
func TestServerStrictData_shortEOF(t *testing.T) {
	be, s, c, scanner := testServerGreeted(t, strictData)
	defer s.Close()

	be.dataErrors = make(chan error, 1)

	strictDataBegin(t, c, scanner)

	io.WriteString(c, "partial data, no terminator\r\n")

	// Bye!
	c.Close()

	select {
	case err := <-be.dataErrors:
		if err != io.ErrUnexpectedEOF {
			t.Fatal("Backend received a different error:", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for the backend to observe the short EOF")
	}

	if len(be.anonmsgs) != 0 {
		t.Fatal("Truncated message was marked as successful")
	}
}
