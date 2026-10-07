package smtp_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/emersion/go-smtp"
)

// swallowBackend accepts DATA but always ignores reader errors: it models
// a backend that swallows ErrDataTooLarge. The server must still drain the
// surplus octets, answer 552 and allow RSET followed by a new MAIL.
type swallowBackend struct{ dataN []int }

type swallowSession struct{ be *swallowBackend }

func (be *swallowBackend) NewSession(*smtp.Conn) (smtp.Session, error) {
	return &swallowSession{be: be}, nil
}
func (s *swallowSession) Mail(string, *smtp.MailOptions) error { return nil }
func (s *swallowSession) Rcpt(string, *smtp.RcptOptions) error { return nil }
func (s *swallowSession) Reset()                               {}
func (s *swallowSession) Logout() error                        { return nil }
func (s *swallowSession) Data(r io.Reader) error {
	n, _ := io.Copy(io.Discard, r) // deliberately ignore ErrDataTooLarge
	s.be.dataN = append(s.be.dataN, int(n))
	return nil
}

// ExampleServer_dataTooLargeDrain is a short, self-contained regression
// fixture for the DATA size-limit drain-to-terminator policy. It uses an
// in-memory loopback connection (no files, no external services): a tiny
// MaxMessageBytes, an overlong body whose terminator is split across two
// writes (with a dot-stuffed line in the surplus), then RSET and a fresh
// MAIL transaction on the same connection.
func ExampleServer_dataTooLargeDrain() {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	be := new(swallowBackend)
	srv := smtp.NewServer(be)
	srv.Domain = "localhost"
	srv.MaxMessageBytes = 24
	go srv.Serve(l)
	defer srv.Close()

	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	sc := bufio.NewScanner(conn)

	code := func() string {
		sc.Scan()
		line := sc.Text()
		if i := strings.IndexByte(line, ' '); i >= 0 {
			return line[:i]
		}
		return line
	}

	code() // greeting
	fmt.Fprintln(conn, "HELO localhost")
	fmt.Println(code())
	fmt.Fprintln(conn, "MAIL FROM:<big@nsa.gov>")
	fmt.Println(code())
	fmt.Fprintln(conn, "RCPT TO:<root@gchq.gov.uk>")
	fmt.Println(code())
	fmt.Fprintln(conn, "DATA")
	fmt.Println(code()) // 354

	// 24 decoded bytes are accepted, everything afterwards is surplus.
	io.WriteString(conn, "abcdefghijklmnopqrstuvwx")
	io.WriteString(conn, "yyyyyyyyy\r\n")
	io.WriteString(conn, "..dot-stuffed surplus\r\n")
	io.WriteString(conn, "tail\r")
	// Terminator "<CR><LF>.<CR><LF>" split across two writes.
	io.WriteString(conn, "\n.\r")
	io.WriteString(conn, "\n")
	fmt.Println(code()) // 552

	fmt.Fprintln(conn, "RSET")
	fmt.Println(code())
	fmt.Fprintln(conn, "MAIL FROM:<small@nsa.gov>")
	fmt.Println(code())
	fmt.Fprintln(conn, "RCPT TO:<root@gchq.gov.uk>")
	fmt.Println(code())
	fmt.Fprintln(conn, "DATA")
	fmt.Println(code()) // 354
	io.WriteString(conn, "short\r\n.\r\n")
	fmt.Println(code()) // 250

	fmt.Fprintln(conn, "QUIT")
	fmt.Println(code())
	fmt.Println("backend bytes:", be.dataN)

	// Output:
	// 250
	// 250
	// 250
	// 354
	// 552
	// 250
	// 250
	// 250
	// 354
	// 250
	// 221
	// backend bytes: [24 7]
}
