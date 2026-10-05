// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package smtp_test

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

func ExampleDial() {
	// Connect to the remote SMTP server.
	c, err := smtp.Dial("mail.example.com:25")
	if err != nil {
		log.Fatal(err)
	}

	// Set the sender and recipient first
	if err := c.Mail("sender@example.org", nil); err != nil {
		log.Fatal(err)
	}
	if err := c.Rcpt("recipient@example.net", nil); err != nil {
		log.Fatal(err)
	}

	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		log.Fatal(err)
	}
	_, err = fmt.Fprintf(wc, "This is the email body")
	if err != nil {
		log.Fatal(err)
	}
	err = wc.Close()
	if err != nil {
		log.Fatal(err)
	}

	// Send the QUIT command and close the connection.
	err = c.Quit()
	if err != nil {
		log.Fatal(err)
	}
}

// scriptedConn is an in-memory connection whose server side is a fixed
// script of responses. It retains the SMTP phase between commands but does
// not record AUTH values, so the command receipt is deterministic and free
// of credentials.
type scriptedConn struct {
	reader io.Reader
	writer io.Writer
}

func (c *scriptedConn) Read(b []byte) (int, error)         { return c.reader.Read(b) }
func (c *scriptedConn) Write(b []byte) (int, error)        { return c.writer.Write(b) }
func (c *scriptedConn) Close() error                       { return nil }
func (c *scriptedConn) LocalAddr() net.Addr                { return nil }
func (c *scriptedConn) RemoteAddr() net.Addr               { return nil }
func (c *scriptedConn) SetDeadline(time.Time) error        { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error    { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error   { return nil }

// ExampleClient_EHLO demonstrates the explicit EHLO snapshot: the client
// performs an EHLO handshake, receives a snapshot of the server's
// capabilities, and the mail transaction uses only the capabilities
// confirmed by that EHLO.
func ExampleClient_EHLO() {
	server := "220 mail.example.com ESMTP service ready\r\n" +
		"250-mail.example.com Hello\r\n" +
		"250-8BITMIME\r\n" +
		"250-SMTPUTF8\r\n" +
		"250 Ok\r\n" +
		"250 Ok\r\n" +
		"250 Ok\r\n" +
		"354 End data with <CR><LF>.<CR><LF>\r\n" +
		"250 Ok: queued\r\n" +
		"221 Bye\r\n"

	var cmds strings.Builder
	conn := &scriptedConn{
		reader: strings.NewReader(server),
		writer: &cmds,
	}

	c := smtp.NewClient(conn)
	defer c.Close()

	// Perform an explicit EHLO and get a snapshot of the server's
	// capabilities.
	caps, err := c.EHLO("localhost")
	if err != nil {
		log.Fatal(err)
	}
	_, smtpUTF8 := caps["SMTPUTF8"]
	fmt.Printf("SMTPUTF8: %v\n", smtpUTF8)

	// The mail transaction uses the capabilities confirmed by this EHLO.
	if err := c.Mail("user@example.com", nil); err != nil {
		log.Fatal(err)
	}
	if err := c.Rcpt("other@example.com", nil); err != nil {
		log.Fatal(err)
	}
	wc, err := c.Data()
	if err != nil {
		log.Fatal(err)
	}
	if err := wc.Close(); err != nil {
		log.Fatal(err)
	}
	if err := c.Quit(); err != nil {
		log.Fatal(err)
	}

	fmt.Print(cmds.String())
	// Output:
	// SMTPUTF8: true
	// EHLO localhost
	// MAIL FROM:<user@example.com> BODY=8BITMIME
	// RCPT TO:<other@example.com>
	// DATA
	//
	// .
	// QUIT
}

// variables to make ExamplePlainAuth compile, without adding
// unnecessary noise there.
var (
	from       = "gopher@example.net"
	msg        = strings.NewReader("dummy message")
	recipients = []string{"foo@example.com"}
)

func ExampleSendMail_plainAuth() {
	// hostname is used by PlainAuth to validate the TLS certificate.
	hostname := "mail.example.com"
	auth := sasl.NewPlainClient("", "user@example.com", "password")

	err := smtp.SendMail(hostname+":25", auth, from, recipients, msg)
	if err != nil {
		log.Fatal(err)
	}
}

func ExampleSendMail() {
	// Set up authentication information.
	auth := sasl.NewPlainClient("", "user@example.com", "password")

	// Connect to the server, authenticate, set the sender and recipient,
	// and send the email all in one step.
	to := []string{"recipient@example.net"}
	msg := strings.NewReader("To: recipient@example.net\r\n" +
		"Subject: discount Gophers!\r\n" +
		"\r\n" +
		"This is the email body.\r\n")
	err := smtp.SendMail("mail.example.com:25", auth, "sender@example.org", to, msg)
	if err != nil {
		log.Fatal(err)
	}
}
