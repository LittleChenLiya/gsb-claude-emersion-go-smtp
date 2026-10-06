package smtp

import (
	"bufio"
	"io"
	"io/ioutil"
	"strings"
	"testing"
)

func newTestStrictDataReader(input string, lineLimit int) *strictDataReader {
	// A tiny buffer forces the input to be delivered in small chunks so
	// that dots and line breaks are split across underlying reads.
	return &strictDataReader{
		r:         bufio.NewReaderSize(strings.NewReader(input), 4),
		lineLimit: lineLimit,
	}
}

// The terminator and the stuffed dots must be detected correctly even
// when they are split across input chunks, and whatever follows the
// terminator must stay in the connection reader.
func TestStrictDataReaderChunked(t *testing.T) {
	r := newTestStrictDataReader("line1\r\n..hello\r\n.\r\nNOOP\r\n", 100)

	// Read with a 2-byte buffer to split the input across many Read calls.
	var out []byte
	buf := make([]byte, 2)
	for {
		n, err := r.Read(buf)
		out = append(out, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read() = %v", err)
		}
	}

	if expected := "line1\r\n.hello\r\n"; string(out) != expected {
		t.Fatalf("Got data %q, expected %q", out, expected)
	}

	rest, err := ioutil.ReadAll(r.r)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "NOOP\r\n" {
		t.Fatalf("Trailing command was swallowed into the message, remaining: %q", rest)
	}
}

// "..hello" on the wire must be delivered as ".hello".
func TestStrictDataReaderDotUnstuffing(t *testing.T) {
	r := newTestStrictDataReader("..hello\r\n...\r\n.\r\n", 100)

	out, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	if expected := ".hello\r\n..\r\n"; string(out) != expected {
		t.Fatalf("Got data %q, expected %q", out, expected)
	}
}

// A connection EOF before the <CRLF>.<CRLF> terminator (short EOF) is not
// a successful end of data.
func TestStrictDataReaderShortEOF(t *testing.T) {
	r := newTestStrictDataReader("hello\r\n", 100)

	_, err := ioutil.ReadAll(r)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("ReadAll() = %v, expected io.ErrUnexpectedEOF", err)
	}
}

// A single dot at the beginning of a line that is neither the terminator
// nor a stuffed dot is invalid.
func TestStrictDataReaderInvalidDot(t *testing.T) {
	r := newTestStrictDataReader(".foo\r\n.\r\n", 100)

	_, err := ioutil.ReadAll(r)
	if err != ErrDataInvalidDot {
		t.Fatalf("ReadAll() = %v, expected ErrDataInvalidDot", err)
	}
}

// The content line limit is enforced on the wire form of the line (before
// dot-unstuffing, excluding CRLF). After the error, drainMode must consume
// the rest of the message up to the terminator, leaving trailing commands
// in the connection reader.
func TestStrictDataReaderLineTooLong(t *testing.T) {
	r := newTestStrictDataReader("123456\r\nmore\r\n.\r\nNOOP\r\n", 5)

	_, err := ioutil.ReadAll(r)
	if err != ErrDataLineTooLong {
		t.Fatalf("ReadAll() = %v, expected ErrDataLineTooLong", err)
	}

	r.drainMode()
	if _, err := io.Copy(ioutil.Discard, r); err != nil {
		t.Fatalf("drain: %v", err)
	}

	rest, err := ioutil.ReadAll(r.r)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "NOOP\r\n" {
		t.Fatalf("Trailing command was swallowed into the message, remaining: %q", rest)
	}
}

// The wire-form line limit counts the stuffing dot: a stuffed line of
// exactly the limit on the wire is accepted.
func TestStrictDataReaderLineLimitWireForm(t *testing.T) {
	// "..123" is 5 wire bytes and unstuffs to ".123" (4 bytes).
	r := newTestStrictDataReader("..123\r\n.\r\n", 5)

	out, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll() = %v", err)
	}
	if string(out) != ".123\r\n" {
		t.Fatalf("Got data %q", out)
	}

	// One more wire byte exceeds the limit even though the unstuffed
	// line would be exactly 5 bytes long.
	r = newTestStrictDataReader("..1234\r\n.\r\n", 5)
	if _, err := ioutil.ReadAll(r); err != ErrDataLineTooLong {
		t.Fatalf("ReadAll() = %v, expected ErrDataLineTooLong", err)
	}
}
