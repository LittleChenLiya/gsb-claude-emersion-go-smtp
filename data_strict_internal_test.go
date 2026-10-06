package smtp

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"strings"
	"testing"
)

// chunkReader returns the data split into the given chunks, one per Read
// call, to simulate data arriving fragmented over the network.
type chunkReader struct {
	chunks []string
}

func (r *chunkReader) Read(b []byte) (int, error) {
	if len(r.chunks) == 0 {
		return 0, io.EOF
	}
	n := copy(b, r.chunks[0])
	r.chunks[0] = r.chunks[0][n:]
	if len(r.chunks[0]) == 0 {
		r.chunks = r.chunks[1:]
	}
	return n, nil
}

func newStrictReader(chunks ...string) (*strictDataReader, *bufio.Reader) {
	br := bufio.NewReader(&chunkReader{chunks: chunks})
	return &strictDataReader{r: br}, br
}

// A stuffed dot line must be unstuffed: "..hello" is delivered as ".hello".
func TestStrictDataReaderDotUnstuffing(t *testing.T) {
	r, _ := newStrictReader("..hello\r\n.\r\n")

	b, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal("ReadAll failed:", err)
	}
	if string(b) != ".hello\r\n" {
		t.Fatalf("Invalid un-stuffed data: %q", string(b))
	}
	if err := r.streamErr(); err != nil {
		t.Fatal("Unexpected stream error:", err)
	}
}

// Four data lines example: a regular line, a dot-stuffed line, an empty
// line and a line that is only a stuffed dot.
func TestStrictDataReaderFourLines(t *testing.T) {
	r, _ := newStrictReader(
		"first line\r\n",
		"..second line\r\n",
		"\r\n",
		"..\r\n",
		".\r\n",
	)

	b, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal("ReadAll failed:", err)
	}
	want := "first line\r\n.second line\r\n\r\n.\r\n"
	if string(b) != want {
		t.Fatalf("Invalid data: got %q, want %q", string(b), want)
	}
}

// The <CRLF>.<CRLF> terminator split across multiple input chunks must
// still be recognized, and bytes after it (a pipelined NOOP command) must
// stay in the connection reader.
func TestStrictDataReaderChunkedTerminator(t *testing.T) {
	r, br := newStrictReader("body\r", "\n", ".", "\r", "\nNOOP\r\n")

	b, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal("ReadAll failed:", err)
	}
	if string(b) != "body\r\n" {
		t.Fatalf("Invalid data: %q", string(b))
	}

	rest, err := ioutil.ReadAll(br)
	if err != nil {
		t.Fatal("Failed to read remaining input:", err)
	}
	if string(rest) != "NOOP\r\n" {
		t.Fatalf("Data after terminator was swallowed: %q", string(rest))
	}
}

// A connection closed before <CRLF>.<CRLF> is a short EOF, not a clean
// end of the message.
func TestStrictDataReaderShortEOF(t *testing.T) {
	r, _ := newStrictReader("hello\r\npartial line, no terminator")

	_, err := ioutil.ReadAll(r)
	if err != io.ErrUnexpectedEOF {
		t.Fatalf("Expected io.ErrUnexpectedEOF, got: %v", err)
	}
	if err := r.streamErr(); err != io.ErrUnexpectedEOF {
		t.Fatalf("streamErr: expected io.ErrUnexpectedEOF, got: %v", err)
	}
}

// The line limit applies to the wire form of the line, before
// dot-unstuffing and excluding the terminating CRLF.
func TestStrictDataReaderLineLimit(t *testing.T) {
	// Wire content "..123" is 5 bytes: at the limit, accepted and
	// un-stuffed to ".123".
	r, _ := newStrictReader("..123\r\n.\r\n")
	r.lineLimit = 5
	if _, err := ioutil.ReadAll(r); err != nil {
		t.Fatal("Line at the limit rejected:", err)
	}

	// Wire content "..1234" is 6 bytes: over the limit, even though the
	// un-stuffed form would fit.
	r, _ = newStrictReader("..1234\r\n.\r\n")
	r.lineLimit = 5
	if _, err := ioutil.ReadAll(r); err != ErrDataLineTooLong {
		t.Fatalf("Expected ErrDataLineTooLong, got: %v", err)
	}

	// The terminator itself is never rejected by the line limit.
	r, _ = newStrictReader(".\r\n")
	r.lineLimit = 5
	if _, err := ioutil.ReadAll(r); err != nil {
		t.Fatal("Terminator rejected:", err)
	}
}

// A bare LF line ending is rejected in strict mode.
func TestStrictDataReaderBareLF(t *testing.T) {
	r, _ := newStrictReader("hello\n.\r\n")
	if _, err := ioutil.ReadAll(r); err != ErrDataBareLF {
		t.Fatalf("Expected ErrDataBareLF, got: %v", err)
	}
}

// The message size limit applies to the un-stuffed content delivered to
// the backend.
func TestStrictDataReaderMessageBytesLimit(t *testing.T) {
	r, _ := newStrictReader("..12\r\n.\r\n")
	r.limited = true
	r.n = 5 // un-stuffed content is ".12\r\n" = 5 bytes
	b, err := ioutil.ReadAll(r)
	if err != nil {
		t.Fatal("ReadAll failed:", err)
	}
	if string(b) != ".12\r\n" {
		t.Fatalf("Invalid data: %q", string(b))
	}

	r, _ = newStrictReader("..12\r\n.\r\n")
	r.limited = true
	r.n = 4
	if _, err := ioutil.ReadAll(r); err != ErrDataTooLarge {
		t.Fatalf("Expected ErrDataTooLarge, got: %v", err)
	}
}

// drain must discard the rest of the payload after a stream error and
// leave pipelined commands in the connection reader.
func TestStrictDataReaderDrainAfterError(t *testing.T) {
	r, br := newStrictReader("this line is way too long\r\nmore\r\n.\r\nNOOP\r\n")
	r.lineLimit = 5

	buf := make([]byte, 16)
	if _, err := r.Read(buf); err != ErrDataLineTooLong {
		t.Fatalf("Expected ErrDataLineTooLong, got: %v", err)
	}

	r.drain()

	rest, err := ioutil.ReadAll(br)
	if err != nil {
		t.Fatal("Failed to read remaining input:", err)
	}
	if string(rest) != "NOOP\r\n" {
		t.Fatalf("Data after terminator was swallowed: %q", string(rest))
	}
}

// Reading via small buffers must not misinterpret dots or newlines.
func TestStrictDataReaderSmallReads(t *testing.T) {
	r, _ := newStrictReader("..ab\r\n.\r\n")

	var out bytes.Buffer
	buf := make([]byte, 1)
	for {
		n, err := r.Read(buf)
		out.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal("Read failed:", err)
		}
	}
	if !strings.HasPrefix(out.String(), ".ab\r\n") || out.String() != ".ab\r\n" {
		t.Fatalf("Invalid data: %q", out.String())
	}
}
