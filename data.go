package smtp

import (
	"bufio"
	"fmt"
	"io"
	"io/ioutil"
)

type EnhancedCode [3]int

// SMTPError specifies the error code, enhanced error code (if any) and
// message returned by the server.
type SMTPError struct {
	Code         int
	EnhancedCode EnhancedCode
	Message      string
}

// NoEnhancedCode is used to indicate that enhanced error code should not be
// included in response.
//
// Note that RFC 2034 requires an enhanced code to be included in all 2xx, 4xx
// and 5xx responses. This constant is exported for use by extensions, you
// should probably use EnhancedCodeNotSet instead.
var NoEnhancedCode = EnhancedCode{-1, -1, -1}

// EnhancedCodeNotSet is a nil value of EnhancedCode field in SMTPError, used
// to indicate that backend failed to provide enhanced status code. X.0.0 will
// be used (X is derived from error code).
var EnhancedCodeNotSet = EnhancedCode{0, 0, 0}

func (err *SMTPError) Error() string {
	s := fmt.Sprintf("SMTP error %03d", err.Code)
	if err.Message != "" {
		s += ": " + err.Message
	}
	return s
}

func (err *SMTPError) Temporary() bool {
	return err.Code/100 == 4
}

var ErrDataTooLarge = &SMTPError{
	Code:         552,
	EnhancedCode: EnhancedCode{5, 3, 4},
	Message:      "Maximum message size exceeded",
}

// ErrDataLineTooLong is returned by the strict DATA reader when a content
// line exceeds Server.MaxLineLength bytes. The limit is applied to the
// wire form of the line, i.e. before dot-unstuffing and excluding the
// terminating CRLF.
var ErrDataLineTooLong = &SMTPError{
	Code:         552,
	EnhancedCode: EnhancedCode{5, 3, 4},
	Message:      "Maximum DATA line length exceeded",
}

// ErrDataBareLF is returned by the strict DATA reader when a content line
// is terminated by a bare LF instead of a CRLF sequence.
var ErrDataBareLF = &SMTPError{
	Code:         554,
	EnhancedCode: EnhancedCode{5, 6, 0},
	Message:      "Bare LF in DATA content, lines must end with CRLF",
}

// dataStream is the common interface of DATA payload readers.
type dataStream interface {
	io.Reader
	// streamErr reports a sticky protocol or limit error encountered while
	// reading the DATA payload, if any. A clean <CRLF>.<CRLF> termination
	// is not an error.
	streamErr() error
	// drain discards the remainder of the DATA payload, stopping right
	// after the terminating <CRLF>.<CRLF> so that any pipelined protocol
	// commands stay in the connection reader.
	drain()
}

func newDataReader(c *Conn) dataStream {
	if c.server.StrictDataReader {
		return newStrictDataReader(c)
	}

	dr := &dataReader{
		r: c.text.R,
	}

	if c.server.MaxMessageBytes > 0 {
		dr.limited = true
		dr.n = int64(c.server.MaxMessageBytes)
	}

	return dr
}

type dataReader struct {
	r     *bufio.Reader
	state int

	limited bool
	n       int64 // Maximum bytes remaining
}

// streamErr implements dataStream. The lenient reader does not track
// stream errors and always reports nil.
func (r *dataReader) streamErr() error {
	return nil
}

// drain implements dataStream.
func (r *dataReader) drain() {
	r.limited = false
	io.Copy(ioutil.Discard, r) // Make sure all the data has been consumed
}

func (r *dataReader) Read(b []byte) (n int, err error) {
	if r.limited {
		if r.n <= 0 {
			return 0, ErrDataTooLarge
		}
		if int64(len(b)) > r.n {
			b = b[0:r.n]
		}
	}

	// Code below is taken from net/textproto with only one modification to
	// not rewrite CRLF -> LF.

	// Run data through a simple state machine to
	// elide leading dots and detect End-of-Data (<CR><LF>.<CR><LF>) line.
	const (
		stateBeginLine = iota // beginning of line; initial state; must be zero
		stateDot              // read . at beginning of line
		stateDotCR            // read .\r at beginning of line
		stateCR               // read \r (possibly at end of line)
		stateData             // reading data in middle of line
		stateEOF              // reached .\r\n end marker line
	)
	for n < len(b) && r.state != stateEOF {
		var c byte
		c, err = r.r.ReadByte()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			break
		}
		switch r.state {
		case stateBeginLine:
			if c == '.' {
				r.state = stateDot
				continue
			}
			if c == '\r' {
				r.state = stateCR
				break
			}
			r.state = stateData
		case stateDot:
			if c == '\r' {
				r.state = stateDotCR
				continue
			}
			r.state = stateData
		case stateDotCR:
			if c == '\n' {
				r.state = stateEOF
				continue
			}
			r.state = stateData
		case stateCR:
			if c == '\n' {
				r.state = stateBeginLine
				break
			}
			r.state = stateData
		case stateData:
			if c == '\r' {
				r.state = stateCR
			}
		}
		b[n] = c
		n++
	}
	if err == nil && r.state == stateEOF {
		err = io.EOF
	}

	if r.limited {
		r.n -= int64(n)
	}
	return
}

// strictDataReader reads a DATA payload as a sequence of CRLF-terminated
// lines, applying RFC 5321 Section 4.5.2 dot-transparency strictly:
//
//   - The message is terminated only by a <CRLF>.<CRLF> line. The
//     terminator is recognized correctly even when the CR, LF or dot are
//     split across multiple underlying reads.
//   - A single leading dot is removed from every content line
//     (dot-unstuffing), so "..hello" is delivered as ".hello".
//   - Content lines must end with CRLF; a bare LF is rejected with
//     ErrDataBareLF.
//   - Server.MaxLineLength is enforced on the wire form of each content
//     line: before dot-unstuffing and excluding the terminating CRLF.
//     Violations are reported as ErrDataLineTooLong.
//   - Server.MaxMessageBytes is enforced on the un-stuffed content bytes
//     delivered to the backend. Violations are reported as
//     ErrDataTooLarge.
//   - A connection close before the terminating <CRLF>.<CRLF> is a short
//     EOF and is reported as io.ErrUnexpectedEOF, never as a clean end.
//   - Bytes following the terminator (e.g. pipelined commands) are never
//     consumed and stay in the connection reader.
type strictDataReader struct {
	r *bufio.Reader

	lineLimit int // Maximum wire length of a content line, excluding CRLF. 0 = unlimited.

	limited bool
	n       int64 // Maximum un-stuffed content bytes remaining.

	line []byte // Scratch buffer for the current wire line.
	buf  []byte // Un-stuffed bytes pending delivery.

	done bool   // Terminating <CRLF>.<CRLF> consumed.
	err  error  // Sticky stream error.
}

func newStrictDataReader(c *Conn) *strictDataReader {
	dr := &strictDataReader{
		r:         c.text.R,
		lineLimit: c.server.MaxLineLength,
	}

	if c.server.MaxMessageBytes > 0 {
		dr.limited = true
		dr.n = int64(c.server.MaxMessageBytes)
	}

	return dr
}

func (r *strictDataReader) Read(b []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	for len(r.buf) == 0 {
		if r.done {
			return 0, io.EOF
		}
		if err := r.nextLine(); err != nil {
			r.err = err
			return 0, err
		}
	}

	if r.limited {
		if r.n <= 0 {
			r.err = ErrDataTooLarge
			return 0, r.err
		}
		if int64(len(b)) > r.n {
			b = b[0:r.n]
		}
	}

	n := copy(b, r.buf)
	r.buf = r.buf[n:]

	if r.limited {
		r.n -= int64(n)
	}
	return n, nil
}

// nextLine reads a single wire line, detects the terminator and unstuffs
// content lines into r.buf.
func (r *strictDataReader) nextLine() error {
	r.line = r.line[:0]
	for {
		c, err := r.r.ReadByte()
		if err != nil {
			if err == io.EOF {
				// Short EOF: the connection was closed before the
				// terminating <CRLF>.<CRLF>, this is not a clean end.
				return io.ErrUnexpectedEOF
			}
			return err
		}
		r.line = append(r.line, c)
		// The wire line may carry at most 2 extra bytes for the
		// terminating CRLF, anything beyond the limit plus that is
		// definitely too long.
		if r.lineLimit > 0 && len(r.line) > r.lineLimit+2 {
			return ErrDataLineTooLong
		}
		if c == '\n' {
			break
		}
	}

	line := r.line
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return ErrDataBareLF
	}
	content := line[:len(line)-2]

	if len(content) == 1 && content[0] == '.' {
		// <CRLF>.<CRLF> end-of-data marker.
		r.done = true
		return nil
	}
	if len(content) > 0 && content[0] == '.' {
		// Dot-stuffed line: remove exactly one leading dot.
		content = content[1:]
	}

	out := make([]byte, 0, len(content)+2)
	out = append(out, content...)
	out = append(out, '\r', '\n')
	r.buf = out
	return nil
}

// streamErr implements dataStream.
func (r *strictDataReader) streamErr() error {
	return r.err
}

// drain implements dataStream. Limits and the sticky error are lifted so
// that the remainder of the payload can be discarded; reading stops right
// after the terminating <CRLF>.<CRLF>.
func (r *strictDataReader) drain() {
	r.limited = false
	r.lineLimit = 0
	r.err = nil
	io.Copy(ioutil.Discard, r) // Make sure all the data has been consumed
}
