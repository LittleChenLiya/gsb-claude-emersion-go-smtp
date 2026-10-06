package smtp

import (
	"bufio"
	"fmt"
	"io"
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

// ErrDataLineTooLong is returned by the strict DATA reader (see
// Server.StrictDataReader) when a content line exceeds
// Server.MaxLineLength. The limit is enforced on the wire form of the
// line, i.e. before dot-unstuffing, excluding the trailing CRLF.
var ErrDataLineTooLong = &SMTPError{
	Code:         552,
	EnhancedCode: EnhancedCode{5, 3, 4},
	Message:      "Maximum line length exceeded",
}

// ErrDataInvalidDot is returned by the strict DATA reader (see
// Server.StrictDataReader) when a line begins with a single dot that is
// neither the <CRLF>.<CRLF> terminator nor a stuffed ("..") dot.
var ErrDataInvalidDot = &SMTPError{
	Code:         554,
	EnhancedCode: EnhancedCode{5, 6, 0},
	Message:      "Invalid use of a single dot at the beginning of a line",
}

// messageReader is a reader for the DATA command message payload.
type messageReader interface {
	io.Reader

	// drainMode switches the reader into drain mode: size/line limits are
	// lifted and sticky errors are cleared so that the rest of the message
	// up to (and including) the terminator can be discarded. This keeps
	// the connection in sync: commands pipelined after the message stay
	// in the connection reader and are handled as commands afterwards.
	drainMode()
}

// newMessageReader returns the reader for the DATA payload. If
// Server.StrictDataReader is set, a strictDataReader is used, otherwise
// the historical lenient dataReader is kept.
func newMessageReader(c *Conn) messageReader {
	if c.server.StrictDataReader {
		// The connection-level line limit is disabled while the message
		// is read: strictDataReader enforces the content line limit
		// itself, so that an overlong line fails the transaction with a
		// proper reply instead of killing the connection. Conn.reset
		// restores the connection-level limit.
		c.lineLimitReader.LineLimit = 0
		return newStrictDataReader(c)
	}
	return newDataReader(c)
}

type dataReader struct {
	r     *bufio.Reader
	state int

	limited bool
	n       int64 // Maximum bytes remaining
}

func newDataReader(c *Conn) *dataReader {
	dr := &dataReader{
		r: c.text.R,
	}

	if c.server.MaxMessageBytes > 0 {
		dr.limited = true
		dr.n = int64(c.server.MaxMessageBytes)
	}

	return dr
}

// drainMode implements messageReader.
func (r *dataReader) drainMode() {
	r.limited = false
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

// strictDataReader is a strict reader for the DATA command payload,
// enabled via Server.StrictDataReader.
//
// Compared to the lenient dataReader, it:
//   - recognizes only <CRLF>.<CRLF> as the end-of-data terminator and
//     detects it reliably even when the dot and the line breaks are split
//     across multiple input chunks (the reader works byte-by-byte on top
//     of the buffered connection reader);
//   - reverses dot-stuffing: a line beginning with ".." is delivered with
//     a single leading dot (e.g. "..hello" is delivered as ".hello");
//   - rejects a line beginning with a single dot that is neither the
//     terminator nor a stuffed dot (ErrDataInvalidDot);
//   - enforces a per-line length limit (Server.MaxLineLength): the limit
//     is counted on the wire form of the line, i.e. before dot-unstuffing
//     and excluding the trailing CRLF (ErrDataLineTooLong);
//   - treats a connection EOF before the terminator (a short EOF) as
//     io.ErrUnexpectedEOF, so a truncated message is never reported as
//     successfully received.
//
// Server.MaxMessageBytes (when set) is counted on the decoded message
// bytes, i.e. after dot-unstuffing, matching the lenient reader.
type strictDataReader struct {
	r     *bufio.Reader
	state int

	limited bool
	n       int64 // Maximum message bytes remaining (after unstuffing)

	lineLimit int // Maximum content line length in wire bytes, 0 = unlimited
	lineLen   int // Wire bytes seen on the current line so far

	discarding bool   // drain mode: consume up to the terminator without checks
	err        error // sticky error
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

// drainMode implements messageReader.
func (r *strictDataReader) drainMode() {
	r.limited = false
	r.discarding = true
	r.err = nil
}

func (r *strictDataReader) Read(b []byte) (n int, err error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.limited {
		if r.n <= 0 {
			return 0, ErrDataTooLarge
		}
		if int64(len(b)) > r.n {
			b = b[0:r.n]
		}
	}

	// Run data through a simple state machine to detect the
	// End-of-Data (<CR><LF>.<CR><LF>) line and to elide stuffed dots.
	// Unlike the lenient dataReader, CRLF is not rewritten and a lone
	// dot line that is not the terminator is rejected.
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
				// A short EOF (connection closed before the
				// <CRLF>.<CRLF> terminator) is not a successful
				// end of data.
				err = io.ErrUnexpectedEOF
			}
			break
		}

		emit := true
		switch r.state {
		case stateBeginLine:
			if c == '.' {
				r.state = stateDot
				emit = false
				break
			}
			if c == '\r' {
				r.state = stateCR
				break
			}
			r.state = stateData
		case stateDot:
			if c == '.' {
				// Dot-stuffing: ".." at the beginning of a line is
				// delivered as a single dot ("..hello" -> ".hello").
				r.state = stateData
				break
			}
			if c == '\r' {
				r.state = stateDotCR
				emit = false
				break
			}
			// A single dot at the beginning of a line that is neither
			// the terminator nor a stuffed dot is invalid.
			if !r.discarding {
				r.err = ErrDataInvalidDot
			}
			r.state = stateData
			emit = false
		case stateDotCR:
			if c == '\n' {
				r.state = stateEOF
				emit = false
				break
			}
			if !r.discarding {
				r.err = ErrDataInvalidDot
			}
			r.state = stateData
			emit = false
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

		if r.err != nil {
			break
		}

		if !r.discarding {
			// Content line length accounting: the limit is enforced on
			// the wire form of the line, i.e. before dot-unstuffing,
			// excluding the CRLF line terminator.
			if c == '\n' {
				r.lineLen = 0
			} else if c != '\r' {
				r.lineLen++
				if r.lineLimit > 0 && r.lineLen > r.lineLimit {
					r.err = ErrDataLineTooLong
					break
				}
			}
		}

		if !emit {
			continue
		}
		b[n] = c
		n++
	}

	if err == nil {
		if r.err != nil {
			err = r.err
		} else if r.state == stateEOF {
			err = io.EOF
		}
	}

	if r.limited {
		r.n -= int64(n)
	}
	return
}
