package smtp

import (
	"crypto/tls"
	"strings"
)

// CapabilitySnapshot is an explicit, immutable snapshot of the ESMTP
// capabilities confirmed by the server in a single EHLO/HELO exchange.
//
// A snapshot records the session phase (plaintext or post-STARTTLS) in
// which the capabilities were confirmed, but it never stores
// authentication values: SASL credentials and the MAIL AUTH= parameter
// are supplied per command and are never part of a snapshot.
//
// A snapshot is a defensive copy taken at confirmation time: mutating the
// client's shared capability map (or completing a new EHLO) afterwards
// does not alter it. A mail transaction started by Client.Mail is bound
// to the snapshot taken at MAIL time, so every command of the
// transaction uses exactly the capabilities confirmed for it.
type CapabilitySnapshot struct {
	id    uint64
	tls   bool
	ready bool
	ext   map[string]string
}

// ID returns the identity of the confirmation exchange the snapshot was
// taken from. The ID changes whenever the capabilities are re-confirmed
// (EHLO/HELO) or invalidated (STARTTLS) within the client session.
func (s *CapabilitySnapshot) ID() uint64 {
	return s.id
}

// Ready reports whether the snapshot comes from a successfully completed
// EHLO/HELO exchange. A failed EHLO, or a STARTTLS that has not been
// followed by a new EHLO yet, yields a snapshot that is not ready and
// carries no capabilities.
func (s *CapabilitySnapshot) Ready() bool {
	return s.ready
}

// TLS reports whether the snapshot was confirmed on an encrypted
// connection (after STARTTLS or on an implicit-TLS connection).
func (s *CapabilitySnapshot) TLS() bool {
	return s.tls
}

// Extension reports whether the server advertised the given extension in
// this snapshot. The extension name is case-insensitive. If the
// extension is supported, Extension also returns its parameters.
func (s *CapabilitySnapshot) Extension(ext string) (bool, string) {
	if !s.ready {
		return false, ""
	}
	ext = strings.ToUpper(ext)
	param, ok := s.ext[ext]
	return ok, param
}

// SupportsAuth checks whether the snapshot advertises the given
// authentication mechanism.
func (s *CapabilitySnapshot) SupportsAuth(mech string) bool {
	ok, mechs := s.Extension("AUTH")
	if !ok {
		return false
	}
	for _, m := range strings.Split(mechs, " ") {
		if strings.EqualFold(m, mech) {
			return true
		}
	}
	return false
}

// snapshotCaps builds an explicit snapshot of the capabilities currently
// confirmed for the session. The snapshot is a defensive copy: later
// changes to the client's shared capability map do not leak into it.
func (c *Client) snapshotCaps() *CapabilitySnapshot {
	s := &CapabilitySnapshot{
		id:    c.helloGen,
		ready: c.didHello && c.helloError == nil && !c.capsStale,
	}
	if _, ok := c.conn.(*tls.Conn); ok {
		s.tls = true
	}
	if s.ready && len(c.ext) > 0 {
		s.ext = make(map[string]string, len(c.ext))
		for k, v := range c.ext {
			s.ext[k] = v
		}
	}
	return s
}

// Capabilities returns an explicit snapshot of the EHLO capabilities
// currently confirmed for this session.
//
// The method performs no network I/O: it reflects the last completed
// EHLO/HELO exchange. After a successful STARTTLS the previously
// confirmed capabilities are invalidated and the returned snapshot is
// not ready until a new EHLO completes. A failed EHLO never produces a
// ready snapshot.
func (c *Client) Capabilities() *CapabilitySnapshot {
	return c.snapshotCaps()
}

// TransactionCapabilities returns the capability snapshot bound to the
// current mail transaction, or nil if no transaction is in progress.
//
// The returned snapshot is the one taken by the Client.Mail call that
// started the transaction: all commands of the transaction use exactly
// these capabilities, regardless of later changes to the session
// capabilities.
func (c *Client) TransactionCapabilities() *CapabilitySnapshot {
	return c.txCaps
}
