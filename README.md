# go-smtp

[![Go Reference](https://pkg.go.dev/badge/github.com/emersion/go-smtp.svg)](https://pkg.go.dev/github.com/emersion/go-smtp)

An ESMTP client and server library written in Go.

## Features

* ESMTP client & server implementing [RFC 5321]
* Support for additional SMTP extensions such as [AUTH] and [PIPELINING]
* UTF-8 support for subject and message
* [LMTP] support

## Client capability snapshots

The client exposes the EHLO capabilities confirmed for the current session as
an explicit, immutable snapshot (`Client.Capabilities`). A mail transaction is
bound to the snapshot taken at MAIL time (`Client.TransactionCapabilities`):
every command of the transaction uses exactly those capabilities, and later
changes to the shared capability map cannot leak into it. The snapshot records
the session phase (plaintext or post-STARTTLS) but never stores authentication
values.

A successful STARTTLS invalidates all previously confirmed capabilities: until
a new EHLO completes, neither AUTH nor SMTPUTF8 (nor any other extension) is
considered available, and a failed EHLO is never marked ready and never lets
the client enter MAIL.

The canonical STARTTLS workflow uses five commands:

```
EHLO      ; confirm pre-TLS capabilities (e.g. STARTTLS, SMTPUTF8)
STARTTLS  ; invalidate them
EHLO      ; confirm post-TLS capabilities on the encrypted connection
MAIL      ; bind the transaction to the post-TLS snapshot
QUIT
```

Run the capability snapshot acceptance tests (scripted local connections
only) with:

```
go test -run 'TestClientCapabilitySnapshot' .
```

## Relationship with net/smtp

The Go standard library provides a SMTP client implementation in `net/smtp`.
However `net/smtp` is frozen: it's not getting any new features. go-smtp
provides a server implementation and a number of client improvements.

## Contributing

See [CONTRIBUTING.md] for contribution guidelines.

## Licence

MIT

[RFC 5321]: https://tools.ietf.org/html/rfc5321
[AUTH]: https://tools.ietf.org/html/rfc4954
[PIPELINING]: https://tools.ietf.org/html/rfc2920
[LMTP]: https://tools.ietf.org/html/rfc2033
[CONTRIBUTING.md]: https://github.com/emersion/.github/blob/main/CONTRIBUTING.md
