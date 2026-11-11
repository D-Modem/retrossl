# retrossl

A small SSL 2.0, SSL 3.0 and TLS 1.0 server in Go, for the old clients that
Go's `crypto/tls` turns away. D-Modem uses it in front of the BBS's services
and the [WebOne-go](https://github.com/D-Modem/WebOne-go) proxy, so that
period browsers, chat clients and mail programs can still connect.

It serves:

* **TLS 1.0 after an SSL 2.0-format hello.** AIM 6.2 to 7.5 (through NSS),
  IE 5 and 6 and early Opera open this way. `crypto/tls` can't take such a
  hello, and it can't be rewritten for it, because TLS's Finished messages
  sign the hello's exact bytes.
* **SSL 3.0**, in either hello: Netscape 3 and 4, IE 3 to 6 with their
  defaults, old Java and mail clients.
* **SSL 2.0**, when it is turned on: Netscape 1 and 2, IE 2, and clients
  that have SSL 3.0 turned off.
* **Export cipher suites** (40- and 56-bit), for export builds that offer
  nothing else.

Everything newer belongs on `crypto/tls`. `Frontend` looks at a connection's
first bytes and hands it to whichever fits.

These protocols are broken. They are here because the clients have nothing
else. Treat the traffic behind them as readable by anyone on the path, and
tell users so.

## Use

```go
import "github.com/D-Modem/retrossl"

rc := &retrossl.Config{
	GetCertificate: getCert,             // an RSA certificate
	MinVersion:     retrossl.VersionSSL20, // 0: SSL 3.0 and up
}
conn.SetReadDeadline(time.Now().Add(30 * time.Second))
c, err := retrossl.Frontend(conn, tlsConfig, rc) // a *retrossl.Conn or a *tls.Conn
```

`retrossl.Server(conn, rc)` serves a connection by retrossl whatever its
hello, and `retrossl.Wants(firstBytes)` or `retrossl.Sniff(bufReader)` tell
whether retrossl should take it: an SSL 2.0-format hello, or a record hello
that offers SSL 3.0 at best. TLS 1.0 record hellos go to `crypto/tls`, so
set its `MinVersion` to `tls.VersionTLS10` if those clients should be
served.

A `*retrossl.Conn` is a `net.Conn`. `ConnectionState()` gives the version,
cipher and server name once the handshake is done.

**Export suites need small keys.** Their temporary RSA keys are 512 bits
(1024 for the 56-bit suites), which Go refuses unless the program allows it.
Put this in the main package:

```go
//go:debug rsa1024min=0
```

or `godebug rsa1024min=0` in its `go.mod`. Without it, the 40-bit suites are
left out, and clients that offer nothing else are refused.

## What it does

| | |
|---|---|
| Versions | SSL 2.0 (off unless `MinVersion` is `VersionSSL20`), SSL 3.0, TLS 1.0 |
| Key exchange | RSA, with a signed temporary key for export suites when the certificate's key is larger than they allow |
| SSL 3.0 / TLS 1.0 suites | AES-128 and AES-256 CBC, 3DES, RC4-SHA, RC4-MD5, DES, EXP1024-RC4-SHA, EXP1024-DES, EXP-RC4-MD5, EXP-DES40 |
| SSL 2.0 ciphers | DES-EDE3-CBC, RC4-128, DES-CBC, RC4-128-EXPORT40 (all with MD5) |
| Extensions | secure renegotiation's empty `renegotiation_info` (TLS only), server name read |

There is no session resumption, renegotiation, compression, client
certificate, RC2 or IDEA.

**SSL 2.0 sends only the server's own certificate**, not its chain. An SSL
2.0 client therefore has to trust that certificate or its direct issuer. With
the D-Modem BBS's CA, whose sites are signed by a sub-CA, SSL 2.0 clients
need the sub-CA installed, not only the root.

A client that offers SSL 3.0 or TLS in an SSL 2.0-format hello, but whose
version or ciphers aren't served, gets SSL 2.0 if that is on. Such clients
mark their SSL 2.0 key exchange to detect a downgrade; retrossl does not
check the mark, since it only falls back when the newer protocol is off.

## Testing

`go test ./...` runs Go's own TLS client at TLS 1.0, and in-test clients for
SSL 3.0 and TLS 1.0 (both hello formats, every suite) and SSL 2.0 (every
cipher). The in-test clients follow the specifications, but they share the
package's record code, so trying real old clients is still worth doing.

## Where it comes from

The TLS 1.0 server started as the D-Modem BBS's `internal/oldtls` package,
and is released here by the D-Modem authors under the BSD 3-Clause licence
(see [LICENSE](LICENSE)), so that it can be used by BSD-licensed programs
such as WebOne-go. SSL 3.0, SSL 2.0 and the export suites were written from
the protocols' specifications: the SSL 3.0 draft (RFC 6101), the SSL 2.0
draft, RFC 2246 and the 56-bit export draft.
