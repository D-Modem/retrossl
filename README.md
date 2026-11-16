# retrossl

retrossl is a small SSL 2.0, SSL 3.0 and TLS 1.0 server in Go. It is
for the old clients that the `crypto/tls` package of Go refuses. D-Modem
uses it in front of the services of the BBS and the
[WebOne-go](https://github.com/D-Modem/WebOne-go) proxy. Thus old
browsers, chat clients and mail programs can still connect.

It serves these protocols:

* **TLS 1.0 after an SSL 2.0-format hello.** AIM 6.2 to 7.5 (through
  NSS), IE 5 and 6 and early Opera start the connection in this way.
  `crypto/tls` cannot accept this type of hello. Also, you cannot change
  `crypto/tls` to accept it, because the TLS Finished messages sign the
  exact bytes of the hello.
* **SSL 3.0**, in the two hello formats: Netscape 3 and 4, IE 3 to 6 with
  their defaults, old Java and mail clients.
* **SSL 2.0**, if you enable it: Netscape 1 and 2, IE 2, and clients that
  have SSL 3.0 disabled.
* **Export cipher suites** (40- and 56-bit), for export builds that offer
  no other suites.

All newer clients must use `crypto/tls`. `Frontend` examines the first
bytes of a connection and sends it to the applicable server.

**These protocols are not secure.** They are here only because the
clients have no other protocols. Each person on the path can possibly
read the traffic behind them. Tell the users about this risk.

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

`retrossl.Server(conn, rc)` serves a connection with retrossl, for all
types of hello. `retrossl.Wants(firstBytes)` or `retrossl.Sniff(bufReader)`
tell if retrossl must accept the connection. retrossl accepts an SSL
2.0-format hello, or a record hello that offers a maximum of SSL 3.0.
TLS 1.0 record hellos go to `crypto/tls`. Thus, to serve those clients,
set the `MinVersion` of `crypto/tls` to `tls.VersionTLS10`.

A `*retrossl.Conn` is a `net.Conn`. After the handshake, `ConnectionState()`
gives the version, the cipher and the server name.

**Export suites must have small keys.** Their temporary RSA keys are 512
bits (1024 for the 56-bit suites). Go refuses these keys, unless the
program lets it use them. Put this line in the main package:

```go
//go:debug rsa1024min=0
```

Alternatively, put `godebug rsa1024min=0` in its `go.mod`. Without this
setting, retrossl does not offer the 40-bit suites. It refuses clients
that offer only these suites.

## What it does

| | |
|---|---|
| Versions | SSL 2.0 (disabled unless `MinVersion` is `VersionSSL20`), SSL 3.0, TLS 1.0 |
| Key exchange | RSA. For export suites, a signed temporary key if the key of the certificate is larger than the suites permit |
| SSL 3.0 / TLS 1.0 suites | AES-128 and AES-256 CBC, 3DES, RC4-SHA, RC4-MD5, IDEA, DES, EXP1024-RC4-SHA, EXP1024-DES, EXP-RC4-MD5, EXP-RC2-CBC-MD5, EXP-DES40 |
| SSL 2.0 ciphers | DES-EDE3-CBC, RC4-128, IDEA-CBC, RC2-CBC, DES-CBC, RC4-128-EXPORT40, RC2-CBC-EXPORT40 (all with MD5) |
| Session resumption | by session id, for all three versions, with `Config.SessionCache = retrossl.NewSessionCache(size, ttl)` |
| Renegotiation | started by the client, or requested with `Conn.RequestRenegotiation()` (SSL 3.0 and TLS). Refer to the text below |
| Compression | DEFLATE (RFC 3749), if `Config.Compression` is set |
| Client certificates | `Config.ClientAuth`, `ClientCAs` and `VerifyPeerCertificate`, as in `crypto/tls`, for all three versions (RSA keys) |
| Extensions | `renegotiation_info` (RFC 5746), and retrossl reads the server name |

**Renegotiation** is secure by default. Clients that offered RFC 5746 in
their first hello (most clients from 2010 and after) can renegotiate.
retrossl refuses renegotiation from other clients. `RenegotiateInsecure`
lets all clients renegotiate, as servers did before 2009. But this lets
an attacker on the path put their own request in front of the request of
the client (CVE-2009-3555). `RenegotiateNever` refuses all renegotiation.

**Compression** is disabled by default. If a server compresses data
before it encrypts the data, an attacker who can add to the requests of
a client can learn its secrets, for example cookies (CRIME). Also, few
old clients offered compression. Most of these clients used OpenSSL.

**Client certificates** from SSL 2.0 clients come without a chain. Thus
their issuer must be in `ClientCAs`. A resumed session keeps the
certificate of the client from its first handshake.

**SSL 2.0 sends only the certificate of the server**, not its chain. Thus
an SSL 2.0 client must trust that certificate or its direct issuer. The
CA of the D-Modem BBS signs its sites with a sub-CA. Thus, SSL 2.0
clients must have the sub-CA installed, not only the root.

A client can offer SSL 3.0 or TLS in an SSL 2.0-format hello, but with a
version or ciphers that retrossl does not serve. If SSL 2.0 is enabled,
such a client gets SSL 2.0. These clients put a mark in their SSL 2.0 key
exchange to detect a downgrade. retrossl does not check the mark, because
it falls back only when the newer protocol is disabled.

## Testing

`make test` runs gofmt, vet, then `go test -race ./...`. The tests use
these clients:

- The TLS client of Go, at TLS 1.0.
- In-test clients for SSL 3.0 and TLS 1.0 (the two hello formats, all
  suites).
- An in-test client for SSL 2.0 (all ciphers).

The tests include resumption, renegotiation, compression and client
certificates. The tests check IDEA against its published test vector,
RC2 against OpenSSL, and the decompressor against records that zlib
compressed. The in-test clients follow the specifications. But they use
the same record code as the package. Thus it is still useful to test
with real old clients. `make cover` writes the coverage of the tests to
`cover.html`.

## Where it comes from

The TLS 1.0 server started as the `internal/oldtls` package of the
D-Modem BBS. The D-Modem authors release it here under the BSD 3-Clause
licence (refer to [LICENSE](LICENSE)). Thus BSD-licensed programs, for
example WebOne-go, can use it. We wrote SSL 3.0, SSL 2.0 and the export
suites from the specifications of the protocols: the SSL 3.0 draft
(RFC 6101), the SSL 2.0 draft, RFC 2246, RFC 3749, RFC 5746 and the
56-bit export draft. We wrote IDEA from its paper. RC2 (`internal/rc2`)
is a copy from `golang.org/x/crypto` of Go, under its BSD licence
(`internal/rc2/LICENSE`), because x/crypto keeps it internal.
