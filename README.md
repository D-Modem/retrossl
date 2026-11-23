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

## Quick start

You must have Go 1.26 or later.

    go get github.com/D-Modem/retrossl

```go
import "github.com/D-Modem/retrossl"

rc := &retrossl.Config{
	GetCertificate: getCert,               // an RSA certificate
	MinVersion:     retrossl.VersionSSL20, // 0: SSL 3.0 and up
}
conn.SetReadDeadline(time.Now().Add(30 * time.Second))
c, err := retrossl.Frontend(conn, tlsConfig, rc) // a *retrossl.Conn or a *tls.Conn
```

The export suites must have 512-bit RSA keys. To let Go use them, put
`//go:debug rsa1024min=0` in the main package. Refer to
[Usage](docs/usage.md).

## Documentation

- [Usage](docs/usage.md): `Frontend`, `Server`, `Wants` and `Sniff`, and the export suites
- [What it does](docs/features.md): the versions, suites, resumption, renegotiation, compression and client certificates
- [Testing](docs/testing.md): `make test` and the in-test clients
- [Where it comes from](docs/origin.md): the origin of the code, and its specifications
- [Documentation style](docs/STYLE.md): the rules for ASD-STE100 Simplified Technical English

## Licence

BSD 3-Clause ([LICENSE](LICENSE)). `internal/rc2` is a copy from
`golang.org/x/crypto`, under its BSD licence (`internal/rc2/LICENSE`).
