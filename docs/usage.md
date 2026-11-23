# Use

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
