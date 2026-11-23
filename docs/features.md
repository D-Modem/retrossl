# What it does

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
