# Where it comes from

The TLS 1.0 server started as the `internal/oldtls` package of the
D-Modem BBS. The D-Modem authors release it here under the BSD 3-Clause
licence (refer to [LICENSE](../LICENSE)). Thus BSD-licensed programs, for
example WebOne-go, can use it. We wrote SSL 3.0, SSL 2.0 and the export
suites from the specifications of the protocols: the SSL 3.0 draft
(RFC 6101), the SSL 2.0 draft, RFC 2246, RFC 3749, RFC 5746 and the
56-bit export draft. We wrote IDEA from its paper. RC2 (`internal/rc2`)
is a copy from `golang.org/x/crypto` of Go, under its BSD licence
(`internal/rc2/LICENSE`), because x/crypto keeps it internal.
