# Testing

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
