package retrossl

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
)

// Wants reports whether a connection that opens with b should be served
// by this package rather than crypto/tls: an SSL 2.0-format hello (any
// version), or a hello in a record that offers SSL 3.0 at best.  b should
// hold the first 11 bytes (3 are enough for an SSL 2.0 hello).
func Wants(b []byte) bool {
	if len(b) >= 3 && b[0]&0x80 != 0 && b[2] == 1 {
		return true
	}
	return len(b) >= 11 && b[0] == recHandshake && b[1] == 3 && b[5] == hsClientHello &&
		b[9] == 3 && b[10] == 0
}

// Sniff peeks at the start of r, a connection's reader, and says whether
// this package should serve it (see Wants).  It reads nothing away.
func Sniff(r *bufio.Reader) (bool, error) {
	b, err := r.Peek(3)
	if err != nil {
		return false, err
	}
	if b[0]&0x80 != 0 || b[0] != recHandshake {
		return Wants(b), nil
	}
	if b, err = r.Peek(11); err != nil && err != io.EOF {
		return false, err
	}
	return Wants(b), nil
}

// peeked is a connection whose first bytes were read into r.
type peeked struct {
	net.Conn
	r *bufio.Reader
}

func (p *peeked) Read(b []byte) (int, error) { return p.r.Read(b) }

// Frontend is c served by this package when its hello needs it (see
// Wants), and by crypto/tls with tc otherwise: a *Conn or a *tls.Conn.  It
// waits for the client's first bytes, so the caller should set a read
// deadline first.
func Frontend(c net.Conn, tc *tls.Config, rc *Config) (net.Conn, error) {
	p := &peeked{Conn: c, r: bufio.NewReader(c)}
	old, err := Sniff(p.r)
	if err != nil {
		return nil, err
	}
	if old {
		return Server(p, rc), nil
	}
	return tls.Server(p, tc), nil
}
