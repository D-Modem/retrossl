package retrossl

import (
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"io"
	"slices"
	"sync"
)

type clientHello struct {
	version     uint16
	random      []byte
	suites      []uint16
	sni         string
	secureReneg bool

	v2        bool     // the hello was SSL 2.0's
	ssl2Kinds []uint32 // its SSL 2.0 cipher kinds
	challenge []byte   // its challenge
}

func (c *Conn) addTranscript(m []byte) { c.transcript = append(c.transcript, m...) }

func (c *Conn) serverHandshake() error {
	ch, err := c.readClientHello()
	if err != nil {
		return err
	}
	cfg := c.cfg
	v := min(ch.version, cfg.maxVersion())
	tlsOK := ch.version >= VersionSSL30 && v >= max(cfg.minVersion(), VersionSSL30)
	ssl2OK := ch.v2 && cfg.minVersion() <= VersionSSL20
	if !tlsOK && !ssl2OK {
		if ch.v2 && ch.version == VersionSSL20 {
			c.ssl2 = true
			c.writeError2(ssl2NoCipher)
			return fail(0, "the client offers only SSL 2.0, which is off")
		}
		return fail(alertProtocolVersion, "the client offers %s, which is off", VersionName(ch.version))
	}
	if tlsOK {
		c.out.version = v
	} else {
		v = VersionSSL20
	}
	cert, err := cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: ch.sni, CipherSuites: ch.suites,
		SupportedVersions: []uint16{v}, Conn: c.Conn})
	if err != nil {
		if v == VersionSSL20 {
			c.ssl2 = true
		}
		return fail(alertInternal, "certificate: %v", err)
	}
	key, ok := rsaKey(cert)
	if !ok {
		if v == VersionSSL20 {
			c.ssl2 = true
		}
		return fail(alertHandshakeFailure, "the certificate's key is not RSA, which these clients need")
	}
	if tlsOK {
		if s := c.pickSuite(ch, key.Size()*8); s != nil {
			return c.handshake3(ch, v, s, cert, key)
		}
		if !ssl2OK {
			return fail(alertHandshakeFailure, "no cipher suite in common: the client offers %04x", ch.suites)
		}
	}
	// An SSL 2.0 hello whose SSL 3.0 or TLS isn't served: SSL 2.0 it is.
	return c.handshake2(ch, cert, key)
}

// pickSuite is the best suite the client offers, or nil.
func (c *Conn) pickSuite(ch *clientHello, keyBits int) *suite {
	for i := range suites {
		s := &suites[i]
		if !slices.Contains(ch.suites, s.id) || (c.cfg.CipherSuites != nil && !slices.Contains(c.cfg.CipherSuites, s.id)) {
			continue
		}
		if s.export != 0 && keyBits > s.export {
			if _, err := tempKey(s.export); err != nil {
				continue
			}
		}
		return s
	}
	return nil
}

func (c *Conn) handshake3(ch *clientHello, v uint16, s *suite, cert *tls.Certificate, key *rsa.PrivateKey) error {
	sr := random(32)
	hello := binary.BigEndian.AppendUint16(nil, v)
	hello = append(hello, sr...)
	hello = append(hello, 0) // no session id: nothing is resumed
	hello = binary.BigEndian.AppendUint16(hello, s.id)
	hello = append(hello, 0)
	if ch.secureReneg && v >= VersionTLS10 {
		hello = append(hello, 0, 5, 0xff, 0x01, 0, 1, 0) // renegotiation_info, empty
	}
	var chain []byte
	for _, der := range cert.Certificate {
		chain = appendU24(chain, len(der))
		chain = append(chain, der...)
	}
	flight := msg(hsServerHello, hello)
	flight = append(flight, msg(hsCertificate, appendU24(nil, len(chain)), chain...)...)

	kx := key // the key the pre-master secret comes under
	if s.export != 0 && key.Size()*8 > s.export {
		// Export: a temporary key small enough, signed by the certificate's.
		tmp, err := tempKey(s.export)
		if err != nil {
			return fail(alertInternal, "export key: %v", err)
		}
		params := appendVec16(nil, tmp.N.Bytes())
		params = appendVec16(params, bigEndianInt(tmp.E))
		m, h := md5.Sum(cat(ch.random, sr, params)), sha1.Sum(cat(ch.random, sr, params))
		sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.MD5SHA1, cat(m[:], h[:]))
		if err != nil {
			return fail(alertInternal, "signing the export key: %v", err)
		}
		flight = append(flight, msg(hsServerKeyExchange, appendVec16(params, sig))...)
		kx = tmp
	}
	flight = append(flight, msg(hsServerDone, nil)...)
	c.addTranscript(flight)
	if err := c.writeRecord(recHandshake, flight); err != nil {
		return err
	}

	m, err := c.readHandshake()
	if err != nil {
		return err
	}
	if m[0] != hsClientKeyExchange {
		return fail(alertUnexpected, "handshake message %d, not the key exchange", m[0])
	}
	c.addTranscript(m)
	ct, k := m[4:], kx.Size()
	// TLS puts the length first; SSL 3.0 doesn't, though some clients do.
	if len(ct) == k+2 && int(binary.BigEndian.Uint16(ct)) == k {
		ct = ct[2:]
	}
	if len(ct) != k {
		return fail(alertDecode, "key exchange of %d bytes", len(m)-4)
	}
	// A bad decryption, or the wrong version in it, goes on with a random
	// secret, in the same time, and fails at Finished (Bleichenbacher).
	pre, alt := random(48), random(48)
	if err := rsa.DecryptPKCS1v15SessionKey(nil, kx, ct, pre); err != nil {
		return fail(alertInternal, "%v", err)
	}
	vOK := subtle.ConstantTimeByteEq(pre[0], 3) &
		(subtle.ConstantTimeByteEq(pre[1], byte(ch.version)) | subtle.ConstantTimeByteEq(pre[1], byte(v)))
	subtle.ConstantTimeCopy(1-vOK, pre, alt)

	ms := masterSecret(v, pre, ch.random, sr)
	ck, sk := s.keys(v, ms, ch.random, sr)
	clientFinished := finished(v, ms, c.transcript, true)

	if len(c.hs) != 0 {
		return fail(alertUnexpected, "handshake data before ChangeCipherSpec")
	}
	typ, data, err := c.readRecord()
	if err != nil {
		return err
	}
	if typ == recAlert {
		return alertIn(data)
	}
	if typ != recCCS || len(data) != 1 || data[0] != 1 {
		return fail(alertUnexpected, "record type %d, not ChangeCipherSpec", typ)
	}
	c.in = s.newHalf(v, ck, false)
	if m, err = c.readHandshake(); err != nil {
		return err
	}
	if m[0] != hsFinished || len(m) != 4+len(clientFinished) {
		return fail(alertUnexpected, "handshake message %d, not Finished", m[0])
	}
	if subtle.ConstantTimeCompare(m[4:], clientFinished) != 1 {
		return fail(alertDecrypt, "the client's Finished is wrong")
	}
	c.addTranscript(m)

	if err := c.writeRecord(recCCS, []byte{1}); err != nil {
		return err
	}
	c.outMu.Lock()
	c.out = s.newHalf(v, sk, true)
	c.outMu.Unlock()
	if err := c.writeRecord(recHandshake, msg(hsFinished, finished(v, ms, c.transcript, false))); err != nil {
		return err
	}
	c.transcript = nil
	c.state = State{Version: v, CipherSuite: uint32(s.id), CipherName: s.name, ServerName: ch.sni, V2Hello: ch.v2}
	return nil
}

// Temporary RSA keys for the export suites, made once.
var tmpKeys struct {
	sync.Mutex
	keys map[int]*rsa.PrivateKey
	errs map[int]error
}

// tempKey is the temporary key of bits bits.  Go refuses keys under 1024
// bits unless the program has //go:debug rsa1024min=0.
func tempKey(bits int) (*rsa.PrivateKey, error) {
	tmpKeys.Lock()
	defer tmpKeys.Unlock()
	if tmpKeys.keys == nil {
		tmpKeys.keys, tmpKeys.errs = map[int]*rsa.PrivateKey{}, map[int]error{}
	}
	if k, ok := tmpKeys.keys[bits]; ok {
		return k, nil
	}
	if err, ok := tmpKeys.errs[bits]; ok {
		return nil, err
	}
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		tmpKeys.errs[bits] = err
		return nil, err
	}
	tmpKeys.keys[bits] = k
	return k, nil
}

func appendU24(b []byte, n int) []byte { return append(b, byte(n>>16), byte(n>>8), byte(n)) }

func appendVec16(b, v []byte) []byte {
	return append(binary.BigEndian.AppendUint16(b, uint16(len(v))), v...)
}

func bigEndianInt(n int) []byte {
	var b []byte
	for ; n > 0; n >>= 8 {
		b = append([]byte{byte(n)}, b...)
	}
	return b
}

// msg is a handshake message.
func msg(typ uint8, body []byte, more ...byte) []byte {
	m := appendU24([]byte{typ}, len(body)+len(more))
	return append(append(m, body...), more...)
}

// readClientHello reads the hello, in either format.
func (c *Conn) readClientHello() (*clientHello, error) {
	b, err := c.br.Peek(1)
	if err != nil {
		return nil, err
	}
	if b[0]&0x80 != 0 {
		return c.readV2Hello()
	}
	m, err := c.readHandshake()
	if err != nil {
		return nil, err
	}
	if m[0] != hsClientHello {
		return nil, fail(alertUnexpected, "handshake message %d, not ClientHello", m[0])
	}
	c.addTranscript(m)
	ch, err := parseClientHello(m[4:])
	if err == nil && ch.version <= VersionSSL30 {
		c.out.version = VersionSSL30 // for any alert before the version is settled
	}
	return ch, err
}

// readV2Hello reads an SSL 2.0-format ClientHello.  For SSL 3.0 and TLS,
// its message (the bytes after the two of the record's length) is the
// handshake's first, and its challenge, right-aligned, the client random.
func (c *Conn) readV2Hello() (*clientHello, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[0]&0x7f)<<8 | int(hdr[1])
	if n < 9 {
		return nil, fail(alertDecode, "SSL 2.0 hello of %d bytes", n)
	}
	m := make([]byte, n)
	if _, err := io.ReadFull(c.br, m); err != nil {
		return nil, err
	}
	if m[0] != 1 {
		return nil, fail(alertUnexpected, "SSL 2.0 message %d, not CLIENT-HELLO", m[0])
	}
	c.addTranscript(m)
	c.in2.seq = 1 // SSL 2.0 counts the hello
	u := func(i int) int { return int(binary.BigEndian.Uint16(m[i:])) }
	specLen, sidLen, chalLen := u(3), u(5), u(7)
	if 9+specLen+sidLen+chalLen != n || specLen%3 != 0 || chalLen < 16 || chalLen > 32 {
		return nil, fail(alertDecode, "bad SSL 2.0 hello")
	}
	ch := &clientHello{version: uint16(u(1)), v2: true}
	if ch.version <= VersionSSL30 {
		c.out.version = VersionSSL30
	}
	specs := m[9 : 9+specLen]
	for i := 0; i < len(specs); i += 3 {
		if specs[i] == 0 { // an SSL 3.0 / TLS suite
			id := binary.BigEndian.Uint16(specs[i+1:])
			ch.suites = append(ch.suites, id)
			if id == 0x00ff {
				ch.secureReneg = true
			}
		} else { // SSL 2.0's own
			ch.ssl2Kinds = append(ch.ssl2Kinds, uint32(specs[i])<<16|uint32(specs[i+1])<<8|uint32(specs[i+2]))
		}
	}
	ch.challenge = slices.Clone(m[9+specLen+sidLen:])
	ch.random = make([]byte, 32)
	copy(ch.random[32-chalLen:], ch.challenge)
	return ch, nil
}

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || len(r.b) < n {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() int {
	if v := r.take(1); v != nil {
		return int(v[0])
	}
	return 0
}

func (r *reader) u16() int {
	if v := r.take(2); v != nil {
		return int(binary.BigEndian.Uint16(v))
	}
	return 0
}

func parseClientHello(body []byte) (*clientHello, error) {
	r := &reader{b: body}
	ch := &clientHello{version: uint16(r.u16())}
	ch.random = slices.Clone(r.take(32))
	r.take(r.u8()) // session id
	ss := r.take(r.u16())
	if len(ss)%2 != 0 {
		r.bad = true
	}
	for i := 0; i+1 < len(ss); i += 2 {
		id := binary.BigEndian.Uint16(ss[i:])
		ch.suites = append(ch.suites, id)
		if id == 0x00ff {
			ch.secureReneg = true
		}
	}
	if comp := r.take(r.u8()); !r.bad && !slices.Contains(comp, 0) {
		return nil, fail(alertHandshakeFailure, "the client offers no null compression")
	}
	if len(r.b) > 0 && !r.bad {
		ext := &reader{b: r.take(r.u16())}
		for len(ext.b) > 0 && !ext.bad {
			typ, data := ext.u16(), ext.take(ext.u16())
			switch typ {
			case 0xff01:
				ch.secureReneg = true
			case 0x0000: // server name
				sn := &reader{b: data}
				list := &reader{b: sn.take(sn.u16())}
				if list.u8() == 0 {
					ch.sni = string(list.take(list.u16()))
				}
			}
		}
		r.bad = r.bad || ext.bad
	}
	if r.bad {
		return nil, fail(alertDecode, "bad ClientHello")
	}
	return ch, nil
}
