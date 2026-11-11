package retrossl

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"sync"
)

type clientHello struct {
	version   uint16
	random    []byte
	sessionID []byte
	suites    []uint16
	comp      []byte
	sni       string
	scsv      bool   // TLS_EMPTY_RENEGOTIATION_INFO_SCSV offered
	hasReneg  bool   // the renegotiation_info extension sent
	renegInfo []byte // and what it holds

	v2        bool     // the hello was SSL 2.0's
	ssl2Kinds []uint32 // its SSL 2.0 cipher kinds
	challenge []byte   // its challenge
}

func (ch *clientHello) secureReneg() bool { return ch.scsv || ch.hasReneg }

func (c *Conn) addTranscript(m []byte) { c.transcript = append(c.transcript, m...) }

// serverHandshake is the first handshake.
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
		// RFC 5746: a first hello's renegotiation_info must be empty.
		if ch.hasReneg && len(ch.renegInfo) != 0 {
			return fail(alertHandshakeFailure, "renegotiation_info not empty in the first hello")
		}
		c.secureReneg = ch.secureReneg()
	} else {
		v = VersionSSL20
		c.ssl2 = true
	}
	cert, key, err := c.certificate(ch, v)
	if err != nil {
		return err
	}
	if tlsOK {
		err := c.negotiate3(ch, v, cert, key)
		if err != errNoSuite || !ssl2OK {
			return err
		}
		c.ssl2 = true // an SSL 2.0 hello with no SSL 3.0 or TLS suite in common
	}
	return c.handshake2(ch, cert, key)
}

var errNoSuite = errors.New("retrossl: no cipher suite in common")

// certificate is the server's certificate for a hello.
func (c *Conn) certificate(ch *clientHello, v uint16) (*tls.Certificate, *rsa.PrivateKey, error) {
	cert, err := c.cfg.GetCertificate(&tls.ClientHelloInfo{ServerName: ch.sni, CipherSuites: ch.suites,
		SupportedVersions: []uint16{v}, Conn: c.Conn})
	if err != nil {
		return nil, nil, fail(alertInternal, "certificate: %v", err)
	}
	key, ok := rsaKey(cert)
	if !ok {
		return nil, nil, fail(alertHandshakeFailure, "the certificate's key is not RSA, which these clients need")
	}
	return cert, key, nil
}

// negotiate3 runs an SSL 3.0 or TLS 1.0 handshake after its hello:
// resumed when it can be, else in full.  errNoSuite: no suite in common
// (and nothing sent).
func (c *Conn) negotiate3(ch *clientHello, v uint16, cert *tls.Certificate, key *rsa.PrivateKey) error {
	if sess := c.resumable(ch, v, cert); sess != nil {
		return c.resume3(ch, sess)
	}
	s := c.pickSuite(ch, key.Size()*8)
	if s == nil {
		if ch.v2 && !c.renegotiating {
			return errNoSuite
		}
		return fail(alertHandshakeFailure, "no cipher suite in common: the client offers %04x", ch.suites)
	}
	return c.handshake3(ch, v, s, cert, key)
}

// resumable is the cached session a hello asks for, if it can be resumed.
func (c *Conn) resumable(ch *clientHello, v uint16, cert *tls.Certificate) *session {
	sess := c.cfg.SessionCache.get(ch.sessionID)
	if sess == nil || sess.version != v || sess.cert != certHash(cert.Certificate[0]) ||
		!slices.Contains(ch.suites, uint16(sess.suite)) || !slices.Contains(ch.comp, sess.comp) ||
		!c.suiteAllowed(uint16(sess.suite)) || (c.wantCert() && !sess.verified && c.cfg.ClientAuth >= tls.VerifyClientCertIfGiven) {
		return nil
	}
	return sess
}

func (c *Conn) suiteAllowed(id uint16) bool {
	return c.cfg.CipherSuites == nil || slices.Contains(c.cfg.CipherSuites, id)
}

func (c *Conn) wantCert() bool { return c.cfg.ClientAuth != tls.NoClientCert }

// pickSuite is the best suite the client offers, or nil.
func (c *Conn) pickSuite(ch *clientHello, keyBits int) *suite {
	for i := range suites {
		s := &suites[i]
		if !slices.Contains(ch.suites, s.id) || !c.suiteAllowed(s.id) {
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

// pickComp is the compression method to use.
func (c *Conn) pickComp(ch *clientHello) uint8 {
	if c.cfg.Compression && slices.Contains(ch.comp, compDeflate) {
		return compDeflate
	}
	return compNull
}

// serverHello is the ServerHello message.
func (c *Conn) serverHello(ch *clientHello, v uint16, sr, sid []byte, suite uint16, comp uint8) []byte {
	hello := binary.BigEndian.AppendUint16(nil, v)
	hello = append(hello, sr...)
	hello = append(hello, byte(len(sid)))
	hello = append(hello, sid...)
	hello = binary.BigEndian.AppendUint16(hello, suite)
	hello = append(hello, comp)
	if c.secureReneg {
		info := cat(c.clientVerify, c.serverVerify)
		ext := binary.BigEndian.AppendUint16([]byte{0xff, 0x01}, uint16(len(info)+1))
		ext = append(append(ext, byte(len(info))), info...)
		hello = appendVec16(hello, ext)
	}
	return msg(hsServerHello, hello)
}

// resume3 runs an abbreviated handshake: ServerHello, then the server's
// ChangeCipherSpec and Finished, then the client's.
func (c *Conn) resume3(ch *clientHello, sess *session) error {
	v, s := sess.version, suiteByID(uint16(sess.suite))
	sr := random(32)
	sh := c.serverHello(ch, v, sr, sess.id, s.id, sess.comp)
	c.addTranscript(sh)
	if err := c.writeRecord(recHandshake, sh); err != nil {
		return err
	}
	ck, sk := s.keys(v, sess.master, ch.random, sr)
	if err := c.writeRecord(recCCS, []byte{1}); err != nil {
		return err
	}
	c.outMu.Lock()
	c.out = s.newHalf(v, sk, true, sess.comp)
	c.outMu.Unlock()
	sf := finished(v, sess.master, c.transcript, false)
	sfm := msg(hsFinished, sf)
	c.addTranscript(sfm)
	if err := c.writeRecord(recHandshake, sfm); err != nil {
		return err
	}
	cf, err := c.readFinished(v, s, ck, sess.comp, sess.master)
	if err != nil {
		return err
	}
	c.done(State{Version: v, CipherSuite: uint32(s.id), CipherName: s.name, ServerName: ch.sni,
		V2Hello: ch.v2, DidResume: true, Compression: sess.comp, PeerCertificates: sess.peer}, cf, sf)
	return nil
}

// readFinished reads the client's ChangeCipherSpec and Finished, taking
// its keys at the first, and gives the Finished's verify data.
func (c *Conn) readFinished(v uint16, s *suite, ck dirKeys, comp uint8, ms []byte) ([]byte, error) {
	want := finished(v, ms, c.transcript, true)
	if len(c.hs) != 0 {
		return nil, fail(alertUnexpected, "handshake data before ChangeCipherSpec")
	}
	typ, data, err := c.readRecord()
	for err == nil && typ == recData && c.renegotiating { // data still coming under the old keys
		c.data = append(c.data, data...)
		typ, data, err = c.readRecord()
	}
	if err != nil {
		return nil, err
	}
	if typ == recAlert {
		return nil, alertIn(data)
	}
	if typ != recCCS || len(data) != 1 || data[0] != 1 {
		return nil, fail(alertUnexpected, "record type %d, not ChangeCipherSpec", typ)
	}
	c.in = s.newHalf(v, ck, false, comp)
	m, err := c.readHandshake()
	if err != nil {
		return nil, err
	}
	if m[0] != hsFinished || len(m) != 4+len(want) {
		return nil, fail(alertUnexpected, "handshake message %d, not Finished", m[0])
	}
	if subtle.ConstantTimeCompare(m[4:], want) != 1 {
		return nil, fail(alertDecrypt, "the client's Finished is wrong")
	}
	c.addTranscript(m)
	return want, nil
}

// done records a finished handshake.
func (c *Conn) done(st State, clientVerify, serverVerify []byte) {
	c.transcript = nil
	c.clientVerify, c.serverVerify = clientVerify, serverVerify
	c.state = st
}

func (c *Conn) handshake3(ch *clientHello, v uint16, s *suite, cert *tls.Certificate, key *rsa.PrivateKey) error {
	sr := random(32)
	var sid []byte
	if c.cfg.SessionCache != nil {
		sid = random(32)
	}
	comp := c.pickComp(ch)
	var chain []byte
	for _, der := range cert.Certificate {
		chain = appendU24(chain, len(der))
		chain = append(chain, der...)
	}
	flight := c.serverHello(ch, v, sr, sid, s.id, comp)
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
	if c.wantCert() {
		flight = append(flight, msg(hsCertificateRequest, c.certificateRequest())...)
	}
	flight = append(flight, msg(hsServerDone, nil)...)
	c.addTranscript(flight)
	if err := c.writeRecord(recHandshake, flight); err != nil {
		return err
	}

	var peer []*x509.Certificate
	verified := false
	if c.wantCert() {
		var err error
		if peer, verified, err = c.readClientCertificate(); err != nil {
			return err
		}
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

	if len(peer) > 0 {
		if err := c.readCertificateVerify(v, ms, peer[0]); err != nil {
			return err
		}
	}
	ck, sk := s.keys(v, ms, ch.random, sr)
	cf, err := c.readFinished(v, s, ck, comp, ms)
	if err != nil {
		return err
	}

	if err := c.writeRecord(recCCS, []byte{1}); err != nil {
		return err
	}
	c.outMu.Lock()
	c.out = s.newHalf(v, sk, true, comp)
	c.outMu.Unlock()
	sf := finished(v, ms, c.transcript, false)
	if err := c.writeRecord(recHandshake, msg(hsFinished, sf)); err != nil {
		return err
	}
	if sid != nil {
		c.cfg.SessionCache.put(&session{id: sid, version: v, suite: uint32(s.id), comp: comp, master: ms,
			cert: certHash(cert.Certificate[0]), peer: peer, sni: ch.sni, verified: verified})
	}
	c.done(State{Version: v, CipherSuite: uint32(s.id), CipherName: s.name, ServerName: ch.sni, V2Hello: ch.v2,
		Compression: comp, PeerCertificates: peer}, cf, sf)
	return nil
}

// certificateRequest is a CertificateRequest's body: RSA certificates,
// from the ClientCAs.
func (c *Conn) certificateRequest() []byte {
	b := []byte{1, 1} // rsa_sign
	var cas []byte
	if c.cfg.ClientCAs != nil {
		//lint:ignore SA1019 the pool is the caller's own, not the system's
		for _, s := range c.cfg.ClientCAs.Subjects() { //nolint:staticcheck
			cas = appendVec16(cas, s)
		}
	}
	return appendVec16(b, cas)
}

// readClientCertificate reads the client's Certificate (or SSL 3.0's
// no_certificate alert) and checks it as ClientAuth asks.
func (c *Conn) readClientCertificate() ([]*x509.Certificate, bool, error) {
	c.wantNoCert = true
	m, err := c.readHandshake()
	c.wantNoCert = false
	var raw [][]byte
	switch {
	case err == errNoCertificate:
	case err != nil:
		return nil, false, err
	case m[0] != hsCertificate:
		return nil, false, fail(alertUnexpected, "handshake message %d, not the client's Certificate", m[0])
	default:
		c.addTranscript(m)
		r := &reader{b: m[4:]}
		list := &reader{b: r.take(r.u24())}
		for len(list.b) > 0 && !list.bad {
			raw = append(raw, list.take(list.u24()))
		}
		if r.bad || list.bad || len(r.b) != 0 {
			return nil, false, fail(alertDecode, "bad client Certificate")
		}
	}
	return c.checkPeer(raw)
}

// checkPeer parses and verifies the client's certificates, as ClientAuth
// asks; verified: they were verified.
func (c *Conn) checkPeer(raw [][]byte) ([]*x509.Certificate, bool, error) {
	cfg := c.cfg
	if len(raw) == 0 {
		if cfg.ClientAuth == tls.RequireAnyClientCert || cfg.ClientAuth == tls.RequireAndVerifyClientCert {
			return nil, false, fail(alertHandshakeFailure, "the client sent no certificate")
		}
		return nil, false, nil
	}
	var certs []*x509.Certificate
	for _, der := range raw {
		pc, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, false, fail(alertBadCertificate, "the client's certificate: %v", err)
		}
		certs = append(certs, pc)
	}
	if _, ok := certs[0].PublicKey.(*rsa.PublicKey); !ok {
		return nil, false, fail(alertUnsupportedCertificate, "the client's certificate is not RSA")
	}
	var chains [][]*x509.Certificate
	verified := false
	if cfg.ClientAuth >= tls.VerifyClientCertIfGiven {
		inter := x509.NewCertPool()
		for _, ic := range certs[1:] {
			inter.AddCert(ic)
		}
		var err error
		chains, err = certs[0].Verify(x509.VerifyOptions{Roots: cfg.ClientCAs, Intermediates: inter,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		if err != nil {
			return nil, false, fail(alertBadCertificate, "the client's certificate: %v", err)
		}
		verified = true
	}
	if cfg.VerifyPeerCertificate != nil {
		if err := cfg.VerifyPeerCertificate(raw, chains); err != nil {
			return nil, false, fail(alertBadCertificate, "the client's certificate: %v", err)
		}
	}
	return certs, verified, nil
}

// readCertificateVerify checks the client's proof that it has its
// certificate's key: a signature over the handshake so far.
func (c *Conn) readCertificateVerify(v uint16, ms []byte, peer *x509.Certificate) error {
	digest := c.certVerifyDigest(v, ms)
	m, err := c.readHandshake()
	if err != nil {
		return err
	}
	if m[0] != hsCertificateVerify {
		return fail(alertUnexpected, "handshake message %d, not CertificateVerify", m[0])
	}
	r := &reader{b: m[4:]}
	sig := r.take(r.u16())
	if r.bad || len(r.b) != 0 {
		return fail(alertDecode, "bad CertificateVerify")
	}
	if err := rsa.VerifyPKCS1v15(peer.PublicKey.(*rsa.PublicKey), crypto.MD5SHA1, digest, sig); err != nil {
		return fail(alertDecrypt, "the client's CertificateVerify is wrong")
	}
	c.addTranscript(m)
	return nil
}

// certVerifyDigest is what CertificateVerify signs.
func (c *Conn) certVerifyDigest(v uint16, ms []byte) []byte {
	if v == VersionSSL30 {
		return ssl3Hash(ms, c.transcript, "")
	}
	m, s := md5.Sum(c.transcript), sha1.Sum(c.transcript)
	return cat(m[:], s[:])
}

// renegotiate runs a handshake the client starts (or answers a
// HelloRequest with) on an established connection.
func (c *Conn) renegotiate() error {
	c.renegotiating = true
	defer func() { c.renegotiating = false }()
	m, err := c.readHandshake()
	if err != nil {
		return err
	}
	if m[0] != hsClientHello {
		return fail(alertUnexpected, "handshake message %d, not ClientHello", m[0])
	}
	ch, err := parseClientHello(m[4:])
	if err != nil {
		return err
	}
	if c.secureReneg {
		if !ch.hasReneg || ch.scsv || !bytes.Equal(ch.renegInfo, c.clientVerify) {
			return fail(alertHandshakeFailure, "the renegotiation's renegotiation_info is wrong")
		}
	} else if ch.secureReneg() {
		return fail(alertHandshakeFailure, "renegotiation_info in a renegotiation it wasn't in first")
	}
	v := c.state.Version
	if ch.version < v {
		return fail(alertProtocolVersion, "the renegotiation offers %s, not %s", VersionName(ch.version), VersionName(v))
	}
	c.transcript = nil
	c.addTranscript(m)
	cert, key, err := c.certificate(ch, v)
	if err != nil {
		return err
	}
	return c.negotiate3(ch, v, cert, key)
}

// RequestRenegotiation asks the client to renegotiate (a HelloRequest),
// as for asking for its certificate after the connection is made; the
// handshake runs in a later Read.  Not for SSL 2.0.
func (c *Conn) RequestRenegotiation() error {
	if err := c.Handshake(); err != nil {
		return err
	}
	if c.ssl2 {
		return errors.New("retrossl: SSL 2.0 cannot renegotiate")
	}
	if c.cfg.Renegotiation == RenegotiateNever || (!c.secureReneg && c.cfg.Renegotiation != RenegotiateInsecure) {
		return errors.New("retrossl: renegotiation is off for this connection")
	}
	return c.writeRecord(recHandshake, msg(hsHelloRequest, nil))
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
	ch := &clientHello{version: uint16(u(1)), v2: true, comp: []byte{compNull}}
	if ch.version <= VersionSSL30 {
		c.out.version = VersionSSL30
	}
	specs := m[9 : 9+specLen]
	for i := 0; i < len(specs); i += 3 {
		if specs[i] == 0 { // an SSL 3.0 / TLS suite
			id := binary.BigEndian.Uint16(specs[i+1:])
			ch.suites = append(ch.suites, id)
			if id == 0x00ff {
				ch.scsv = true
			}
		} else { // SSL 2.0's own
			ch.ssl2Kinds = append(ch.ssl2Kinds, uint32(specs[i])<<16|uint32(specs[i+1])<<8|uint32(specs[i+2]))
		}
	}
	ch.challenge = slices.Clone(m[9+specLen+sidLen:])
	ch.sessionID = slices.Clone(m[9+specLen : 9+specLen+sidLen]) // SSL 2.0's, to resume
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

func (r *reader) u24() int {
	if v := r.take(3); v != nil {
		return int(v[0])<<16 | int(v[1])<<8 | int(v[2])
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
	ch.sessionID = slices.Clone(r.take(r.u8()))
	ss := r.take(r.u16())
	if len(ss)%2 != 0 {
		r.bad = true
	}
	for i := 0; i+1 < len(ss); i += 2 {
		id := binary.BigEndian.Uint16(ss[i:])
		ch.suites = append(ch.suites, id)
		if id == 0x00ff {
			ch.scsv = true
		}
	}
	ch.comp = slices.Clone(r.take(r.u8()))
	if comp := ch.comp; !r.bad && !slices.Contains(comp, 0) {
		return nil, fail(alertHandshakeFailure, "the client offers no null compression")
	}
	if len(r.b) > 0 && !r.bad {
		ext := &reader{b: r.take(r.u16())}
		for len(ext.b) > 0 && !ext.bad {
			typ, data := ext.u16(), ext.take(ext.u16())
			switch typ {
			case 0xff01:
				ri := &reader{b: data}
				ch.hasReneg, ch.renegInfo = true, slices.Clone(ri.take(ri.u8()))
				if ri.bad || len(ri.b) != 0 {
					ext.bad = true
				}
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
