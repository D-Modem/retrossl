package retrossl

import (
	"bufio"
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"slices"
	"sync"
	"testing"
	"time"
)

var (
	certOnce sync.Once
	testCert tls.Certificate
)

func cert(t *testing.T) *tls.Certificate {
	t.Helper()
	certOnce.Do(func() {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "127.0.0.1"},
			IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour),
			NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		testCert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	})
	return &testCert
}

// echo serves one connection by Frontend, echoing what it reads; the
// server's error and state come on the channel.
func echo(t *testing.T, cfg Config) (string, chan error, chan State) {
	return echoBy(t, cfg, true)
}

// echoBy is echo, by Frontend or (frontend false) by Server.
func echoBy(t *testing.T, cfg Config, frontend bool) (string, chan error, chan State) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	c := cert(t)
	cfg.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return c, nil }
	errs, states := make(chan error, 1), make(chan State, 1)
	go func() {
		nc, err := ln.Accept()
		if err != nil {
			errs <- err
			return
		}
		nc.SetDeadline(time.Now().Add(10 * time.Second))
		var fc net.Conn = Server(nc, &cfg)
		if frontend {
			fc, err = Frontend(nc, &tls.Config{Certificates: []tls.Certificate{*c}}, &cfg)
		}
		if err != nil {
			errs <- err
			return
		}
		defer fc.Close()
		if sc, ok := fc.(*Conn); ok {
			if err := sc.Handshake(); err != nil {
				errs <- err
				return
			}
			states <- sc.ConnectionState()
		}
		_, err = io.Copy(fc, fc)
		errs <- err
	}()
	return ln.Addr().String(), errs, states
}

// TestGoClient: Go's own TLS client, at TLS 1.0, with each suite it has.
// Its record hello offers TLS 1.0, so this goes through the package
// directly, not Frontend.
func TestGoClient(t *testing.T) {
	for _, id := range []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, tls.TLS_RSA_WITH_RC4_128_SHA} {
		t.Run(tls.CipherSuiteName(id), func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()
			c := cert(t)
			errs := make(chan error, 1)
			go func() {
				nc, err := ln.Accept()
				if err != nil {
					errs <- err
					return
				}
				sc := Server(nc, &Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return c, nil }})
				defer sc.Close()
				sc.SetDeadline(time.Now().Add(10 * time.Second))
				_, err = io.Copy(sc, sc)
				errs <- err
			}()
			gc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10,
				MaxVersion: tls.VersionTLS10, CipherSuites: []uint16{id}, ServerName: "example.com"})
			if err != nil {
				t.Fatal(err)
			}
			if st := gc.ConnectionState(); st.CipherSuite != id || st.Version != tls.VersionTLS10 {
				t.Fatalf("state %+v", st)
			}
			msg := bytes.Repeat([]byte("ping "), 9000) // more than a record
			go gc.Write(msg)
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(gc, got); err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("echo: %v", err)
			}
			gc.Close()
			if err := <-errs; err != nil {
				t.Errorf("server: %v", err)
			}
		})
	}
}

// TestFrontendModern: a modern client goes to crypto/tls.
func TestFrontendModern(t *testing.T) {
	addr, errs, _ := echo(t, Config{})
	gc, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if v := gc.ConnectionState().Version; v != tls.VersionTLS13 {
		t.Errorf("version %x", v)
	}
	gc.Write([]byte("hi"))
	b := make([]byte, 2)
	if _, err := io.ReadFull(gc, b); err != nil || string(b) != "hi" {
		t.Fatalf("echo %q %v", b, err)
	}
	gc.Close()
	<-errs
}

// oldClient is an SSL 3.0 / TLS 1.0 client, built on the package's own
// record layer.  Its fields before the blank line are options.
type oldClient struct {
	t           *testing.T
	v, id       uint16
	v2          bool             // open with an SSL 2.0-format hello
	badFinished bool             // send a wrong Finished
	secure      bool             // offer secure renegotiation
	comp        bool             // offer DEFLATE
	sessionID   []byte           // ask to resume this session
	cert        *tls.Certificate // send this when asked (nil: none)

	c                          Conn
	transcript                 []byte
	tempKey                    bool // the server sent a ServerKeyExchange
	certRequested, resumed     bool
	gotSID, ms                 []byte
	clientVerify, serverVerify []byte
	compMethod                 uint8
}

func v2Hello(version uint16, suites []uint16, kinds []uint32, challenge []byte) []byte {
	return v2HelloSID(version, suites, kinds, nil, challenge)
}

func v2HelloSID(version uint16, suites []uint16, kinds []uint32, sid, challenge []byte) []byte {
	var specs []byte
	for _, k := range kinds {
		specs = append(specs, byte(k>>16), byte(k>>8), byte(k))
	}
	for _, s := range suites {
		specs = append(specs, 0, byte(s>>8), byte(s))
	}
	m := binary.BigEndian.AppendUint16([]byte{1}, version)
	m = binary.BigEndian.AppendUint16(m, uint16(len(specs)))
	m = binary.BigEndian.AppendUint16(m, uint16(len(sid)))
	m = binary.BigEndian.AppendUint16(m, uint16(len(challenge)))
	m = append(append(append(m, specs...), sid...), challenge...)
	return append([]byte{0x80 | byte(len(m)>>8), byte(len(m))}, m...)
}

// handshake runs the client's first handshake on nc.
func (o *oldClient) handshake(nc net.Conn) error {
	o.c.Conn, o.c.br = nc, bufio.NewReader(nc)
	o.c.out.version = o.v
	return o.run(true)
}

// renegotiate runs another handshake on the connection.
func (o *oldClient) renegotiate() error { return o.run(false) }

func (o *oldClient) run(first bool) error {
	t, c, v := o.t, &o.c, o.v
	o.transcript, o.resumed, o.certRequested, o.tempKey = nil, false, false, false
	cr := random(32)
	if o.v2 && first {
		offer := []uint16{o.id}
		if o.secure {
			offer = append(offer, 0x00ff)
		}
		chal := random(16)
		copy(cr, make([]byte, 16))
		copy(cr[16:], chal)
		hello := v2Hello(v, offer, []uint32{0x010080}, chal)
		o.transcript = append(o.transcript, hello[2:]...)
		if _, err := c.Conn.Write(hello); err != nil {
			return err
		}
	} else {
		offer := []uint16{o.id}
		if o.secure && first {
			offer = append(offer, 0x00ff)
		}
		body := binary.BigEndian.AppendUint16(nil, v)
		body = append(body, cr...)
		body = append(append(body, byte(len(o.sessionID))), o.sessionID...)
		body = binary.BigEndian.AppendUint16(body, uint16(2*len(offer)))
		for _, s := range offer {
			body = binary.BigEndian.AppendUint16(body, s)
		}
		if o.comp {
			body = append(body, 2, 1, 0)
		} else {
			body = append(body, 1, 0)
		}
		if o.secure && !first {
			ri := append([]byte{byte(len(o.clientVerify))}, o.clientVerify...)
			ext := appendVec16([]byte{0xff, 0x01}, ri)
			body = appendVec16(body, ext)
		}
		hello := msg(hsClientHello, body)
		o.transcript = append(o.transcript, hello...)
		if err := c.writeRecord(recHandshake, hello); err != nil {
			return err
		}
	}
	sh, err := c.readHandshake()
	if err != nil {
		return err
	}
	if sh[0] != hsServerHello || binary.BigEndian.Uint16(sh[4:]) != v {
		t.Fatalf("server hello %x", sh)
	}
	r := &reader{b: sh[6:]}
	sr := slices.Clone(r.take(32))
	sid := slices.Clone(r.take(r.u8()))
	if got := uint16(r.u16()); got != o.id {
		t.Fatalf("suite %04x", got)
	}
	o.compMethod = uint8(r.u8())
	var renegInfo []byte
	hasReneg := false
	if len(r.b) > 0 {
		ext := &reader{b: r.take(r.u16())}
		for len(ext.b) > 0 && !ext.bad {
			typ, data := ext.u16(), ext.take(ext.u16())
			if typ == 0xff01 {
				hasReneg, renegInfo = true, data[1:]
			}
		}
	}
	if hasReneg != o.secure {
		t.Errorf("renegotiation_info %v", hasReneg)
	} else if hasReneg && !bytes.Equal(renegInfo, cat(o.clientVerify, o.serverVerify)) {
		t.Errorf("renegotiation_info %x", renegInfo)
	}
	o.transcript = append(o.transcript, sh...)
	s := suiteByID(o.id)

	if len(o.sessionID) > 0 && bytes.Equal(sid, o.sessionID) { // resumed
		o.resumed = true
		ck, sk := s.keys(v, o.ms, cr, sr)
		if err := o.readServerFinished(s, sk); err != nil {
			return err
		}
		return o.sendFinished(s, ck, nil)
	}
	o.gotSID = sid

	ce, err := c.readHandshake()
	if err != nil {
		return err
	}
	o.transcript = append(o.transcript, ce...)
	pc, err := x509.ParseCertificate(ce[10:])
	if err != nil {
		t.Fatal(err)
	}
	pub := pc.PublicKey.(*rsa.PublicKey)
	m, err := c.readHandshake()
	if err != nil {
		return err
	}
	o.transcript = append(o.transcript, m...)
	if m[0] == hsServerKeyExchange {
		r := &reader{b: m[4:]}
		n, e := r.take(r.u16()), r.take(r.u16())
		params := m[4 : 4+4+len(n)+len(e)]
		sig := r.take(r.u16())
		if r.bad || len(r.b) != 0 {
			t.Fatalf("server key exchange %x", m)
		}
		h5, h1 := md5.Sum(cat(cr, sr, params)), sha1.Sum(cat(cr, sr, params))
		if err := rsa.VerifyPKCS1v15(pub, crypto.MD5SHA1, cat(h5[:], h1[:]), sig); err != nil {
			t.Fatalf("export key's signature: %v", err)
		}
		pub = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		o.tempKey = true
		if m, err = c.readHandshake(); err != nil {
			return err
		}
		o.transcript = append(o.transcript, m...)
	}
	if m[0] == hsCertificateRequest {
		o.certRequested = true
		if m, err = c.readHandshake(); err != nil {
			return err
		}
		o.transcript = append(o.transcript, m...)
	}
	if m[0] != hsServerDone {
		t.Fatalf("server hello done %x", m)
	}

	var flight []byte
	if o.certRequested {
		switch {
		case o.cert != nil:
			var chain []byte
			for _, der := range o.cert.Certificate {
				chain = append(appendU24(chain, len(der)), der...)
			}
			flight = msg(hsCertificate, appendU24(nil, len(chain)), chain...)
		case v == VersionSSL30:
			if err := c.writeRecord(recAlert, []byte{levelWarning, alertNoCertificate}); err != nil {
				return err
			}
		default:
			flight = msg(hsCertificate, appendU24(nil, 0))
		}
	}
	pre := random(48)
	binary.BigEndian.PutUint16(pre, v)
	ct, err := rsa.EncryptPKCS1v15(rand.Reader, pub, pre)
	if err != nil {
		t.Fatal(err)
	}
	if v == VersionTLS10 {
		ct = appendVec16(nil, ct)
	}
	flight = append(flight, msg(hsClientKeyExchange, ct)...)
	o.transcript = append(o.transcript, flight...)
	o.ms = masterSecret(v, pre, cr, sr)
	if o.certRequested && o.cert != nil {
		var digest []byte
		if v == VersionSSL30 {
			digest = ssl3Hash(o.ms, o.transcript, "")
		} else {
			h5, h1 := md5.Sum(o.transcript), sha1.Sum(o.transcript)
			digest = cat(h5[:], h1[:])
		}
		sig, err := rsa.SignPKCS1v15(rand.Reader, o.cert.PrivateKey.(*rsa.PrivateKey), crypto.MD5SHA1, digest)
		if err != nil {
			t.Fatal(err)
		}
		cv := msg(hsCertificateVerify, appendVec16(nil, sig))
		o.transcript = append(o.transcript, cv...)
		flight = append(flight, cv...)
	}
	ck, sk := s.keys(v, o.ms, cr, sr)
	if err := c.writeRecord(recHandshake, flight); err != nil {
		return err
	}
	if err := o.sendFinished(s, ck, nil); err != nil {
		return err
	}
	return o.readServerFinished(s, sk)
}

func (o *oldClient) sendFinished(s *suite, ck dirKeys, _ []byte) error {
	c := &o.c
	fin := finished(o.v, o.ms, o.transcript, true)
	o.clientVerify = slices.Clone(fin)
	if o.badFinished {
		fin[0] ^= 1
	}
	finMsg := msg(hsFinished, fin)
	o.transcript = append(o.transcript, finMsg...)
	if err := c.writeRecord(recCCS, []byte{1}); err != nil {
		return err
	}
	c.out = s.newHalf(o.v, ck, true, o.compMethod)
	return c.writeRecord(recHandshake, finMsg)
}

func (o *oldClient) readServerFinished(s *suite, sk dirKeys) error {
	c := &o.c
	typ, data, err := c.readRecord()
	if err != nil {
		return err
	}
	if typ == recAlert {
		return alertIn(data)
	}
	if typ != recCCS {
		o.t.Fatalf("record %d, not CCS", typ)
	}
	c.in = s.newHalf(o.v, sk, false, o.compMethod)
	sf, err := c.readHandshake()
	if err != nil {
		return err
	}
	want := finished(o.v, o.ms, o.transcript, false)
	if !bytes.Equal(sf[4:], want) {
		o.t.Fatalf("server Finished wrong")
	}
	o.serverVerify = want
	o.transcript = append(o.transcript, sf...)
	return nil
}

// echoCheck sends data and checks it comes back.
func (o *oldClient) echoCheck(t *testing.T, n int) {
	t.Helper()
	c := &o.c
	want := bytes.Repeat([]byte("hello "), n)
	if err := c.writeRecord(recData, want); err != nil {
		t.Fatal(err)
	}
	var got []byte
	for len(got) < len(want) {
		typ, data, err := c.readRecord()
		if err != nil || typ != recData {
			t.Fatalf("record %d %x: %v", typ, data, err)
		}
		got = append(got, data...)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("echo differs")
	}
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	nc, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	nc.SetDeadline(time.Now().Add(10 * time.Second))
	return nc
}

// TestOldClients: SSL 3.0 and TLS 1.0, in either hello, with each suite,
// export ones included, and data echoed.
func TestOldClients(t *testing.T) {
	for _, v := range []uint16{VersionSSL30, VersionTLS10} {
		for _, v2 := range []bool{false, true} {
			for _, s := range suites {
				t.Run(fmt.Sprintf("%s/v2=%v/%s", VersionName(v), v2, s.name), func(t *testing.T) {
					// A TLS 1.0 record hello is crypto/tls's, through Frontend.
					addr, errs, states := echoBy(t, Config{}, v == VersionSSL30 || v2)
					o := &oldClient{t: t, v: v, id: s.id, v2: v2, secure: v == VersionTLS10}
					if err := o.handshake(dial(t, addr)); err != nil {
						t.Fatal(err)
					}
					if o.tempKey != (s.export != 0) {
						t.Errorf("temporary key sent: %v", o.tempKey)
					}
					st := <-states
					if st.Version != v || st.CipherSuite != uint32(s.id) || st.V2Hello != v2 {
						t.Errorf("state %+v", st)
					}
					o.echoCheck(t, 5000)
					o.c.sendAlert(levelWarning, alertCloseNotify)
					if err := <-errs; err != nil {
						t.Errorf("server: %v", err)
					}
				})
			}
		}
	}
}

// TestBadFinished: a wrong Finished is refused, with an alert.
func TestBadFinished(t *testing.T) {
	for _, v := range []uint16{VersionSSL30, VersionTLS10} {
		addr, errs, _ := echoBy(t, Config{}, false)
		o := &oldClient{t: t, v: v, id: 0x002f, badFinished: true}
		if err := o.handshake(dial(t, addr)); err == nil {
			t.Fatal("handshake passed")
		}
		if err := <-errs; err == nil {
			t.Error("server took it")
		}
	}
}

// TestSSL3Off: a client offering only SSL 3.0 is refused when the server
// starts at TLS 1.0.
func TestSSL3Off(t *testing.T) {
	addr, errs, _ := echo(t, Config{MinVersion: VersionTLS10})
	nc := dial(t, addr)
	nc.Write(v2Hello(VersionSSL30, []uint16{0x002f}, nil, make([]byte, 16)))
	b, _ := io.ReadAll(nc)
	if len(b) < 7 || b[0] != recAlert || b[1] != 3 || b[2] != 0 || b[6] != alertHandshakeFailure {
		t.Errorf("answer %x", b)
	}
	if err := <-errs; err == nil {
		t.Error("server took it")
	}
}

// ssl2Opts are an SSL 2.0 test client's options.
type ssl2Opts struct {
	version uint16
	kind    uint32
	suites  []uint16         // SSL 3.0 / TLS suites offered too
	resume  *ssl2Result      // a session to resume
	cert    *tls.Certificate // sent when asked
}

// ssl2Result is a finished SSL 2.0 client handshake.
type ssl2Result struct {
	c                  *Conn
	sid, master, arg   []byte
	hit, certRequested bool
}

func ssl2Client(t *testing.T, nc net.Conn, version uint16, kind uint32, suites []uint16) (*Conn, error) {
	r, err := ssl2Run(t, nc, ssl2Opts{version: version, kind: kind, suites: suites})
	if err != nil {
		return nil, err
	}
	return r.c, nil
}

// ssl2Run runs SSL 2.0's client side.
func ssl2Run(t *testing.T, nc net.Conn, o ssl2Opts) (*ssl2Result, error) {
	c := &Conn{Conn: nc, br: bufio.NewReader(nc), ssl2: true}
	res := &ssl2Result{c: c}
	chal := random(16)
	var sid []byte
	if o.resume != nil {
		sid = o.resume.sid
	}
	if _, err := nc.Write(v2HelloSID(o.version, o.suites, SSL2CipherKinds(), sid, chal)); err != nil {
		return nil, err
	}
	c.out2.seq = 1
	sh, err := c.readRecord2()
	if err != nil {
		return nil, err
	}
	if len(sh) > 0 && sh[0] == ssl2Error {
		return nil, fmt.Errorf("SSL 2.0 error %x", sh)
	}
	u := func(i int) int { return int(binary.BigEndian.Uint16(sh[i:])) }
	if sh[0] != ssl2ServerHello || u(3) != VersionSSL20 {
		t.Fatalf("server hello %x", sh[:11])
	}
	certLen, specLen, idLen := u(5), u(7), u(9)
	serverCert := sh[11 : 11+certLen]
	connID := sh[11+certLen+specLen:]
	if len(connID) != idLen {
		t.Fatalf("connection id %x", connID)
	}
	var sc ssl2Cipher
	for _, x := range ssl2Ciphers {
		if x.kind == o.kind {
			sc = x
		}
	}
	if sh[1] == 1 { // a session hit
		if o.resume == nil || certLen != 0 || specLen != 0 {
			t.Fatalf("session hit %x", sh[:11])
		}
		res.hit, res.master, res.arg = true, o.resume.master, o.resume.arg
	} else {
		pc, err := x509.ParseCertificate(serverCert)
		if err != nil {
			t.Fatal(err)
		}
		specs := sh[11+certLen : 11+certLen+specLen]
		if !bytes.Contains(specs, []byte{byte(o.kind >> 16), byte(o.kind >> 8), byte(o.kind)}) {
			t.Fatalf("specs %x", specs)
		}
		res.master, res.arg = random(sc.keyLen), random(sc.ivLen)
		clearLen := sc.keyLen - sc.secretLen
		enc, err := rsa.EncryptPKCS1v15(rand.Reader, pc.PublicKey.(*rsa.PublicKey), res.master[clearLen:])
		if err != nil {
			t.Fatal(err)
		}
		cmk := []byte{ssl2ClientMaster, byte(o.kind >> 16), byte(o.kind >> 8), byte(o.kind)}
		cmk = binary.BigEndian.AppendUint16(cmk, uint16(clearLen))
		cmk = binary.BigEndian.AppendUint16(cmk, uint16(len(enc)))
		cmk = binary.BigEndian.AppendUint16(cmk, uint16(len(res.arg)))
		if err := c.writeRecord2(cat(cmk, res.master[:clearLen], enc, res.arg)); err != nil {
			return nil, err
		}
	}
	var km []byte
	for d := byte('0'); len(km) < 2*sc.keyLen; d++ {
		h := md5.Sum(cat(res.master, []byte{d}, chal, connID))
		km = append(km, h[:]...)
	}
	km = km[:2*sc.keyLen]
	rk, wk := km[:sc.keyLen], km[sc.keyLen:]
	c.in2.key, c.out2.key = rk, wk
	if sc.ivLen == 0 {
		c.in2.stream, _ = rc4NewCipher(rk)
		c.out2.stream, _ = rc4NewCipher(wk)
	} else {
		rb, _ := sc.block(rk)
		wb, _ := sc.block(wk)
		c.in2.block, c.out2.block = cbcDecrypter(rb, res.arg), cbcEncrypter(wb, res.arg)
	}
	if err := c.writeRecord2(cat([]byte{ssl2ClientFinished}, connID)); err != nil {
		return nil, err
	}
	sv, err := c.readRecord2()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(sv, cat([]byte{ssl2ServerVerify}, chal)) {
		t.Fatalf("server verify %x", sv)
	}
	sf, err := c.readRecord2()
	if err != nil {
		return nil, err
	}
	if len(sf) > 0 && sf[0] == ssl2RequestCert {
		res.certRequested = true
		if sf[1] != ssl2AuthMD5RSA {
			t.Fatalf("request certificate %x", sf)
		}
		if o.cert == nil {
			c.writeRecord2([]byte{ssl2Error, 0, ssl2NoCertificate})
		} else {
			sum := md5.Sum(cat(km, sf[2:], serverCert))
			sig, err := rsa.SignPKCS1v15(rand.Reader, o.cert.PrivateKey.(*rsa.PrivateKey), crypto.MD5, sum[:])
			if err != nil {
				t.Fatal(err)
			}
			der := o.cert.Certificate[0]
			cc := []byte{ssl2ClientCert, 1}
			cc = binary.BigEndian.AppendUint16(cc, uint16(len(der)))
			cc = binary.BigEndian.AppendUint16(cc, uint16(len(sig)))
			if err := c.writeRecord2(cat(cc, der, sig)); err != nil {
				return nil, err
			}
		}
		if sf, err = c.readRecord2(); err != nil {
			return nil, err
		}
	}
	if len(sf) == 3 && sf[0] == ssl2Error {
		return nil, fmt.Errorf("SSL 2.0 error %x", sf)
	}
	if len(sf) != 17 || sf[0] != ssl2ServerFinished {
		t.Fatalf("server finished %x", sf)
	}
	res.sid = sf[1:]
	return res, nil
}

// TestSSL2: an SSL 2.0 client, with each cipher, and data echoed.
func TestSSL2(t *testing.T) {
	for _, sc := range ssl2Ciphers {
		t.Run(sc.name, func(t *testing.T) {
			addr, errs, states := echo(t, Config{MinVersion: VersionSSL20})
			nc := dial(t, addr)
			c, err := ssl2Client(t, nc, VersionSSL20, sc.kind, nil)
			if err != nil {
				t.Fatal(err)
			}
			if st := <-states; st.Version != VersionSSL20 || st.CipherSuite != sc.kind {
				t.Errorf("state %+v", st)
			}
			want := bytes.Repeat([]byte("hello "), 6000)
			if err := c.writeRecord2(want); err != nil {
				t.Fatal(err)
			}
			var got []byte
			for len(got) < len(want) {
				data, err := c.readRecord2()
				if err != nil {
					t.Fatal(err)
				}
				got = append(got, data...)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("echo differs")
			}
			nc.Close()
			<-errs
		})
	}
}

// TestSSL2Fallback: an SSL 2.0 hello offering SSL 3.0 gets SSL 2.0 when
// SSL 3.0 is off.
func TestSSL2Fallback(t *testing.T) {
	addr, errs, states := echo(t, Config{MinVersion: VersionSSL20, MaxVersion: VersionSSL20})
	nc := dial(t, addr)
	if _, err := ssl2Client(t, nc, VersionSSL30, 0x010080, []uint16{0x0004}); err != nil {
		t.Fatal(err)
	}
	if st := <-states; st.Version != VersionSSL20 {
		t.Errorf("state %+v", st)
	}
	nc.Close()
	<-errs
}

// TestSSL2Off: an SSL 2.0-only client gets SSL 2.0's NO-CIPHER error when
// SSL 2.0 is off.
func TestSSL2Off(t *testing.T) {
	addr, errs, _ := echo(t, Config{})
	nc := dial(t, addr)
	if _, err := ssl2Client(t, nc, VersionSSL20, 0x010080, nil); err == nil {
		t.Fatal("handshake passed")
	}
	if err := <-errs; err == nil {
		t.Error("server took it")
	}
}

func TestWants(t *testing.T) {
	for _, c := range []struct {
		b    []byte
		want bool
	}{
		{v2Hello(VersionTLS10, []uint16{0x002f}, nil, make([]byte, 16)), true},
		{v2Hello(VersionSSL20, nil, []uint32{0x010080}, make([]byte, 16)), true},
		{[]byte{0x16, 3, 0, 0, 0x50, 1, 0, 0, 0x4c, 3, 0}, true},
		{[]byte{0x16, 3, 1, 0, 0x50, 1, 0, 0, 0x4c, 3, 1}, false},
		{[]byte{0x16, 3, 1, 0, 0x50, 1, 0, 0, 0x4c, 3, 3}, false},
		{[]byte{'G', 'E', 'T', ' ', '/'}, false},
	} {
		if got := Wants(c.b); got != c.want {
			t.Errorf("Wants(%x) = %v", c.b[:5], got)
		}
	}
}

func TestPRF(t *testing.T) {
	// The TLS 1.0 PRF test vector (48 bytes of 0xab secret, 64 of 0xcd
	// seed) from the IETF TLS list: its first bytes.
	secret := bytes.Repeat([]byte{0xab}, 48)
	seed := bytes.Repeat([]byte{0xcd}, 64)
	got := prf10(secret, "PRF Testvector", seed, 104)
	want := []byte{0xd3, 0xd4, 0xd1, 0xe3, 0x49, 0xb5, 0xd5, 0x15}
	if !bytes.Equal(got[:8], want) {
		t.Errorf("prf %x", got[:8])
	}
}
