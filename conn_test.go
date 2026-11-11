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
// record layer.
type oldClient struct {
	t          *testing.T
	c          Conn
	transcript []byte
	tempKey    bool // the server sent a ServerKeyExchange
}

func v2Hello(version uint16, suites []uint16, kinds []uint32, challenge []byte) []byte {
	var specs []byte
	for _, k := range kinds {
		specs = append(specs, byte(k>>16), byte(k>>8), byte(k))
	}
	for _, s := range suites {
		specs = append(specs, 0, byte(s>>8), byte(s))
	}
	m := binary.BigEndian.AppendUint16([]byte{1}, version)
	m = binary.BigEndian.AppendUint16(m, uint16(len(specs)))
	m = binary.BigEndian.AppendUint16(m, 0)
	m = binary.BigEndian.AppendUint16(m, uint16(len(challenge)))
	m = append(append(m, specs...), challenge...)
	return append([]byte{0x80 | byte(len(m)>>8), byte(len(m))}, m...)
}

// handshake runs the client's side, offering version v and suite id, in
// an SSL 2.0-format hello if v2; a wrong Finished if badFinished.
func (o *oldClient) handshake(nc net.Conn, v, id uint16, v2, badFinished bool) error {
	t := o.t
	c := &o.c
	c.Conn, c.br = nc, bufio.NewReader(nc)
	c.out.version = v
	cr := random(32)
	offer := []uint16{id}
	if v == VersionTLS10 {
		offer = append(offer, 0x00ff)
	}
	if v2 {
		chal := random(16)
		copy(cr, make([]byte, 16))
		copy(cr[16:], chal)
		hello := v2Hello(v, offer, []uint32{0x010080}, chal)
		o.transcript = append(o.transcript, hello[2:]...)
		if _, err := nc.Write(hello); err != nil {
			return err
		}
	} else {
		body := binary.BigEndian.AppendUint16(nil, v)
		body = append(append(body, cr...), 0)
		body = binary.BigEndian.AppendUint16(body, uint16(2*len(offer)))
		for _, s := range offer {
			body = binary.BigEndian.AppendUint16(body, s)
		}
		hello := msg(hsClientHello, append(body, 1, 0))
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
	sr := sh[6:38]
	if got := binary.BigEndian.Uint16(sh[39:]); got != id {
		t.Fatalf("suite %04x", got)
	}
	if hasReneg := bytes.HasSuffix(sh, []byte{0xff, 0x01, 0, 1, 0}); hasReneg != (v == VersionTLS10) {
		t.Errorf("renegotiation_info %v at %x", hasReneg, v)
	}
	o.transcript = append(o.transcript, sh...)
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
	if m[0] != hsServerDone {
		t.Fatalf("server hello done %x", m)
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
	cke := msg(hsClientKeyExchange, ct)
	o.transcript = append(o.transcript, cke...)
	ms := masterSecret(v, pre, cr, sr)
	s := suiteByID(id)
	ck, sk := s.keys(v, ms, cr, sr)
	fin := finished(v, ms, o.transcript, true)
	if badFinished {
		fin[0] ^= 1
	}
	finMsg := msg(hsFinished, fin)
	o.transcript = append(o.transcript, finMsg...)
	if err := c.writeRecord(recHandshake, cke); err != nil {
		return err
	}
	if err := c.writeRecord(recCCS, []byte{1}); err != nil {
		return err
	}
	c.out = s.newHalf(v, ck, true)
	if err := c.writeRecord(recHandshake, finMsg); err != nil {
		return err
	}
	typ, data, err := c.readRecord()
	if err != nil {
		return err
	}
	if typ == recAlert {
		return alertIn(data)
	}
	if typ != recCCS {
		t.Fatalf("record %d, not CCS", typ)
	}
	c.in = s.newHalf(v, sk, false)
	sf, err := c.readHandshake()
	if err != nil {
		return err
	}
	if !bytes.Equal(sf[4:], finished(v, ms, o.transcript, false)) {
		t.Fatalf("server Finished wrong")
	}
	return nil
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
					o := &oldClient{t: t}
					if err := o.handshake(dial(t, addr), v, s.id, v2, false); err != nil {
						t.Fatal(err)
					}
					if o.tempKey != (s.export != 0) {
						t.Errorf("temporary key sent: %v", o.tempKey)
					}
					st := <-states
					if st.Version != v || st.CipherSuite != uint32(s.id) || st.V2Hello != v2 {
						t.Errorf("state %+v", st)
					}
					c := &o.c
					want := bytes.Repeat([]byte("hello "), 5000)
					if err := c.writeRecord(recData, want); err != nil {
						t.Fatal(err)
					}
					var got []byte
					for len(got) < len(want) {
						typ, data, err := c.readRecord()
						if err != nil || typ != recData {
							t.Fatalf("record %d: %v", typ, err)
						}
						got = append(got, data...)
					}
					if !bytes.Equal(got, want) {
						t.Fatal("echo differs")
					}
					c.sendAlert(levelWarning, alertCloseNotify)
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
		o := &oldClient{t: t}
		if err := o.handshake(dial(t, addr), v, 0x002f, false, true); err == nil {
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

// ssl2Client runs SSL 2.0's client side with cipher kind; offer is what
// the hello offers (version and kinds).
func ssl2Client(t *testing.T, nc net.Conn, version uint16, kind uint32, suites []uint16) (*Conn, error) {
	c := &Conn{Conn: nc, br: bufio.NewReader(nc), ssl2: true}
	chal := random(16)
	if _, err := nc.Write(v2Hello(version, suites, SSL2CipherKinds(), chal)); err != nil {
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
	if sh[0] != ssl2ServerHello || sh[1] != 0 || sh[2] != 1 || u(3) != VersionSSL20 {
		t.Fatalf("server hello %x", sh[:11])
	}
	certLen, specLen, idLen := u(5), u(7), u(9)
	pc, err := x509.ParseCertificate(sh[11 : 11+certLen])
	if err != nil {
		t.Fatal(err)
	}
	specs, connID := sh[11+certLen:11+certLen+specLen], sh[11+certLen+specLen:]
	if len(connID) != idLen || !bytes.Contains(specs, []byte{byte(kind >> 16), byte(kind >> 8), byte(kind)}) {
		t.Fatalf("specs %x, connection id %x", specs, connID)
	}
	var sc ssl2Cipher
	for _, x := range ssl2Ciphers {
		if x.kind == kind {
			sc = x
		}
	}
	master, arg := random(sc.keyLen), random(sc.ivLen)
	clearLen := sc.keyLen - sc.secretLen
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, pc.PublicKey.(*rsa.PublicKey), master[clearLen:])
	if err != nil {
		t.Fatal(err)
	}
	cmk := []byte{ssl2ClientMaster, byte(kind >> 16), byte(kind >> 8), byte(kind)}
	cmk = binary.BigEndian.AppendUint16(cmk, uint16(clearLen))
	cmk = binary.BigEndian.AppendUint16(cmk, uint16(len(enc)))
	cmk = binary.BigEndian.AppendUint16(cmk, uint16(len(arg)))
	if err := c.writeRecord2(cat(cmk, master[:clearLen], enc, arg)); err != nil {
		return nil, err
	}
	var km []byte
	for d := byte('0'); len(km) < 2*sc.keyLen; d++ {
		h := md5.Sum(cat(master, []byte{d}, chal, connID))
		km = append(km, h[:]...)
	}
	rk, wk := km[:sc.keyLen], km[sc.keyLen:2*sc.keyLen]
	c.in2.key, c.out2.key = rk, wk
	if sc.ivLen == 0 {
		c.in2.stream, _ = rc4NewCipher(rk)
		c.out2.stream, _ = rc4NewCipher(wk)
	} else {
		rb, _ := sc.block(rk)
		wb, _ := sc.block(wk)
		c.in2.block, c.out2.block = cbcDecrypter(rb, arg), cbcEncrypter(wb, arg)
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
	if len(sf) != 17 || sf[0] != ssl2ServerFinished {
		t.Fatalf("server finished %x", sf)
	}
	return c, nil
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
