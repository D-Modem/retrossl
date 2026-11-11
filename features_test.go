package retrossl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

var (
	clientOnce sync.Once
	clientCA   *x509.CertPool
	clientCert tls.Certificate
)

// clientCertificate is a client certificate and the pool of its CA.
func clientCertificate(t *testing.T) (*tls.Certificate, *x509.CertPool) {
	t.Helper()
	clientOnce.Do(func() {
		caKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		caTmpl := &x509.Certificate{SerialNumber: big.NewInt(10), Subject: pkix.Name{CommonName: "Test client CA"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
			BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
		caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		ca, _ := x509.ParseCertificate(caDER)
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "caller"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		clientCA = x509.NewCertPool()
		clientCA.AddCert(ca)
		clientCert = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	})
	return &clientCert, clientCA
}

var versions = []uint16{VersionSSL30, VersionTLS10}

// closeCheck ends a test client's connection and checks the server's end.
func closeCheck(t *testing.T, o *oldClient, errs chan error) {
	t.Helper()
	o.c.sendAlert(levelWarning, alertCloseNotify)
	if err := <-errs; err != nil {
		t.Errorf("server: %v", err)
	}
}

func TestResume(t *testing.T) {
	for _, v := range versions {
		t.Run(VersionName(v), func(t *testing.T) {
			cfg := Config{SessionCache: NewSessionCache(0, 0)}
			addr, errs, _ := echoBy(t, cfg, v == VersionSSL30)
			o := &oldClient{t: t, v: v, id: 0x002f}
			if err := o.handshake(dial(t, addr)); err != nil {
				t.Fatal(err)
			}
			if len(o.gotSID) != 32 || o.resumed {
				t.Fatalf("session id %x, resumed %v", o.gotSID, o.resumed)
			}
			o.echoCheck(t, 10)
			closeCheck(t, o, errs)
			if n := cfg.SessionCache.Len(); n != 1 {
				t.Fatalf("%d sessions kept", n)
			}

			addr, errs, states := echoBy(t, cfg, v == VersionSSL30)
			o2 := &oldClient{t: t, v: v, id: 0x002f, sessionID: o.gotSID, ms: o.ms}
			if err := o2.handshake(dial(t, addr)); err != nil {
				t.Fatal(err)
			}
			if !o2.resumed {
				t.Fatal("not resumed")
			}
			if st := <-states; !st.DidResume || st.Version != v {
				t.Errorf("state %+v", st)
			}
			o2.echoCheck(t, 3000)
			closeCheck(t, o2, errs)

			// an unknown session: a full handshake
			addr, errs, _ = echoBy(t, cfg, v == VersionSSL30)
			o3 := &oldClient{t: t, v: v, id: 0x002f, sessionID: random(32), ms: o.ms}
			if err := o3.handshake(dial(t, addr)); err != nil || o3.resumed {
				t.Fatalf("unknown session: resumed %v, %v", o3.resumed, err)
			}
			closeCheck(t, o3, errs)
		})
	}
}

func TestRenegotiate(t *testing.T) {
	for _, v := range versions {
		t.Run(VersionName(v), func(t *testing.T) {
			addr, errs, _ := echoBy(t, Config{}, v == VersionSSL30)
			o := &oldClient{t: t, v: v, id: 0x002f, secure: true}
			if err := o.handshake(dial(t, addr)); err != nil {
				t.Fatal(err)
			}
			o.echoCheck(t, 100)
			o.id = 0x000a // and another suite
			if err := o.renegotiate(); err != nil {
				t.Fatal(err)
			}
			o.echoCheck(t, 3000)
			if err := o.renegotiate(); err != nil {
				t.Fatal(err)
			}
			o.echoCheck(t, 10)
			closeCheck(t, o, errs)
		})
	}
}

// TestRenegotiateRefused: a client without secure renegotiation can't
// renegotiate by default: TLS says no_renegotiation and goes on, SSL 3.0
// has no such alert and ends.
func TestRenegotiateRefused(t *testing.T) {
	for _, v := range versions {
		t.Run(VersionName(v), func(t *testing.T) {
			addr, errs, _ := echoBy(t, Config{}, v == VersionSSL30)
			o := &oldClient{t: t, v: v, id: 0x002f}
			if err := o.handshake(dial(t, addr)); err != nil {
				t.Fatal(err)
			}
			body := append(append([]byte{byte(v >> 8), byte(v)}, random(32)...), 0, 0, 2, 0, 0x2f, 1, 0)
			o.c.writeRecord(recHandshake, msg(hsClientHello, body))
			typ, data, err := o.c.readRecord()
			if err != nil || typ != recAlert {
				t.Fatalf("record %d %x: %v", typ, data, err)
			}
			if v == VersionTLS10 {
				if data[0] != levelWarning || data[1] != alertNoRenegotiation {
					t.Fatalf("alert %x", data)
				}
				o.echoCheck(t, 10)
				closeCheck(t, o, errs)
			} else {
				if data[0] != levelFatal || data[1] != alertHandshakeFailure {
					t.Fatalf("alert %x", data)
				}
				if err := <-errs; err == nil {
					t.Error("server went on")
				}
			}
		})
	}
}

func TestRenegotiateInsecure(t *testing.T) {
	addr, errs, _ := echoBy(t, Config{Renegotiation: RenegotiateInsecure}, true)
	o := &oldClient{t: t, v: VersionSSL30, id: 0x0004}
	if err := o.handshake(dial(t, addr)); err != nil {
		t.Fatal(err)
	}
	if err := o.renegotiate(); err != nil {
		t.Fatal(err)
	}
	o.echoCheck(t, 10)
	closeCheck(t, o, errs)
}

// TestHelloRequest: the server asks, the client renegotiates.
func TestHelloRequest(t *testing.T) {
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
		if err := sc.RequestRenegotiation(); err != nil {
			errs <- err
			return
		}
		_, err = io.Copy(sc, sc)
		errs <- err
	}()
	o := &oldClient{t: t, v: VersionTLS10, id: 0x002f, secure: true}
	if err := o.handshake(dial(t, ln.Addr().String())); err != nil {
		t.Fatal(err)
	}
	m, err := o.c.readHandshake()
	if err != nil || m[0] != hsHelloRequest {
		t.Fatalf("hello request %x: %v", m, err)
	}
	if err := o.renegotiate(); err != nil {
		t.Fatal(err)
	}
	o.echoCheck(t, 10)
	closeCheck(t, o, errs)
}

func TestCompression(t *testing.T) {
	for _, v := range versions {
		for _, on := range []bool{false, true} {
			addr, errs, states := echoBy(t, Config{Compression: on}, v == VersionSSL30)
			o := &oldClient{t: t, v: v, id: 0x0035, comp: true}
			if err := o.handshake(dial(t, addr)); err != nil {
				t.Fatal(err)
			}
			want := uint8(0)
			if on {
				want = compDeflate
			}
			if st := <-states; o.compMethod != want || st.Compression != want {
				t.Fatalf("%s: compression %d, state %+v", VersionName(v), o.compMethod, st)
			}
			o.echoCheck(t, 20000) // compresses well: several records' worth
			o.echoCheck(t, 1)
			closeCheck(t, o, errs)
		}
	}
}

func TestClientCert(t *testing.T) {
	cc, pool := clientCertificate(t)
	for _, v := range versions {
		t.Run(VersionName(v), func(t *testing.T) {
			cfg := Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
			addr, errs, states := echoBy(t, cfg, v == VersionSSL30)
			o := &oldClient{t: t, v: v, id: 0x002f, cert: cc}
			if err := o.handshake(dial(t, addr)); err != nil {
				t.Fatal(err)
			}
			st := <-states
			if !o.certRequested || len(st.PeerCertificates) != 1 || st.PeerCertificates[0].Subject.CommonName != "caller" {
				t.Fatalf("state %+v", st)
			}
			o.echoCheck(t, 10)
			closeCheck(t, o, errs)

			// no certificate: refused when required, taken when only asked
			addr, errs, _ = echoBy(t, cfg, v == VersionSSL30)
			o = &oldClient{t: t, v: v, id: 0x002f}
			if err := o.handshake(dial(t, addr)); err == nil {
				t.Error("handshake without a certificate passed")
			}
			if err := <-errs; err == nil {
				t.Error("server took no certificate")
			}
			addr, errs, states = echoBy(t, Config{ClientAuth: tls.RequestClientCert}, v == VersionSSL30)
			o = &oldClient{t: t, v: v, id: 0x002f}
			if err := o.handshake(dial(t, addr)); err != nil {
				t.Fatal(err)
			}
			if st := <-states; len(st.PeerCertificates) != 0 {
				t.Errorf("state %+v", st)
			}
			closeCheck(t, o, errs)
		})
	}
}

func TestSSL2Resume(t *testing.T) {
	cfg := Config{MinVersion: VersionSSL20, SessionCache: NewSessionCache(0, 0)}
	addr, errs, _ := echo(t, cfg)
	nc := dial(t, addr)
	r, err := ssl2Run(t, nc, ssl2Opts{version: VersionSSL20, kind: 0x0700c0})
	if err != nil || r.hit {
		t.Fatalf("first: hit %v, %v", r != nil && r.hit, err)
	}
	nc.Close()
	<-errs
	addr, errs, states := echo(t, cfg)
	nc = dial(t, addr)
	r2, err := ssl2Run(t, nc, ssl2Opts{version: VersionSSL20, kind: 0x0700c0, resume: r})
	if err != nil || !r2.hit {
		t.Fatalf("second: hit %v, %v", r2 != nil && r2.hit, err)
	}
	if st := <-states; !st.DidResume {
		t.Errorf("state %+v", st)
	}
	if err := r2.c.writeRecord2([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	if got, err := r2.c.readRecord2(); err != nil || string(got) != "ping" {
		t.Fatalf("echo %q %v", got, err)
	}
	nc.Close()
	<-errs
}

func TestSSL2ClientCert(t *testing.T) {
	cc, pool := clientCertificate(t)
	cfg := Config{MinVersion: VersionSSL20, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	addr, errs, states := echo(t, cfg)
	nc := dial(t, addr)
	r, err := ssl2Run(t, nc, ssl2Opts{version: VersionSSL20, kind: 0x010080, cert: cc})
	if err != nil || !r.certRequested {
		t.Fatalf("requested %v, %v", r != nil && r.certRequested, err)
	}
	if st := <-states; len(st.PeerCertificates) != 1 {
		t.Errorf("state %+v", st)
	}
	nc.Close()
	<-errs

	addr, errs, _ = echo(t, cfg)
	nc = dial(t, addr)
	if _, err := ssl2Run(t, nc, ssl2Opts{version: VersionSSL20, kind: 0x010080}); err == nil {
		t.Error("handshake without a certificate passed")
	}
	if err := <-errs; err == nil {
		t.Error("server took no certificate")
	}
}
