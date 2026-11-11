// Package retrossl is an SSL 2.0, SSL 3.0 and TLS 1.0 server for the old
// clients Go's crypto/tls can't take:
//
//   - those that offer only SSL 3.0 (Netscape 3 and 4, IE 3 to 6 with their
//     defaults, old Java and mail programs), or only SSL 2.0 (Netscape 1
//     and 2, IE 2);
//   - those that open with an SSL 2.0-format hello, even for TLS 1.0 (AIM
//     6.2 to 7.5 through their NSS, IE 5 and 6, early Opera).  TLS's
//     Finished messages sign the hello's very bytes, so such a hello can't
//     be rewritten for crypto/tls;
//   - export builds that offer only 40- or 56-bit ciphers.
//
// Everything newer belongs on crypto/tls: Wants and Frontend tell the two
// apart from a connection's first bytes.
//
// Key exchange is RSA only (so the certificates' keys must be RSA), with
// AES-CBC, 3DES, IDEA, RC2, DES or RC4 and the export suites.  Sessions
// resume by id (Config.SessionCache), clients may renegotiate (securely,
// unless Config.Renegotiation says otherwise), DEFLATE compression can be
// turned on, and clients can be asked for certificates.  These protocols
// are broken; they are here because the clients have nothing else, and
// the traffic behind them should be treated as readable.
package retrossl

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// Versions.
const (
	VersionSSL20 = 0x0002
	VersionSSL30 = 0x0300
	VersionTLS10 = 0x0301
)

// VersionName is a version's name: "SSL 2.0", "SSL 3.0" or "TLS 1.0".
func VersionName(v uint16) string {
	switch v {
	case VersionSSL20:
		return "SSL 2.0"
	case VersionSSL30:
		return "SSL 3.0"
	case VersionTLS10:
		return "TLS 1.0"
	}
	return fmt.Sprintf("0x%04x", v)
}

// Config is a server's.  It must not change once in use.
type Config struct {
	// GetCertificate gives the certificate; its key must be RSA.  SSL
	// 2.0 sends only the first certificate of the chain, so SSL 2.0
	// clients must trust the certificate itself or its direct issuer.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	// MinVersion and MaxVersion bound the versions served: 0 means SSL
	// 3.0 and TLS 1.0.  SSL 2.0 is served only when MinVersion is
	// VersionSSL20.
	MinVersion, MaxVersion uint16

	// CipherSuites are the SSL 3.0 / TLS 1.0 suites allowed, nil for all
	// of CipherSuites().  The server's order is used.
	CipherSuites []uint16

	// SSL2Ciphers are the SSL 2.0 cipher kinds allowed, nil for all of
	// SSL2CipherKinds().
	SSL2Ciphers []uint32

	// SessionCache keeps sessions for clients to resume; nil: none are
	// kept, and every handshake is in full.
	SessionCache *SessionCache

	// Renegotiation is when clients may renegotiate (SSL 3.0 and TLS).
	Renegotiation RenegotiationSupport

	// Compression allows DEFLATE when the client offers it.  Off by
	// default: compression before encryption lets an attacker who can add
	// to the requests learn their secrets (CRIME).
	Compression bool

	// ClientAuth, ClientCAs and VerifyPeerCertificate are as crypto/tls's:
	// whether clients are asked for certificates, which CAs verify them,
	// and a check of the caller's own.  Clients' keys must be RSA.  SSL
	// 2.0 clients send no chain, so their certificates' issuers must be
	// in ClientCAs.
	ClientAuth            tls.ClientAuthType
	ClientCAs             *x509.CertPool
	VerifyPeerCertificate func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error
}

// RenegotiationSupport is when clients may renegotiate.
type RenegotiationSupport int

const (
	// RenegotiateSecure lets clients renegotiate that offered secure
	// renegotiation (RFC 5746) in their first hello: most clients from
	// 2010 on, and none before.
	RenegotiateSecure RenegotiationSupport = iota
	// RenegotiateNever refuses every renegotiation.
	RenegotiateNever
	// RenegotiateInsecure lets every client renegotiate, as servers did
	// before 2009.  An attacker in the path can then put their own
	// request in front of the client's (CVE-2009-3555).
	RenegotiateInsecure
)

func (c *Config) minVersion() uint16 {
	if c.MinVersion == 0 {
		return VersionSSL30
	}
	return c.MinVersion
}

func (c *Config) maxVersion() uint16 {
	if c.MaxVersion == 0 || c.MaxVersion > VersionTLS10 {
		return VersionTLS10
	}
	return c.MaxVersion
}

// CipherSuite is a suite this package serves.
type CipherSuite struct {
	ID     uint16
	Name   string
	Export bool // 40- or 56-bit
}

// CipherSuites are the SSL 3.0 / TLS 1.0 suites served, the best first.
func CipherSuites() []CipherSuite {
	var out []CipherSuite
	for _, s := range suites {
		out = append(out, CipherSuite{s.id, s.name, s.export != 0})
	}
	return out
}

// State is a connection's, once its handshake is done.
type State struct {
	Version          uint16
	CipherSuite      uint32 // the SSL 3.0 / TLS 1.0 suite, or SSL 2.0's three-byte cipher kind
	CipherName       string
	ServerName       string              // what the client asked for (TLS 1.0 only)
	V2Hello          bool                // the client opened with an SSL 2.0-format hello
	DidResume        bool                // the session was resumed
	Compression      uint8               // 0: none; 1: DEFLATE
	PeerCertificates []*x509.Certificate // the client's, when it sent any
}

const (
	recCCS       = 20
	recAlert     = 21
	recHandshake = 22
	recData      = 23

	hsHelloRequest       = 0
	hsClientHello        = 1
	hsServerHello        = 2
	hsCertificate        = 11
	hsServerKeyExchange  = 12
	hsCertificateRequest = 13
	hsServerDone         = 14
	hsCertificateVerify  = 15
	hsClientKeyExchange  = 16
	hsFinished           = 20

	maxPlain  = 16384
	maxRecord = maxPlain + 2048
	maxHSMsg  = 1 << 16

	alertCloseNotify            = 0
	alertUnexpected             = 10
	alertBadMAC                 = 20
	alertOverflow               = 22
	alertHandshakeFailure       = 40
	alertNoCertificate          = 41 // SSL 3.0's
	alertBadCertificate         = 42
	alertUnsupportedCertificate = 43
	alertIllegalParameter       = 47
	alertDecode                 = 50
	alertDecrypt                = 51
	alertProtocolVersion        = 70
	alertInternal               = 80
	alertNoRenegotiation        = 100
	levelWarning, levelFatal    = 1, 2
)

// Conn is a connection, server side.
type Conn struct {
	net.Conn
	cfg *Config
	br  *bufio.Reader

	hsMu   sync.Mutex
	hsDone bool
	hsErr  error
	up     atomic.Bool
	state  State
	ssl2   bool // SSL 2.0's records, not SSL 3.0's

	hs         []byte // handshake bytes read, not yet taken
	transcript []byte // the handshake's messages so far

	secureReneg                bool   // the client does RFC 5746
	clientVerify, serverVerify []byte // the last handshake's Finished
	renegotiating              bool
	wantNoCert                 bool   // SSL 3.0's no_certificate alert would do
	serverLeaf                 []byte // SSL 2.0: the certificate sent

	inMu    sync.Mutex
	in      half
	in2     half2
	data    []byte
	readErr error

	outMu sync.Mutex
	out   half
	out2  half2
}

// Server is c served by this package, whatever its hello; the handshake
// comes with the first Read or Write, or Handshake.
func Server(c net.Conn, cfg *Config) *Conn {
	sc := &Conn{Conn: c, cfg: cfg}
	if p, ok := c.(*peeked); ok {
		sc.br = p.r
	} else {
		sc.br = bufio.NewReader(c)
	}
	sc.out.version = VersionTLS10
	return sc
}

// ConnectionState is the connection's state (zero before the handshake).
func (c *Conn) ConnectionState() State {
	c.hsMu.Lock()
	defer c.hsMu.Unlock()
	return c.state
}

// tlsError is an error that sends an alert.
type tlsError struct {
	alert uint8
	msg   string
}

func (e *tlsError) Error() string { return "retrossl: " + e.msg }

func fail(alert uint8, format string, a ...any) error {
	return &tlsError{alert, fmt.Sprintf(format, a...)}
}

// alertFor sends err's alert, if it has one.
func (c *Conn) alertFor(err error) {
	var te *tlsError
	if errors.As(err, &te) && te.alert != 0 {
		c.sendAlert(levelFatal, te.alert)
	}
}

// ssl3Alerts maps TLS's alerts to SSL 3.0's, which has fewer.
var ssl3Alerts = map[uint8]uint8{
	alertOverflow:        alertBadMAC,
	alertDecode:          alertIllegalParameter,
	alertDecrypt:         alertHandshakeFailure,
	alertProtocolVersion: alertHandshakeFailure,
	alertInternal:        alertHandshakeFailure,
}

func (c *Conn) sendAlert(level, desc uint8) {
	if c.ssl2 {
		return // SSL 2.0 has its own errors, sent where they happen
	}
	if c.out.version == VersionSSL30 {
		if d, ok := ssl3Alerts[desc]; ok {
			desc = d
		}
	}
	c.writeRecord(recAlert, []byte{level, desc})
}

// alertIn is the error for an alert the client sent.
func alertIn(data []byte) error {
	if len(data) != 2 {
		return fail(alertDecode, "bad alert")
	}
	if data[1] == alertCloseNotify {
		return io.EOF
	}
	return fmt.Errorf("retrossl: alert %d from the client", data[1])
}

func (c *Conn) writeRecord(typ uint8, data []byte) error {
	c.outMu.Lock()
	defer c.outMu.Unlock()
	var buf []byte
	for len(data) > 0 || buf == nil {
		n := min(len(data), maxPlain)
		buf = append(buf, c.out.seal(typ, data[:n])...)
		data = data[n:]
	}
	_, err := c.Conn.Write(buf)
	return err
}

func (c *Conn) readRecord() (uint8, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(c.br, hdr[:]); err != nil {
		return 0, nil, err
	}
	if hdr[1] != 3 {
		return 0, nil, fail(alertProtocolVersion, "record version %x", hdr[1:3])
	}
	n := int(hdr[3])<<8 | int(hdr[4])
	if n > maxRecord {
		return 0, nil, fail(alertOverflow, "record of %d bytes", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c.br, body); err != nil {
		return 0, nil, err
	}
	plain, ok := c.in.open(hdr[0], body)
	if !ok {
		return 0, nil, fail(alertBadMAC, "bad record MAC")
	}
	if len(plain) > maxPlain {
		return 0, nil, fail(alertOverflow, "record of %d bytes", len(plain))
	}
	return hdr[0], plain, nil
}

// readHandshake is the next handshake message, whole (with its header).
func (c *Conn) readHandshake() ([]byte, error) {
	for {
		if len(c.hs) >= 4 {
			n := int(c.hs[1])<<16 | int(c.hs[2])<<8 | int(c.hs[3])
			if n > maxHSMsg {
				return nil, fail(alertDecode, "handshake message of %d bytes", n)
			}
			if len(c.hs) >= 4+n {
				m := slices.Clone(c.hs[:4+n])
				c.hs = c.hs[4+n:]
				return m, nil
			}
		}
		typ, data, err := c.readRecord()
		if err != nil {
			return nil, err
		}
		switch {
		case typ == recHandshake:
			c.hs = append(c.hs, data...)
		case typ == recAlert && c.wantNoCert && len(data) == 2 && data[0] == levelWarning && data[1] == alertNoCertificate:
			return nil, errNoCertificate
		case typ == recAlert:
			return nil, alertIn(data)
		case typ == recData && c.renegotiating: // data may come between a renegotiation's messages
			c.data = append(c.data, data...)
		default:
			return nil, fail(alertUnexpected, "record type %d in the handshake", typ)
		}
	}
}

// errNoCertificate: SSL 3.0's no_certificate alert, for the client's
// Certificate.
var errNoCertificate = errors.New("retrossl: the client has no certificate")

// Handshake runs the handshake, if it hasn't run.
func (c *Conn) Handshake() error {
	c.hsMu.Lock()
	defer c.hsMu.Unlock()
	if c.hsDone {
		return c.hsErr
	}
	c.hsDone = true
	if c.hsErr = c.serverHandshake(); c.hsErr != nil {
		c.alertFor(c.hsErr)
	} else {
		c.up.Store(true)
	}
	return c.hsErr
}

// Read reads application data.
func (c *Conn) Read(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	c.inMu.Lock()
	defer c.inMu.Unlock()
	for len(c.data) == 0 {
		if c.readErr != nil {
			return 0, c.readErr
		}
		if c.ssl2 {
			data, err := c.readRecord2()
			if err != nil {
				c.readErr = err
			}
			c.data = data
			continue
		}
		typ, data, err := c.readRecord()
		switch {
		case err != nil:
			c.alertFor(err)
			c.readErr = err
		case typ == recData:
			c.data = data
		case typ == recAlert:
			if len(data) == 2 && data[0] == levelWarning && data[1] != alertCloseNotify {
				continue
			}
			c.readErr = alertIn(data)
		case typ == recHandshake: // the client would renegotiate
			c.hs = append(c.hs, data...)
			if err := c.handleRenegotiation(); err != nil {
				c.readErr = err
				c.alertFor(err)
			}
		default:
			c.readErr = fail(alertUnexpected, "record type %d", typ)
			c.alertFor(c.readErr)
		}
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}

// handleRenegotiation answers a client's renegotiation, as the Config
// allows.
func (c *Conn) handleRenegotiation() error {
	cfg := c.cfg
	if cfg.Renegotiation == RenegotiateNever || (!c.secureReneg && cfg.Renegotiation != RenegotiateInsecure) {
		c.hs = nil
		if c.out.version == VersionSSL30 { // which has no alert to say no
			return fail(alertHandshakeFailure, "the client would renegotiate, which is off")
		}
		c.sendAlert(levelWarning, alertNoRenegotiation)
		return nil
	}
	c.hsMu.Lock()
	defer c.hsMu.Unlock()
	return c.renegotiate()
}

// Write writes application data.
func (c *Conn) Write(p []byte) (int, error) {
	if err := c.Handshake(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	var err error
	if c.ssl2 {
		err = c.writeRecord2(p)
	} else {
		err = c.writeRecord(recData, p)
	}
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close sends close_notify (after an SSL 3.0 or TLS handshake) and closes
// the connection.
func (c *Conn) Close() error {
	if c.up.Load() && !c.ssl2 {
		c.Conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		c.sendAlert(levelWarning, alertCloseNotify)
	}
	return c.Conn.Close()
}

// random is n random bytes.
func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// rsaKey is a certificate's RSA key.
func rsaKey(cert *tls.Certificate) (*rsa.PrivateKey, bool) {
	k, ok := cert.PrivateKey.(*rsa.PrivateKey)
	return k, ok && len(cert.Certificate) > 0
}
