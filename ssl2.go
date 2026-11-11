package retrossl

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"io"
	"slices"
)

// ssl2Cipher is an SSL 2.0 cipher kind.  Its MAC is always MD5.
type ssl2Cipher struct {
	kind      uint32
	name      string
	keyLen    int // the master key's length, and each direction's key's
	secretLen int // of the master key, the part sent encrypted
	ivLen     int // 0: RC4
	block     func(key []byte) (cipher.Block, error)
}

// ssl2Ciphers are those served, the best first.  (No RC2 or IDEA.)
var ssl2Ciphers = []ssl2Cipher{
	{0x0700c0, "SSL_CK_DES_192_EDE3_CBC_WITH_MD5", 24, 24, 8, des.NewTripleDESCipher},
	{0x010080, "SSL_CK_RC4_128_WITH_MD5", 16, 16, 0, nil},
	{0x060040, "SSL_CK_DES_64_CBC_WITH_MD5", 8, 8, 8, des.NewCipher},
	{0x020080, "SSL_CK_RC4_128_EXPORT40_WITH_MD5", 16, 5, 0, nil},
}

// SSL2CipherKinds are the SSL 2.0 cipher kinds served, the best first.
func SSL2CipherKinds() []uint32 {
	var out []uint32
	for _, c := range ssl2Ciphers {
		out = append(out, c.kind)
	}
	return out
}

// SSL 2.0's messages and errors.
const (
	ssl2Error          = 0
	ssl2ClientHello    = 1
	ssl2ClientMaster   = 2
	ssl2ClientFinished = 3
	ssl2ServerHello    = 4
	ssl2ServerVerify   = 5
	ssl2ServerFinished = 6

	ssl2NoCipher = 0x0001

	ssl2MaxData = 16000 // per record, under the 3-byte header's 16383 with MAC and padding
)

// half2 is one direction of SSL 2.0's record layer: clear (key nil) until
// the keys are made.  Every record counts, the clear ones too.
type half2 struct {
	seq    uint32
	key    []byte // the MAC secret, which is the direction's key
	block  cipher.BlockMode
	stream cipher.Stream
}

func (h *half2) macOf(data, pad []byte) []byte {
	m := md5.New()
	m.Write(h.key)
	m.Write(data)
	m.Write(pad)
	m.Write(binary.BigEndian.AppendUint32(nil, h.seq))
	return m.Sum(nil)
}

// seal is a record of data.
func (h *half2) seal(data []byte) []byte {
	defer func() { h.seq++ }()
	if h.key == nil {
		return append([]byte{0x80 | byte(len(data)>>8), byte(len(data))}, data...)
	}
	var pad []byte
	if h.block != nil {
		bs := h.block.BlockSize()
		pad = make([]byte, (bs-(md5.Size+len(data))%bs)%bs)
	}
	body := cat(h.macOf(data, pad), data, pad)
	if h.block != nil {
		h.block.CryptBlocks(body, body)
	} else {
		h.stream.XORKeyStream(body, body)
	}
	if len(pad) == 0 {
		return append([]byte{0x80 | byte(len(body)>>8), byte(len(body))}, body...)
	}
	return append([]byte{byte(len(body)>>8) & 0x3f, byte(len(body)), byte(len(pad))}, body...)
}

// open is a record's data, in place; ok false: its MAC is wrong.
func (h *half2) open(body []byte, pad int) (data []byte, ok bool) {
	defer func() { h.seq++ }()
	if h.key == nil {
		return body, pad == 0
	}
	if h.block != nil {
		if len(body)%h.block.BlockSize() != 0 {
			return nil, false
		}
		h.block.CryptBlocks(body, body)
	} else {
		h.stream.XORKeyStream(body, body)
	}
	if len(body) < md5.Size+pad {
		return nil, false
	}
	n := len(body) - pad
	return body[md5.Size:n], hmac.Equal(body[:md5.Size], h.macOf(body[md5.Size:n], body[n:]))
}

func (c *Conn) writeRecord2(data []byte) error {
	c.outMu.Lock()
	defer c.outMu.Unlock()
	var buf []byte
	for len(data) > 0 || buf == nil {
		n := min(len(data), ssl2MaxData)
		buf = append(buf, c.out2.seal(data[:n])...)
		data = data[n:]
	}
	_, err := c.Conn.Write(buf)
	return err
}

func (c *Conn) readRecord2() ([]byte, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(c.br, hdr[:2]); err != nil {
		return nil, err
	}
	var n, pad int
	if hdr[0]&0x80 != 0 {
		n = int(hdr[0]&0x7f)<<8 | int(hdr[1])
	} else {
		if _, err := io.ReadFull(c.br, hdr[2:]); err != nil {
			return nil, err
		}
		n, pad = int(hdr[0]&0x3f)<<8|int(hdr[1]), int(hdr[2])
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c.br, body); err != nil {
		return nil, err
	}
	data, ok := c.in2.open(body, pad)
	if !ok {
		return nil, fail(0, "bad SSL 2.0 record MAC")
	}
	return data, nil
}

// writeError2 sends an SSL 2.0 ERROR.
func (c *Conn) writeError2(code uint16) {
	c.writeRecord2(binary.BigEndian.AppendUint16([]byte{ssl2Error}, code))
}

// readMsg2 is the next SSL 2.0 handshake message, which must be typ.
func (c *Conn) readMsg2(typ byte) ([]byte, error) {
	m, err := c.readRecord2()
	if err != nil {
		return nil, err
	}
	if len(m) >= 3 && m[0] == ssl2Error {
		return nil, fail(0, "SSL 2.0 error %d from the client", binary.BigEndian.Uint16(m[1:]))
	}
	if len(m) == 0 || m[0] != typ {
		return nil, fail(0, "SSL 2.0 message %x, not %d", m[:min(len(m), 1)], typ)
	}
	return m, nil
}

func (c *Conn) handshake2(ch *clientHello, cert *tls.Certificate, key *rsa.PrivateKey) error {
	c.ssl2 = true
	var common []ssl2Cipher
	for _, sc := range ssl2Ciphers {
		if slices.Contains(ch.ssl2Kinds, sc.kind) && (c.cfg.SSL2Ciphers == nil || slices.Contains(c.cfg.SSL2Ciphers, sc.kind)) {
			common = append(common, sc)
		}
	}
	if len(common) == 0 {
		c.writeError2(ssl2NoCipher)
		return fail(0, "no SSL 2.0 cipher in common: the client offers %06x", ch.ssl2Kinds)
	}
	var specs []byte
	for _, sc := range common {
		specs = append(specs, byte(sc.kind>>16), byte(sc.kind>>8), byte(sc.kind))
	}
	connID := random(16)
	leaf := cert.Certificate[0]
	sh := []byte{ssl2ServerHello, 0, 1} // no session hit; an X.509 certificate
	sh = binary.BigEndian.AppendUint16(sh, VersionSSL20)
	sh = binary.BigEndian.AppendUint16(sh, uint16(len(leaf)))
	sh = binary.BigEndian.AppendUint16(sh, uint16(len(specs)))
	sh = binary.BigEndian.AppendUint16(sh, uint16(len(connID)))
	sh = cat(sh, leaf, specs, connID)
	if err := c.writeRecord2(sh); err != nil {
		return err
	}

	m, err := c.readMsg2(ssl2ClientMaster)
	if err != nil {
		return err
	}
	if len(m) < 10 {
		return fail(0, "short CLIENT-MASTER-KEY")
	}
	kind := uint32(m[1])<<16 | uint32(m[2])<<8 | uint32(m[3])
	u := func(i int) int { return int(binary.BigEndian.Uint16(m[i:])) }
	clearLen, encLen, argLen := u(4), u(6), u(8)
	if 10+clearLen+encLen+argLen != len(m) {
		return fail(0, "bad CLIENT-MASTER-KEY")
	}
	i := slices.IndexFunc(common, func(sc ssl2Cipher) bool { return sc.kind == kind })
	if i < 0 {
		c.writeError2(ssl2NoCipher)
		return fail(0, "the client chose cipher %06x, not offered", kind)
	}
	sc := common[i]
	clear, enc, arg := m[10:10+clearLen], m[10+clearLen:10+clearLen+encLen], m[10+clearLen+encLen:]
	if clearLen+sc.secretLen != sc.keyLen || argLen != sc.ivLen {
		return fail(0, "CLIENT-MASTER-KEY's lengths are wrong for %s", sc.name)
	}
	// As for SSL 3.0: a bad decryption goes on with a random secret, and
	// fails at CLIENT-FINISHED.
	secret := random(sc.secretLen)
	if err := rsa.DecryptPKCS1v15SessionKey(nil, key, enc, secret); err != nil {
		return fail(0, "%v", err)
	}
	master := cat(clear, secret)

	// Key material: MD5(master, "0", challenge, connection id), then "1"...
	var km []byte
	for d := byte('0'); len(km) < 2*sc.keyLen; d++ {
		h := md5.Sum(cat(master, []byte{d}, ch.challenge, connID))
		km = append(km, h[:]...)
	}
	// The client reads with the first key and writes with the second; the
	// MAC secrets are the keys.
	wk, rk := km[:sc.keyLen], km[sc.keyLen:2*sc.keyLen]
	c.in2.key, c.out2.key = rk, wk
	if sc.ivLen == 0 {
		c.in2.stream, _ = rc4.NewCipher(rk)
		c.out2.stream, _ = rc4.NewCipher(wk)
	} else {
		rb, _ := sc.block(rk)
		wb, _ := sc.block(wk)
		c.in2.block = cipher.NewCBCDecrypter(rb, arg)
		c.out2.block = cipher.NewCBCEncrypter(wb, arg)
	}

	if err := c.writeRecord2(cat([]byte{ssl2ServerVerify}, ch.challenge)); err != nil {
		return err
	}
	if m, err = c.readMsg2(ssl2ClientFinished); err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(m[1:], connID) != 1 {
		return fail(0, "the client's CLIENT-FINISHED is wrong")
	}
	if err := c.writeRecord2(cat([]byte{ssl2ServerFinished}, random(16))); err != nil {
		return err
	}
	c.transcript = nil
	c.state = State{Version: VersionSSL20, CipherSuite: sc.kind, CipherName: sc.name, V2Hello: true}
	return nil
}
