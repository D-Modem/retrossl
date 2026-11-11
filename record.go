package retrossl

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"crypto/sha1"
	"encoding/binary"
	"hash"
)

// suite is an SSL 3.0 / TLS 1.0 cipher suite: RSA key exchange, then a
// block cipher in CBC or RC4, with a MAC.
type suite struct {
	id     uint16
	name   string
	keyLen int // key bytes per side in the key block: 5 or 7 for export
	encLen int // the cipher's key length (export keys are stretched to it)
	ivLen  int // 0: RC4
	macLen int
	export int // export suites: the largest RSA key the key exchange may use
	block  func(key []byte) (cipher.Block, error)
	hash   func() hash.Hash
}

// suites are those served, the best first.  The export ones come last, for
// the clients that have nothing else (export builds of Netscape and IE).
var suites = []suite{
	{0x002f, "TLS_RSA_WITH_AES_128_CBC_SHA", 16, 16, 16, 20, 0, aes.NewCipher, sha1.New},
	{0x0035, "TLS_RSA_WITH_AES_256_CBC_SHA", 32, 32, 16, 20, 0, aes.NewCipher, sha1.New},
	{0x000a, "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 24, 24, 8, 20, 0, des.NewTripleDESCipher, sha1.New},
	{0x0005, "TLS_RSA_WITH_RC4_128_SHA", 16, 16, 0, 20, 0, nil, sha1.New},
	{0x0004, "TLS_RSA_WITH_RC4_128_MD5", 16, 16, 0, 16, 0, nil, md5.New},
	{0x0009, "TLS_RSA_WITH_DES_CBC_SHA", 8, 8, 8, 20, 0, des.NewCipher, sha1.New},
	{0x0064, "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", 7, 16, 0, 20, 1024, nil, sha1.New},
	{0x0062, "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", 7, 8, 8, 20, 1024, des.NewCipher, sha1.New},
	{0x0003, "TLS_RSA_EXPORT_WITH_RC4_40_MD5", 5, 16, 0, 16, 512, nil, md5.New},
	{0x0008, "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 5, 8, 8, 20, 512, des.NewCipher, sha1.New},
}

func suiteByID(id uint16) *suite {
	for i := range suites {
		if suites[i].id == id {
			return &suites[i]
		}
	}
	return nil
}

// SSL 3.0's MAC and Finished pads.
var (
	pad1 = [48]byte{0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36,
		0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36, 0x36}
	pad2 = [48]byte{0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
		0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c,
		0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c, 0x5c}
)

// padLen is SSL 3.0's pad length for a hash: 48 for MD5, 40 for SHA-1.
func padLen(h hash.Hash) int {
	if h.Size() == 20 {
		return 40
	}
	return 48
}

// half is one direction of the SSL 3.0 / TLS 1.0 record layer: none (mac
// nil) until the ChangeCipherSpec, then a cipher and MAC.
type half struct {
	version uint16 // put in records sent
	seq     uint64
	ssl3    bool
	macKey  []byte           // SSL 3.0's MAC secret (TLS's is in its HMAC)
	mac     hash.Hash        // TLS: an HMAC; SSL 3.0: the bare hash
	block   cipher.BlockMode // CBC; its IV chains from record to record
	stream  cipher.Stream    // or RC4
}

// dirKeys are one direction's MAC secret, key and IV.
type dirKeys struct{ mac, key, iv []byte }

// newHalf is a direction's protection from its keys (enc: the sending
// side).
func (s *suite) newHalf(v uint16, k dirKeys, enc bool) half {
	h := half{version: v}
	if v == VersionSSL30 {
		h.ssl3, h.macKey, h.mac = true, k.mac, s.hash()
	} else {
		h.mac = hmac.New(s.hash, k.mac)
	}
	if s.ivLen == 0 {
		h.stream, _ = rc4.NewCipher(k.key)
		return h
	}
	b, _ := s.block(k.key)
	if enc {
		h.block = cipher.NewCBCEncrypter(b, k.iv)
	} else {
		h.block = cipher.NewCBCDecrypter(b, k.iv)
	}
	return h
}

func (h *half) macOf(typ uint8, data []byte) []byte {
	var hdr [13]byte
	binary.BigEndian.PutUint64(hdr[:], h.seq)
	hdr[8] = typ
	if h.ssl3 {
		// hash(secret, pad2, hash(secret, pad1, seq, type, length, data))
		binary.BigEndian.PutUint16(hdr[9:], uint16(len(data)))
		n := padLen(h.mac)
		h.mac.Reset()
		h.mac.Write(h.macKey)
		h.mac.Write(pad1[:n])
		h.mac.Write(hdr[:11])
		h.mac.Write(data)
		inner := h.mac.Sum(nil)
		h.mac.Reset()
		h.mac.Write(h.macKey)
		h.mac.Write(pad2[:n])
		h.mac.Write(inner)
		return h.mac.Sum(nil)
	}
	binary.BigEndian.PutUint16(hdr[9:], h.version)
	binary.BigEndian.PutUint16(hdr[11:], uint16(len(data)))
	h.mac.Reset()
	h.mac.Write(hdr[:])
	h.mac.Write(data)
	return h.mac.Sum(nil)
}

// seal is a record of plain (at most maxPlain bytes).
func (h *half) seal(typ uint8, plain []byte) []byte {
	out := make([]byte, 5, 5+len(plain)+64)
	out[0] = typ
	binary.BigEndian.PutUint16(out[1:], h.version)
	if h.mac == nil {
		out = append(out, plain...)
	} else {
		body := append(append(make([]byte, 0, len(plain)+64), plain...), h.macOf(typ, plain)...)
		h.seq++
		if h.block != nil {
			bs := h.block.BlockSize()
			n := (bs - (len(body)+1)%bs) % bs
			for range n + 1 {
				body = append(body, byte(n))
			}
			h.block.CryptBlocks(body, body)
		} else {
			h.stream.XORKeyStream(body, body)
		}
		out = append(out, body...)
	}
	binary.BigEndian.PutUint16(out[3:], uint16(len(out)-5))
	return out
}

// open is a record's plaintext, in place; ok false: its MAC or padding is
// wrong.  A bad padding is still MACed, so the two fail alike.
func (h *half) open(typ uint8, body []byte) (plain []byte, ok bool) {
	if h.mac == nil {
		return body, true
	}
	ms := h.mac.Size()
	defer func() { h.seq++ }()
	if h.stream != nil {
		h.stream.XORKeyStream(body, body)
		if len(body) < ms {
			return nil, false
		}
		n := len(body) - ms
		return body[:n], hmac.Equal(h.macOf(typ, body[:n]), body[n:])
	}
	bs := h.block.BlockSize()
	if len(body)%bs != 0 || len(body) < ms+1 {
		return nil, false
	}
	h.block.CryptBlocks(body, body)
	pad := int(body[len(body)-1])
	good := true
	if pad+1+ms > len(body) || (h.ssl3 && pad >= bs) {
		good, pad = false, 0
	}
	if !h.ssl3 { // SSL 3.0's padding bytes are arbitrary; TLS's all equal its length
		for _, b := range body[len(body)-1-pad : len(body)-1] {
			if b != byte(pad) {
				good = false
			}
		}
	}
	n := len(body) - 1 - pad - ms
	macOK := hmac.Equal(h.macOf(typ, body[:n]), body[n:n+ms])
	return body[:n], macOK && good
}

// prf10 is TLS 1.0's PRF: P_MD5 over the secret's first half, XORed with
// P_SHA1 over its second.
func prf10(secret []byte, label string, seed []byte, n int) []byte {
	ls := append([]byte(label), seed...)
	s1, s2 := secret[:(len(secret)+1)/2], secret[len(secret)/2:]
	out, b := make([]byte, n), make([]byte, n)
	pHash(out, s1, ls, md5.New)
	pHash(b, s2, ls, sha1.New)
	for i := range out {
		out[i] ^= b[i]
	}
	return out
}

func pHash(out, secret, seed []byte, h func() hash.Hash) {
	m := hmac.New(h, secret)
	m.Write(seed)
	a := m.Sum(nil)
	for j := 0; j < len(out); {
		m.Reset()
		m.Write(a)
		m.Write(seed)
		j += copy(out[j:], m.Sum(nil))
		m.Reset()
		m.Write(a)
		a = m.Sum(nil)
	}
}

// prf30 is SSL 3.0's key generator: MD5(secret, SHA1("A", secret, r1,
// r2)), then with "BB", "CCC" and so on.
func prf30(secret, r1, r2 []byte, n int) []byte {
	out := make([]byte, 0, n+16)
	for i := 0; len(out) < n; i++ {
		s := sha1.New()
		for range i + 1 {
			s.Write([]byte{'A' + byte(i)})
		}
		s.Write(secret)
		s.Write(r1)
		s.Write(r2)
		m := md5.New()
		m.Write(secret)
		m.Write(s.Sum(nil))
		out = m.Sum(out)
	}
	return out[:n]
}

func cat(b ...[]byte) []byte {
	var out []byte
	for _, x := range b {
		out = append(out, x...)
	}
	return out
}

// masterSecret is the master secret from the pre-master secret.
func masterSecret(v uint16, pre, cr, sr []byte) []byte {
	if v == VersionSSL30 {
		return prf30(pre, cr, sr, 48)
	}
	return prf10(pre, "master secret", cat(cr, sr), 48)
}

// keys are a session's client and server protection, from its master
// secret and randoms.
func (s *suite) keys(v uint16, ms, cr, sr []byte) (client, server dirKeys) {
	n := 2 * (s.macLen + s.keyLen)
	if s.export == 0 {
		n += 2 * s.ivLen
	}
	var kb []byte
	if v == VersionSSL30 {
		kb = prf30(ms, sr, cr, n)
	} else {
		kb = prf10(ms, "key expansion", cat(sr, cr), n)
	}
	take := func(n int) []byte { v := kb[:n]; kb = kb[n:]; return v }
	client.mac, server.mac = take(s.macLen), take(s.macLen)
	client.key, server.key = take(s.keyLen), take(s.keyLen)
	if s.export == 0 {
		client.iv, server.iv = take(s.ivLen), take(s.ivLen)
		return
	}
	// Export: the short keys are stretched with the randoms, and the IVs
	// come from the randoms alone.
	if v == VersionSSL30 {
		md := func(b ...[]byte) []byte { h := md5.Sum(cat(b...)); return h[:] }
		client.key = md(client.key, cr, sr)[:s.encLen]
		server.key = md(server.key, sr, cr)[:s.encLen]
		client.iv = md(cr, sr)[:s.ivLen]
		server.iv = md(sr, cr)[:s.ivLen]
		return
	}
	client.key = prf10(client.key, "client write key", cat(cr, sr), s.encLen)
	server.key = prf10(server.key, "server write key", cat(cr, sr), s.encLen)
	ivs := prf10(nil, "IV block", cat(cr, sr), 2*s.ivLen)
	client.iv, server.iv = ivs[:s.ivLen], ivs[s.ivLen:]
	return
}

// finished is a Finished message's body for a handshake transcript.
func finished(v uint16, ms, transcript []byte, client bool) []byte {
	if v == VersionSSL30 {
		sender := "SRVR"
		if client {
			sender = "CLNT"
		}
		out := make([]byte, 0, 36)
		for _, h := range []hash.Hash{md5.New(), sha1.New()} {
			n := padLen(h)
			h.Write(transcript)
			h.Write([]byte(sender))
			h.Write(ms)
			h.Write(pad1[:n])
			inner := h.Sum(nil)
			h.Reset()
			h.Write(ms)
			h.Write(pad2[:n])
			h.Write(inner)
			out = h.Sum(out)
		}
		return out
	}
	label := "server finished"
	if client {
		label = "client finished"
	}
	m, s := md5.Sum(transcript), sha1.Sum(transcript)
	return prf10(ms, label, cat(m[:], s[:]), 12)
}
