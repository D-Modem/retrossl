// Package idea is the IDEA block cipher (Lai and Massey, 1991): 64-bit
// blocks and a 128-bit key, as SSL 2.0, SSL 3.0 and TLS 1.0 use it.
package idea

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// BlockSize is IDEA's block size in bytes.
const BlockSize = 8

type ideaCipher struct{ ek, dk [52]uint16 }

// NewCipher is IDEA with a 16-byte key.
func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != 16 {
		return nil, errors.New("idea: the key must be 16 bytes")
	}
	c := new(ideaCipher)
	// The key's eight 16-bit words, then the 128-bit key turned left by
	// 25 bits for the next eight, and so on.
	var k [8]uint16
	for i := range k {
		k[i] = binary.BigEndian.Uint16(key[2*i:])
	}
	for i := 0; i < 52; i++ {
		c.ek[i] = k[i%8]
		if i%8 == 7 {
			var n [8]uint16
			for j := range n {
				n[j] = k[(j+1)%8]<<9 | k[(j+2)%8]>>7
			}
			k = n
		}
	}
	// Decryption runs the same rounds with the keys inverted, in reverse.
	ek, p := c.ek[:], 52
	put := func(v ...uint16) {
		for i := len(v) - 1; i >= 0; i-- {
			p--
			c.dk[p] = v[i]
		}
	}
	put(inv(ek[0]), -ek[1], -ek[2], inv(ek[3]))
	ek = ek[4:]
	for range 7 {
		put(ek[0], ek[1])
		put(inv(ek[2]), -ek[4], -ek[3], inv(ek[5]))
		ek = ek[6:]
	}
	put(ek[0], ek[1])
	put(inv(ek[2]), -ek[3], -ek[4], inv(ek[5]))
	return c, nil
}

func (*ideaCipher) BlockSize() int { return BlockSize }

func (c *ideaCipher) Encrypt(dst, src []byte) { crypt(&c.ek, dst, src) }
func (c *ideaCipher) Decrypt(dst, src []byte) { crypt(&c.dk, dst, src) }

// mul is multiplication modulo 65537, with 0 standing for 65536.
func mul(a, b uint16) uint16 {
	x, y := uint32(a), uint32(b)
	if x == 0 {
		x = 65536
	}
	if y == 0 {
		y = 65536
	}
	return uint16(uint64(x) * uint64(y) % 65537)
}

// inv is the inverse for mul (65537 is prime: x to the 65535th).
func inv(x uint16) uint16 {
	if x <= 1 {
		return x
	}
	r, b := uint16(1), x
	for e := 65535; e > 0; e >>= 1 {
		if e&1 != 0 {
			r = mul(r, b)
		}
		b = mul(b, b)
	}
	return r
}

func crypt(k *[52]uint16, dst, src []byte) {
	if len(src) < BlockSize || len(dst) < BlockSize {
		panic("idea: block too short")
	}
	x1 := binary.BigEndian.Uint16(src[0:])
	x2 := binary.BigEndian.Uint16(src[2:])
	x3 := binary.BigEndian.Uint16(src[4:])
	x4 := binary.BigEndian.Uint16(src[6:])
	z := k[:]
	for range 8 {
		x1 = mul(x1, z[0])
		x2 += z[1]
		x3 += z[2]
		x4 = mul(x4, z[3])
		t0 := mul(x1^x3, z[4])
		t1 := mul((x2^x4)+t0, z[5])
		t0 += t1
		x1 ^= t1
		x4 ^= t0
		x2, x3 = x3^t1, x2^t0
		z = z[6:]
	}
	// the last round's swap undone
	binary.BigEndian.PutUint16(dst[0:], mul(x1, z[0]))
	binary.BigEndian.PutUint16(dst[2:], x3+z[1])
	binary.BigEndian.PutUint16(dst[4:], x2+z[2])
	binary.BigEndian.PutUint16(dst[6:], mul(x4, z[3]))
}
