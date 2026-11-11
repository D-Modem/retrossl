package rc2

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestOpenSSL: a 128-bit key with 128 effective bits, as SSL uses RC2,
// against OpenSSL 3's legacy rc2-ecb.
func TestOpenSSL(t *testing.T) {
	key, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	want, _ := hex.DecodeString("f215c5a22e43f5c6")
	c, _ := New(key, 128)
	got := make([]byte, 8)
	c.Encrypt(got, []byte("ABCDEFGH"))
	if !bytes.Equal(got, want) {
		t.Fatalf("%x, want %x", got, want)
	}
}
