package idea

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// The test vector from Lai's thesis and the original IDEA paper.
func TestVector(t *testing.T) {
	key, _ := hex.DecodeString("00010002000300040005000600070008")
	pt, _ := hex.DecodeString("0000000100020003")
	want, _ := hex.DecodeString("11fbed2b01986de5")
	c, err := NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 8)
	c.Encrypt(got, pt)
	if !bytes.Equal(got, want) {
		t.Fatalf("encrypt: %x, want %x", got, want)
	}
	c.Decrypt(got, got)
	if !bytes.Equal(got, pt) {
		t.Fatalf("decrypt: %x", got)
	}
}

func TestRoundTrip(t *testing.T) {
	for range 200 {
		key, pt := make([]byte, 16), make([]byte, 8)
		rand.Read(key)
		rand.Read(pt)
		c, _ := NewCipher(key)
		ct, back := make([]byte, 8), make([]byte, 8)
		c.Encrypt(ct, pt)
		c.Decrypt(back, ct)
		if !bytes.Equal(back, pt) {
			t.Fatalf("key %x: %x → %x → %x", key, pt, ct, back)
		}
	}
}

func TestInv(t *testing.T) {
	for x := 0; x < 65536; x += 7 {
		if got := mul(uint16(x), inv(uint16(x))); got != 1 {
			t.Fatalf("%d × inv = %d", x, got)
		}
	}
}
