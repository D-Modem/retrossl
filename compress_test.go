package retrossl

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// TestZlibRecords: two records compressed by zlib itself (Python's, with
// a sync flush after each, as OpenSSL does); the second refers back into
// the first.
func TestZlibRecords(t *testing.T) {
	recs := []string{
		"789c72770d51d057f0080909d037d433e0e5f2c82f2eb15248ad48cc2dc849d54bcecfe5e5e2e502000000ffff",
		"7207292a29cfa7b73a00000000ffff",
	}
	want := []string{"GET / HTTP/1.0\r\nHost: example.com\r\n\r\n",
		strings.Repeat("GET /two HTTP/1.0\r\nHost: example.com\r\n\r\n", 3)}
	d := &decompressor{}
	for i, r := range recs {
		b, _ := hex.DecodeString(r)
		got, err := d.decompress(b, maxPlain)
		if err != nil || string(got) != want[i] {
			t.Fatalf("record %d: %q, %v", i, got, err)
		}
	}
}

// TestCompressRoundTrip: what the compressor makes, the decompressor
// takes back, record by record.
func TestCompressRoundTrip(t *testing.T) {
	c, d := newCompressor(), &decompressor{}
	for i := range 50 {
		p := bytes.Repeat([]byte{byte('a' + i%26)}, 100+i*37)
		got, err := d.decompress(c.compress(p), maxPlain)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	if _, err := (&decompressor{}).decompress([]byte{0x12, 0x34}, maxPlain); err == nil {
		t.Error("a bad zlib header passed")
	}
}
