package retrossl

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"errors"
	"io"
)

// DEFLATE compression (RFC 3749, method 1), as OpenSSL does it: one zlib
// stream per direction for the connection's state, flushed at the end of
// every record.

const (
	compNull    = 0
	compDeflate = 1
)

type compressor struct {
	buf bytes.Buffer
	w   *zlib.Writer
}

func newCompressor() *compressor {
	c := &compressor{}
	c.w = zlib.NewWriter(&c.buf)
	return c
}

func (c *compressor) compress(p []byte) []byte {
	c.buf.Reset()
	c.w.Write(p)
	c.w.Flush()
	return bytes.Clone(c.buf.Bytes())
}

// decompressor reads one record at a time.  Each record ends at a flush,
// on a block boundary, so the next starts afresh with the last 32 KB of
// output as its dictionary.
type decompressor struct {
	started bool
	window  []byte
}

var errDecompress = errors.New("retrossl: bad compressed record")

func (d *decompressor) decompress(p []byte, limit int) ([]byte, error) {
	if !d.started {
		if len(p) < 2 || p[0]&0x0f != 8 || (uint(p[0])<<8|uint(p[1]))%31 != 0 || p[1]&0x20 != 0 {
			return nil, errDecompress
		}
		p, d.started = p[2:], true
	}
	r := flate.NewReaderDict(bytes.NewReader(p), d.window)
	out, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, errDecompress
	}
	if len(out) > limit {
		return nil, errDecompress
	}
	d.window = append(d.window, out...)
	if n := len(d.window) - 32768; n > 0 {
		d.window = append([]byte(nil), d.window[n:]...)
	}
	return out, nil
}
