package retrossl

import (
	"crypto/cipher"
	"crypto/rc4"
)

func rc4NewCipher(k []byte) (cipher.Stream, error)            { return rc4.NewCipher(k) }
func cbcDecrypter(b cipher.Block, iv []byte) cipher.BlockMode { return cipher.NewCBCDecrypter(b, iv) }
func cbcEncrypter(b cipher.Block, iv []byte) cipher.BlockMode { return cipher.NewCBCEncrypter(b, iv) }
