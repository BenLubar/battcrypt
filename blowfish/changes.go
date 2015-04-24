package blowfish

// This package is identical to golang.org/x/crypto/blowfish, but with the
// following method added and the import path removed.

func (c *Cipher) Reset(key []byte) error {
	if k := len(key); k < 1 || k > 56 {
		return KeySizeError(k)
	}
	initCipher(c)
	ExpandKey(key, c)
	return nil
}
