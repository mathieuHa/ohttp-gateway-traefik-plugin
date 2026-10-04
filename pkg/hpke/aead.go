package hpke

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// AEAD is an HPKE authenticated encryption identifier (RFC 9180, Section 7.3).
type AEAD uint16

// AEAD identifiers. Only the AES-GCM variants are implemented: ChaCha20-Poly1305
// is not part of the Go standard library and therefore not available to plugins
// interpreted by Yaegi.
const (
	AEADAES128GCM        AEAD = 0x0001
	AEADAES256GCM        AEAD = 0x0002
	AEADChaCha20Poly1305 AEAD = 0x0003
	AEADExportOnly       AEAD = 0xffff
)

// IsSupported reports whether the AEAD is implemented by this package.
func (a AEAD) IsSupported() bool {
	return a == AEADAES128GCM || a == AEADAES256GCM
}

func (a AEAD) String() string {
	switch a {
	case AEADAES128GCM:
		return "AES-128-GCM"
	case AEADAES256GCM:
		return "AES-256-GCM"
	case AEADChaCha20Poly1305:
		return "ChaCha20Poly1305"
	case AEADExportOnly:
		return "Export-only"
	default:
		return fmt.Sprintf("AEAD(0x%04x)", uint16(a))
	}
}

// Nk returns the key size in bytes.
func (a AEAD) Nk() int {
	if a == AEADAES128GCM {
		return 16
	}
	return 32
}

// Nn returns the nonce size in bytes.
func (a AEAD) Nn() int {
	return 12
}

// New returns a cipher.AEAD keyed with key.
func (a AEAD) New(key []byte) (cipher.AEAD, error) {
	if !a.IsSupported() {
		return nil, fmt.Errorf("hpke: unsupported AEAD %s", a)
	}
	if len(key) != a.Nk() {
		return nil, fmt.Errorf("hpke: invalid key length %d for %s", len(key), a)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
