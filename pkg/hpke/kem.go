package hpke

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// KEM is an HPKE key encapsulation mechanism identifier (RFC 9180, Section 7.1).
type KEM uint16

// Supported DHKEM identifiers.
const (
	KEMP256HKDFSHA256   KEM = 0x0010
	KEMP384HKDFSHA384   KEM = 0x0011
	KEMP521HKDFSHA512   KEM = 0x0012
	KEMX25519HKDFSHA256 KEM = 0x0020
)

var errDeriveKeyPair = errors.New("hpke: DeriveKeyPair failed")

// IsSupported reports whether the KEM is implemented by this package.
func (k KEM) IsSupported() bool {
	switch k {
	case KEMP256HKDFSHA256, KEMP384HKDFSHA384, KEMP521HKDFSHA512, KEMX25519HKDFSHA256:
		return true
	default:
		return false
	}
}

func (k KEM) String() string {
	switch k {
	case KEMP256HKDFSHA256:
		return "DHKEM(P-256, HKDF-SHA256)"
	case KEMP384HKDFSHA384:
		return "DHKEM(P-384, HKDF-SHA384)"
	case KEMP521HKDFSHA512:
		return "DHKEM(P-521, HKDF-SHA512)"
	case KEMX25519HKDFSHA256:
		return "DHKEM(X25519, HKDF-SHA256)"
	default:
		return fmt.Sprintf("KEM(0x%04x)", uint16(k))
	}
}

// Curve returns the ecdh curve backing the KEM.
func (k KEM) Curve() ecdh.Curve {
	switch k {
	case KEMP256HKDFSHA256:
		return ecdh.P256()
	case KEMP384HKDFSHA384:
		return ecdh.P384()
	case KEMP521HKDFSHA512:
		return ecdh.P521()
	case KEMX25519HKDFSHA256:
		return ecdh.X25519()
	default:
		return nil
	}
}

func (k KEM) kdf() KDF {
	switch k {
	case KEMP384HKDFSHA384:
		return KDFHKDFSHA384
	case KEMP521HKDFSHA512:
		return KDFHKDFSHA512
	default:
		return KDFHKDFSHA256
	}
}

// Nsecret returns the length in bytes of a KEM shared secret.
func (k KEM) Nsecret() int {
	return k.kdf().Nh()
}

// Nenc returns the length in bytes of an encapsulated key (also Npk).
func (k KEM) Nenc() int {
	switch k {
	case KEMP256HKDFSHA256:
		return 65
	case KEMP384HKDFSHA384:
		return 97
	case KEMP521HKDFSHA512:
		return 133
	default:
		return 32
	}
}

// Nsk returns the length in bytes of a serialized private key.
func (k KEM) Nsk() int {
	switch k {
	case KEMP384HKDFSHA384:
		return 48
	case KEMP521HKDFSHA512:
		return 66
	default:
		return 32
	}
}

func (k KEM) suiteID() []byte {
	id := []byte("KEM\x00\x00")
	binary.BigEndian.PutUint16(id[3:], uint16(k))
	return id
}

// GenerateKeyPair generates a new random private key.
func (k KEM) GenerateKeyPair(rand io.Reader) (*ecdh.PrivateKey, error) {
	if !k.IsSupported() {
		return nil, fmt.Errorf("hpke: unsupported KEM %s", k)
	}
	return k.Curve().GenerateKey(rand)
}

// DeriveKeyPair deterministically derives a private key from the input keying
// material ikm (RFC 9180, Section 7.1.3). ikm should have at least Nsk bytes of
// entropy.
func (k KEM) DeriveKeyPair(ikm []byte) (*ecdh.PrivateKey, error) {
	if !k.IsSupported() {
		return nil, fmt.Errorf("hpke: unsupported KEM %s", k)
	}
	sid := k.suiteID()
	kdf := k.kdf()
	prk := kdf.labeledExtract(sid, nil, "dkp_prk", ikm)
	if k == KEMX25519HKDFSHA256 {
		sk, err := kdf.labeledExpand(sid, prk, "sk", nil, k.Nsk())
		if err != nil {
			return nil, err
		}
		return k.Curve().NewPrivateKey(sk)
	}
	bitmask := byte(0xff)
	if k == KEMP521HKDFSHA512 {
		bitmask = 0x01
	}
	for counter := 0; counter < 256; counter++ {
		candidate, err := kdf.labeledExpand(sid, prk, "candidate", []byte{byte(counter)}, k.Nsk())
		if err != nil {
			return nil, err
		}
		candidate[0] &= bitmask
		// NewPrivateKey rejects zero and out-of-range scalars, which is exactly
		// the rejection-sampling condition of the specification.
		if sk, err := k.Curve().NewPrivateKey(candidate); err == nil {
			return sk, nil
		}
	}
	return nil, errDeriveKeyPair
}

// ParsePrivateKey deserializes a private key (DeserializePrivateKey).
func (k KEM) ParsePrivateKey(b []byte) (*ecdh.PrivateKey, error) {
	if !k.IsSupported() {
		return nil, fmt.Errorf("hpke: unsupported KEM %s", k)
	}
	if len(b) != k.Nsk() {
		return nil, fmt.Errorf("hpke: invalid private key length %d for %s (want %d)", len(b), k, k.Nsk())
	}
	return k.Curve().NewPrivateKey(b)
}

// ParsePublicKey deserializes a public key (DeserializePublicKey).
func (k KEM) ParsePublicKey(b []byte) (*ecdh.PublicKey, error) {
	if !k.IsSupported() {
		return nil, fmt.Errorf("hpke: unsupported KEM %s", k)
	}
	if len(b) != k.Nenc() {
		return nil, fmt.Errorf("hpke: invalid public key length %d for %s (want %d)", len(b), k, k.Nenc())
	}
	return k.Curve().NewPublicKey(b)
}

// Encap generates an ephemeral key pair and returns the shared secret along
// with the encapsulated key to send to the receiver.
func (k KEM) Encap(rand io.Reader, pkR *ecdh.PublicKey) (sharedSecret, enc []byte, err error) {
	skE, err := k.GenerateKeyPair(rand)
	if err != nil {
		return nil, nil, err
	}
	return k.encapWithEphemeral(skE, pkR)
}

func (k KEM) encapWithEphemeral(skE *ecdh.PrivateKey, pkR *ecdh.PublicKey) (sharedSecret, enc []byte, err error) {
	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, nil, err
	}
	enc = skE.PublicKey().Bytes()
	kemContext := append(append([]byte{}, enc...), pkR.Bytes()...)
	sharedSecret, err = k.extractAndExpand(dh, kemContext)
	if err != nil {
		return nil, nil, err
	}
	return sharedSecret, enc, nil
}

// Decap recovers the shared secret from an encapsulated key.
func (k KEM) Decap(enc []byte, skR *ecdh.PrivateKey) ([]byte, error) {
	pkE, err := k.ParsePublicKey(enc)
	if err != nil {
		return nil, err
	}
	// ECDH fails on low-order X25519 points (all-zero output), as required by
	// RFC 9180, Section 7.1.4.
	dh, err := skR.ECDH(pkE)
	if err != nil {
		return nil, err
	}
	kemContext := append(append([]byte{}, enc...), skR.PublicKey().Bytes()...)
	return k.extractAndExpand(dh, kemContext)
}

func (k KEM) extractAndExpand(dh, kemContext []byte) ([]byte, error) {
	sid := k.suiteID()
	kdf := k.kdf()
	prk := kdf.labeledExtract(sid, nil, "eae_prk", dh)
	return kdf.labeledExpand(sid, prk, "shared_secret", kemContext, k.Nsecret())
}
