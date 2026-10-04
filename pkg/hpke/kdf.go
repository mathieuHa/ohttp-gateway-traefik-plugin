package hpke

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// KDF is an HPKE key derivation function identifier (RFC 9180, Section 7.2).
type KDF uint16

// Supported KDF identifiers.
const (
	KDFHKDFSHA256 KDF = 0x0001
	KDFHKDFSHA384 KDF = 0x0002
	KDFHKDFSHA512 KDF = 0x0003
)

const versionLabel = "HPKE-v1"

var errExpandTooLong = errors.New("hpke: requested expand length too large")

// IsSupported reports whether the KDF is implemented by this package.
func (k KDF) IsSupported() bool {
	switch k {
	case KDFHKDFSHA256, KDFHKDFSHA384, KDFHKDFSHA512:
		return true
	default:
		return false
	}
}

func (k KDF) String() string {
	switch k {
	case KDFHKDFSHA256:
		return "HKDF-SHA256"
	case KDFHKDFSHA384:
		return "HKDF-SHA384"
	case KDFHKDFSHA512:
		return "HKDF-SHA512"
	default:
		return fmt.Sprintf("KDF(0x%04x)", uint16(k))
	}
}

func (k KDF) newHash() func() hash.Hash {
	switch k {
	case KDFHKDFSHA384:
		return sha512.New384
	case KDFHKDFSHA512:
		return sha512.New
	default:
		return sha256.New
	}
}

// Nh returns the output size of the KDF's Extract function in bytes.
func (k KDF) Nh() int {
	switch k {
	case KDFHKDFSHA384:
		return 48
	case KDFHKDFSHA512:
		return 64
	default:
		return 32
	}
}

// Extract implements HKDF-Extract (RFC 5869).
func (k KDF) Extract(salt, ikm []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, k.Nh())
	}
	mac := hmac.New(k.newHash(), salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// Expand implements HKDF-Expand (RFC 5869).
func (k KDF) Expand(prk, info []byte, length int) ([]byte, error) {
	nh := k.Nh()
	if length < 0 || length > 255*nh {
		return nil, errExpandTooLong
	}
	out := make([]byte, 0, length+nh)
	var prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(k.newHash(), prk)
		mac.Write(prev)
		mac.Write(info)
		mac.Write([]byte{counter})
		prev = mac.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length], nil
}

// labeledExtract implements LabeledExtract (RFC 9180, Section 4).
func (k KDF) labeledExtract(suiteID, salt []byte, label string, ikm []byte) []byte {
	labeledIKM := make([]byte, 0, len(versionLabel)+len(suiteID)+len(label)+len(ikm))
	labeledIKM = append(labeledIKM, versionLabel...)
	labeledIKM = append(labeledIKM, suiteID...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)
	return k.Extract(salt, labeledIKM)
}

// labeledExpand implements LabeledExpand (RFC 9180, Section 4).
func (k KDF) labeledExpand(suiteID, prk []byte, label string, info []byte, length int) ([]byte, error) {
	if length > 0xffff {
		return nil, errExpandTooLong
	}
	labeledInfo := make([]byte, 2, 2+len(versionLabel)+len(suiteID)+len(label)+len(info))
	binary.BigEndian.PutUint16(labeledInfo, uint16(length))
	labeledInfo = append(labeledInfo, versionLabel...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	return k.Expand(prk, labeledInfo, length)
}
