// Package ohttp implements the Oblivious HTTP encapsulation (RFC 9458): key
// configurations, request decapsulation and response encapsulation for a
// gateway, plus the matching client operations.
package ohttp

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/hpke"
)

// Media types defined by RFC 9458.
const (
	RequestMediaType  = "message/ohttp-req"
	ResponseMediaType = "message/ohttp-res"
	KeysMediaType     = "application/ohttp-keys"
)

var errMalformedKeyConfig = errors.New("ohttp: malformed key configuration")

// SymmetricSuite is a KDF and AEAD pair advertised in a key configuration.
type SymmetricSuite struct {
	KDF  hpke.KDF
	AEAD hpke.AEAD
}

func (s SymmetricSuite) String() string {
	return s.KDF.String() + "/" + s.AEAD.String()
}

// KeyConfig is a public key configuration (RFC 9458, Section 3).
type KeyConfig struct {
	KeyID     uint8
	KEM       hpke.KEM
	PublicKey *ecdh.PublicKey
	Suites    []SymmetricSuite
}

// Marshal encodes a single key configuration.
func (c KeyConfig) Marshal() ([]byte, error) {
	if c.PublicKey == nil {
		return nil, errors.New("ohttp: key configuration without public key")
	}
	if len(c.Suites) == 0 || len(c.Suites) > 16383 {
		return nil, fmt.Errorf("ohttp: invalid number of symmetric suites: %d", len(c.Suites))
	}
	pk := c.PublicKey.Bytes()
	if len(pk) != c.KEM.Nenc() {
		return nil, fmt.Errorf("ohttp: public key does not match %s", c.KEM)
	}
	b := make([]byte, 0, 1+2+len(pk)+2+4*len(c.Suites))
	b = append(b, c.KeyID)
	b = binary.BigEndian.AppendUint16(b, uint16(c.KEM))
	b = append(b, pk...)
	b = binary.BigEndian.AppendUint16(b, uint16(4*len(c.Suites)))
	for _, s := range c.Suites {
		b = binary.BigEndian.AppendUint16(b, uint16(s.KDF))
		b = binary.BigEndian.AppendUint16(b, uint16(s.AEAD))
	}
	return b, nil
}

// ParseKeyConfig decodes a single key configuration from the start of data
// and returns the remaining bytes. The KEM must be supported, as its public
// key length is needed to parse the configuration.
func ParseKeyConfig(data []byte) (KeyConfig, []byte, error) {
	if len(data) < 3 {
		return KeyConfig{}, nil, errMalformedKeyConfig
	}
	c := KeyConfig{
		KeyID: data[0],
		KEM:   hpke.KEM(binary.BigEndian.Uint16(data[1:3])),
	}
	if !c.KEM.IsSupported() {
		return KeyConfig{}, nil, fmt.Errorf("ohttp: unsupported KEM %s", c.KEM)
	}
	data = data[3:]
	npk := c.KEM.Nenc()
	if len(data) < npk+2 {
		return KeyConfig{}, nil, errMalformedKeyConfig
	}
	pk, err := c.KEM.ParsePublicKey(data[:npk])
	if err != nil {
		return KeyConfig{}, nil, err
	}
	c.PublicKey = pk
	data = data[npk:]
	suitesLen := int(binary.BigEndian.Uint16(data))
	data = data[2:]
	if suitesLen < 4 || suitesLen%4 != 0 || len(data) < suitesLen {
		return KeyConfig{}, nil, errMalformedKeyConfig
	}
	for i := 0; i < suitesLen; i += 4 {
		c.Suites = append(c.Suites, SymmetricSuite{
			KDF:  hpke.KDF(binary.BigEndian.Uint16(data[i:])),
			AEAD: hpke.AEAD(binary.BigEndian.Uint16(data[i+2:])),
		})
	}
	return c, data[suitesLen:], nil
}

// MarshalKeyConfigs encodes key configurations using the
// "application/ohttp-keys" format, where each configuration is prefixed by its
// 2-byte length (RFC 9458, Section 3.2).
func MarshalKeyConfigs(configs []KeyConfig) ([]byte, error) {
	var out []byte
	for _, c := range configs {
		b, err := c.Marshal()
		if err != nil {
			return nil, err
		}
		if len(b) > 0xffff {
			return nil, fmt.Errorf("ohttp: key configuration %d is too large", c.KeyID)
		}
		out = binary.BigEndian.AppendUint16(out, uint16(len(b)))
		out = append(out, b...)
	}
	return out, nil
}

// ParseKeyConfigs decodes an "application/ohttp-keys" document. Key
// configurations using an unsupported KEM are skipped, as allowed by
// RFC 9458, Section 3.2.
func ParseKeyConfigs(data []byte) ([]KeyConfig, error) {
	var configs []KeyConfig
	for len(data) > 0 {
		if len(data) < 2 {
			return nil, errMalformedKeyConfig
		}
		n := int(binary.BigEndian.Uint16(data))
		data = data[2:]
		if len(data) < n {
			return nil, errMalformedKeyConfig
		}
		entry := data[:n]
		data = data[n:]
		if len(entry) >= 3 && !hpke.KEM(binary.BigEndian.Uint16(entry[1:3])).IsSupported() {
			continue
		}
		c, rest, err := ParseKeyConfig(entry)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errMalformedKeyConfig
		}
		configs = append(configs, c)
	}
	return configs, nil
}

// PrivateKeyConfig associates a gateway private key with its configuration.
type PrivateKeyConfig struct {
	Config     KeyConfig
	PrivateKey *ecdh.PrivateKey
}

// NewPrivateKeyConfig builds a key configuration for a private key.
func NewPrivateKeyConfig(keyID uint8, kem hpke.KEM, sk *ecdh.PrivateKey, suites []SymmetricSuite) (*PrivateKeyConfig, error) {
	if !kem.IsSupported() {
		return nil, fmt.Errorf("ohttp: unsupported KEM %s", kem)
	}
	if sk.Curve() != kem.Curve() {
		return nil, fmt.Errorf("ohttp: private key does not match %s", kem)
	}
	if len(suites) == 0 {
		return nil, errors.New("ohttp: at least one symmetric suite is required")
	}
	for _, s := range suites {
		if !s.KDF.IsSupported() || !s.AEAD.IsSupported() {
			return nil, fmt.Errorf("ohttp: unsupported symmetric suite %s", s)
		}
	}
	return &PrivateKeyConfig{
		Config: KeyConfig{
			KeyID:     keyID,
			KEM:       kem,
			PublicKey: sk.PublicKey(),
			Suites:    append([]SymmetricSuite{}, suites...),
		},
		PrivateKey: sk,
	}, nil
}
