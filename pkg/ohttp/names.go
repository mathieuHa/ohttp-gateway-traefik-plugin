package ohttp

import (
	"fmt"
	"strings"

	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/hpke"
)

// DefaultSuites returns the symmetric suites used when none are configured.
func DefaultSuites() []SymmetricSuite {
	return []SymmetricSuite{
		{KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADAES128GCM},
		{KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADAES256GCM},
	}
}

// ParseSymmetricSuite parses a "KDF/AEAD" pair such as
// "HKDF-SHA256/AES-128-GCM".
func ParseSymmetricSuite(name string) (SymmetricSuite, error) {
	kdfName, aeadName, ok := strings.Cut(name, "/")
	if !ok {
		return SymmetricSuite{}, fmt.Errorf("invalid suite %q: expected KDF/AEAD", name)
	}
	kdf, err := ParseKDF(kdfName)
	if err != nil {
		return SymmetricSuite{}, err
	}
	aead, err := ParseAEAD(aeadName)
	if err != nil {
		return SymmetricSuite{}, err
	}
	return SymmetricSuite{KDF: kdf, AEAD: aead}, nil
}

// normalizeAlgorithm uppercases a name and removes separators so that
// "HKDF-SHA256", "hkdf_sha256" and "HKDFSHA256" are equivalent.
func normalizeAlgorithm(name string) string {
	name = strings.ToUpper(strings.TrimSpace(name))
	return strings.NewReplacer("_", "", "-", "", " ", "").Replace(name)
}

// ParseKEM parses a KEM name such as "X25519", "P-256" or "0x0020". An empty
// name selects X25519.
func ParseKEM(name string) (hpke.KEM, error) {
	switch normalizeAlgorithm(name) {
	case "", "X25519", "X25519HKDFSHA256", "DHKEM(X25519,HKDFSHA256)", "0X0020", "32":
		return hpke.KEMX25519HKDFSHA256, nil
	case "P256", "P256HKDFSHA256", "DHKEM(P256,HKDFSHA256)", "0X0010", "16":
		return hpke.KEMP256HKDFSHA256, nil
	case "P384", "P384HKDFSHA384", "DHKEM(P384,HKDFSHA384)", "0X0011", "17":
		return hpke.KEMP384HKDFSHA384, nil
	case "P521", "P521HKDFSHA512", "DHKEM(P521,HKDFSHA512)", "0X0012", "18":
		return hpke.KEMP521HKDFSHA512, nil
	default:
		return 0, fmt.Errorf("unsupported KEM %q", name)
	}
}

// ParseKDF parses a KDF name such as "HKDF-SHA256".
func ParseKDF(name string) (hpke.KDF, error) {
	switch normalizeAlgorithm(name) {
	case "HKDFSHA256", "SHA256", "0X0001", "1":
		return hpke.KDFHKDFSHA256, nil
	case "HKDFSHA384", "SHA384", "0X0002", "2":
		return hpke.KDFHKDFSHA384, nil
	case "HKDFSHA512", "SHA512", "0X0003", "3":
		return hpke.KDFHKDFSHA512, nil
	default:
		return 0, fmt.Errorf("unsupported KDF %q", name)
	}
}

// ParseAEAD parses an AEAD name such as "AES-128-GCM".
func ParseAEAD(name string) (hpke.AEAD, error) {
	switch normalizeAlgorithm(name) {
	case "AES128GCM", "0X0001", "1":
		return hpke.AEADAES128GCM, nil
	case "AES256GCM", "0X0002", "2":
		return hpke.AEADAES256GCM, nil
	default:
		return 0, fmt.Errorf("unsupported AEAD %q", name)
	}
}
