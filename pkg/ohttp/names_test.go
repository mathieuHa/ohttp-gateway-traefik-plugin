package ohttp

import (
	"testing"

	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/hpke"
)

func TestParseNames(t *testing.T) {
	kems := map[string]hpke.KEM{
		"":                           hpke.KEMX25519HKDFSHA256,
		"x25519":                     hpke.KEMX25519HKDFSHA256,
		"DHKEM(X25519, HKDF-SHA256)": hpke.KEMX25519HKDFSHA256,
		"P-256":                      hpke.KEMP256HKDFSHA256,
		"p_384":                      hpke.KEMP384HKDFSHA384,
		"0x0012":                     hpke.KEMP521HKDFSHA512,
	}
	for name, want := range kems {
		if got, err := ParseKEM(name); err != nil || got != want {
			t.Errorf("ParseKEM(%q) = %v, %v", name, got, err)
		}
	}
	suites := map[string]SymmetricSuite{
		"HKDF-SHA256/AES-128-GCM": {KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADAES128GCM},
		"hkdf_sha384/aes_256_gcm": {KDF: hpke.KDFHKDFSHA384, AEAD: hpke.AEADAES256GCM},
		"SHA512 / 0x0001":         {KDF: hpke.KDFHKDFSHA512, AEAD: hpke.AEADAES128GCM},
	}
	for name, want := range suites {
		if got, err := ParseSymmetricSuite(name); err != nil || got != want {
			t.Errorf("ParseSymmetricSuite(%q) = %v, %v", name, got, err)
		}
	}
	for _, name := range []string{"X448", "P-224"} {
		if _, err := ParseKEM(name); err == nil {
			t.Errorf("ParseKEM(%q): expected error", name)
		}
	}
	for _, name := range []string{"HKDF-SHA256", "SHA1/AES-128-GCM", "HKDF-SHA256/ChaCha20Poly1305"} {
		if _, err := ParseSymmetricSuite(name); err == nil {
			t.Errorf("ParseSymmetricSuite(%q): expected error", name)
		}
	}
	if len(DefaultSuites()) != 2 {
		t.Error("unexpected default suites")
	}
}
