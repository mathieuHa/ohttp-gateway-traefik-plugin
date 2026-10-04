package ohttp

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/hpke"
)

// Values from the complete example of RFC 9458, Appendix A.
const (
	rfcSecretKey      = "3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a"
	rfcKeyConfig      = "01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003"
	rfcRequest        = "00034745540568747470730b6578616d706c652e636f6d012f"
	rfcEncRequest     = "010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b4726374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525"
	rfcResponse       = "0140c8"
	rfcResponseNonce  = "c789e7151fcba46158ca84b04464910d"
	rfcEncResponse    = "c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd"
	rfcEphemeralKey   = "bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73"
	rfcRequestInfoHex = "6d6573736167652f626874747020726571756573740001002000010001"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func rfcGateway(t *testing.T) (*Gateway, *PrivateKeyConfig) {
	t.Helper()
	sk, err := hpke.KEMX25519HKDFSHA256.ParsePrivateKey(mustHex(t, rfcSecretKey))
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewPrivateKeyConfig(1, hpke.KEMX25519HKDFSHA256, sk, []SymmetricSuite{
		{KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADAES128GCM},
	})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := NewGateway([]*PrivateKeyConfig{key})
	if err != nil {
		t.Fatal(err)
	}
	return gw, key
}

func TestRFC9458KeyConfig(t *testing.T) {
	_, key := rfcGateway(t)
	// The RFC example also advertises ChaCha20Poly1305, which is not
	// implemented: it is rejected for gateway keys but can still be encoded.
	if _, err := NewPrivateKeyConfig(1, hpke.KEMX25519HKDFSHA256, key.PrivateKey, []SymmetricSuite{
		{KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADChaCha20Poly1305},
	}); err == nil {
		t.Fatal("expected ChaCha20Poly1305 to be rejected")
	}
	cfg := key.Config
	cfg.Suites = append(cfg.Suites, SymmetricSuite{KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADChaCha20Poly1305})
	encoded, err := cfg.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(encoded); got != rfcKeyConfig {
		t.Fatalf("key config = %s, want %s", got, rfcKeyConfig)
	}
	parsed, rest, err := ParseKeyConfig(mustHex(t, rfcKeyConfig))
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 || parsed.KeyID != 1 || parsed.KEM != hpke.KEMX25519HKDFSHA256 || len(parsed.Suites) != 2 {
		t.Fatalf("parsed = %+v", parsed)
	}
	if !parsed.PublicKey.Equal(key.PrivateKey.PublicKey()) {
		t.Fatal("public key mismatch")
	}
}

func TestRFC9458RequestInfo(t *testing.T) {
	hdr := parseHeader(mustHex(t, rfcEncRequest))
	if got := hex.EncodeToString(hdr.info()); got != rfcRequestInfoHex {
		t.Fatalf("info = %s", got)
	}
}

func TestRFC9458Decapsulation(t *testing.T) {
	gw, _ := rfcGateway(t)
	req, respCtx, err := gw.DecapsulateRequest(mustHex(t, rfcEncRequest))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(req); got != rfcRequest {
		t.Fatalf("request = %s, want %s", got, rfcRequest)
	}
	encResp, err := respCtx.encapsulateResponseWithNonce(mustHex(t, rfcResponseNonce), mustHex(t, rfcResponse))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(encResp); got != rfcEncResponse {
		t.Fatalf("encapsulated response = %s, want %s", got, rfcEncResponse)
	}
	// The nonce read from rand is used verbatim.
	encResp, err = respCtx.EncapsulateResponse(bytes.NewReader(mustHex(t, rfcResponseNonce)), mustHex(t, rfcResponse))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(encResp); got != rfcEncResponse {
		t.Fatalf("encapsulated response = %s, want %s", got, rfcEncResponse)
	}
}

// TestRFC9458ClientEncapsulation reproduces the client side of the example
// using the ephemeral key published in the RFC.
func TestRFC9458ClientEncapsulation(t *testing.T) {
	cfg, _, err := ParseKeyConfig(mustHex(t, rfcKeyConfig))
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	skE, err := hpke.KEMX25519HKDFSHA256.ParsePrivateKey(mustHex(t, rfcEphemeralKey))
	if err != nil {
		t.Fatal(err)
	}
	encReq, clientCtx, err := client.encapsulateRequestWithEphemeral(skE, mustHex(t, rfcRequest))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(encReq); got != rfcEncRequest {
		t.Fatalf("encapsulated request = %s, want %s", got, rfcEncRequest)
	}
	resp, err := clientCtx.DecapsulateResponse(mustHex(t, rfcEncResponse))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(resp); got != rfcResponse {
		t.Fatalf("response = %s", got)
	}
}

func TestRoundTrip(t *testing.T) {
	kems := []hpke.KEM{hpke.KEMX25519HKDFSHA256, hpke.KEMP256HKDFSHA256, hpke.KEMP384HKDFSHA384, hpke.KEMP521HKDFSHA512}
	suites := []SymmetricSuite{
		{KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADAES128GCM},
		{KDF: hpke.KDFHKDFSHA384, AEAD: hpke.AEADAES256GCM},
		{KDF: hpke.KDFHKDFSHA512, AEAD: hpke.AEADAES128GCM},
	}
	var keys []*PrivateKeyConfig
	for i, kem := range kems {
		sk, err := kem.GenerateKeyPair(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		key, err := NewPrivateKeyConfig(uint8(i), kem, sk, suites)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
	}
	gw, err := NewGateway(keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range keys {
		for _, suite := range suites {
			t.Run(key.Config.KEM.String()+"/"+suite.String(), func(t *testing.T) {
				client, err := NewClientWithSuite(key.Config, suite)
				if err != nil {
					t.Fatal(err)
				}
				msg := []byte("request " + suite.String())
				encReq, clientCtx, err := client.EncapsulateRequest(rand.Reader, msg)
				if err != nil {
					t.Fatal(err)
				}
				got, respCtx, err := gw.DecapsulateRequest(encReq)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, msg) {
					t.Fatalf("request = %q", got)
				}
				encResp, err := respCtx.EncapsulateResponse(rand.Reader, []byte("response"))
				if err != nil {
					t.Fatal(err)
				}
				resp, err := clientCtx.DecapsulateResponse(encResp)
				if err != nil {
					t.Fatal(err)
				}
				if string(resp) != "response" {
					t.Fatalf("response = %q", resp)
				}
			})
		}
	}
}

func TestDecapsulationErrors(t *testing.T) {
	gw, key := rfcGateway(t)
	valid := mustHex(t, rfcEncRequest)

	unknownKey := append([]byte{}, valid...)
	unknownKey[0] = 7
	wrongKEM := append([]byte{}, valid...)
	wrongKEM[2] = 0x10
	wrongAEAD := append([]byte{}, valid...)
	wrongAEAD[6] = 0x02
	tampered := append([]byte{}, valid...)
	tampered[len(tampered)-1] ^= 0xff

	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"empty", nil, ErrMalformedRequest},
		{"short header", valid[:5], ErrMalformedRequest},
		{"short enc", valid[:20], ErrMalformedRequest},
		{"unknown key", unknownKey, ErrUnknownKey},
		{"wrong kem", wrongKEM, ErrUnsupportedSuite},
		{"unadvertised aead", wrongAEAD, ErrUnsupportedSuite},
		{"tampered", tampered, ErrDecryptionFailed},
	}
	for _, c := range cases {
		if _, _, err := gw.DecapsulateRequest(c.data); !errors.Is(err, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
	}

	// A response cannot be decrypted with another request's context.
	client, err := NewClient(key.Config)
	if err != nil {
		t.Fatal(err)
	}
	encReq, _, err := client.EncapsulateRequest(rand.Reader, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	_, otherCtx, err := client.EncapsulateRequest(rand.Reader, []byte("b"))
	if err != nil {
		t.Fatal(err)
	}
	_, respCtx, err := gw.DecapsulateRequest(encReq)
	if err != nil {
		t.Fatal(err)
	}
	encResp, err := respCtx.EncapsulateResponse(rand.Reader, []byte("resp"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := otherCtx.DecapsulateResponse(encResp); err == nil {
		t.Fatal("expected response decryption with another context to fail")
	}
	if _, err := otherCtx.DecapsulateResponse(encResp[:4]); !errors.Is(err, ErrMalformedResponse) {
		t.Fatalf("got %v", err)
	}
}

func TestKeyConfigs(t *testing.T) {
	_, key := rfcGateway(t)
	sk, err := hpke.KEMP256HKDFSHA256.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := NewPrivateKeyConfig(2, hpke.KEMP256HKDFSHA256, sk, []SymmetricSuite{{KDF: hpke.KDFHKDFSHA256, AEAD: hpke.AEADAES256GCM}})
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalKeyConfigs([]KeyConfig{key.Config, p256.Config})
	if err != nil {
		t.Fatal(err)
	}
	// An entry using an unknown KEM (X448) is skipped by clients.
	data = append(data, 0x00, 0x03, 0x09, 0x00, 0x21)
	configs, err := ParseKeyConfigs(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(configs) != 2 || configs[0].KeyID != 1 || configs[1].KeyID != 2 || configs[1].KEM != hpke.KEMP256HKDFSHA256 {
		t.Fatalf("configs = %+v", configs)
	}

	// Malformed documents.
	for i, m := range [][]byte{{0x00}, {0x00, 0x05, 0x01}} {
		if _, err := ParseKeyConfigs(m); err == nil {
			t.Errorf("document %d: expected error", i)
		}
	}
	// Malformed key configurations, wrapped in a valid length prefix.
	for i, m := range [][]byte{
		mustHex(t, "0100"),
		mustHex(t, "010020"),
		mustHex(t, rfcKeyConfig)[:36],
		mustHex(t, strings.Replace(rfcKeyConfig, "00080001", "00030001", 1)),
		append(mustHex(t, rfcKeyConfig), 0x00),
	} {
		if _, err := ParseKeyConfigs(append([]byte{0x00, byte(len(m))}, m...)); err == nil {
			t.Errorf("config %d: expected error", i)
		}
	}

	if _, err := NewGateway(nil); err == nil {
		t.Error("expected empty gateway to fail")
	}
	if _, err := NewGateway([]*PrivateKeyConfig{key, key}); err == nil {
		t.Error("expected duplicate key IDs to fail")
	}
	if _, err := NewPrivateKeyConfig(3, hpke.KEMX25519HKDFSHA256, sk, key.Config.Suites); err == nil {
		t.Error("expected curve mismatch to fail")
	}
	if _, err := NewPrivateKeyConfig(3, hpke.KEMP256HKDFSHA256, sk, nil); err == nil {
		t.Error("expected empty suites to fail")
	}
}
