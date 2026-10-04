package hpke

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type vectorEncryption struct {
	AAD   string `json:"aad"`
	CT    string `json:"ct"`
	Nonce string `json:"nonce"`
	PT    string `json:"pt"`
}

type vectorExport struct {
	ExporterContext string `json:"exporter_context"`
	L               int    `json:"L"`
	ExportedValue   string `json:"exported_value"`
}

type vector struct {
	KEMID          uint16             `json:"kem_id"`
	KDFID          uint16             `json:"kdf_id"`
	AEADID         uint16             `json:"aead_id"`
	Info           string             `json:"info"`
	IkmR           string             `json:"ikmR"`
	IkmE           string             `json:"ikmE"`
	SkRm           string             `json:"skRm"`
	SkEm           string             `json:"skEm"`
	PkRm           string             `json:"pkRm"`
	PkEm           string             `json:"pkEm"`
	Enc            string             `json:"enc"`
	SharedSecret   string             `json:"shared_secret"`
	Key            string             `json:"key"`
	BaseNonce      string             `json:"base_nonce"`
	ExporterSecret string             `json:"exporter_secret"`
	Encryptions    []vectorEncryption `json:"encryptions"`
	Exports        []vectorExport     `json:"exports"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex %q: %v", s, err)
	}
	return b
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	data, err := os.ReadFile("testdata/base-mode-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("no test vectors loaded")
	}
	return vectors
}

// TestRFC9180Vectors checks the implementation against the base mode test
// vectors published with RFC 9180 (Appendix A).
func TestRFC9180Vectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		suite := Suite{KEM: KEM(v.KEMID), KDF: KDF(v.KDFID), AEAD: AEAD(v.AEADID)}
		name := fmt.Sprintf("%s/%s/%s", suite.KEM, suite.KDF, suite.AEAD)
		t.Run(name, func(t *testing.T) {
			checkVector(t, suite, v)
		})
	}
}

func checkVector(t *testing.T, suite Suite, v vector) {
	t.Helper()
	if err := suite.Validate(); err != nil {
		t.Fatal(err)
	}

	skR, err := suite.KEM.DeriveKeyPair(mustHex(t, v.IkmR))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(skR.Bytes()); got != v.SkRm {
		t.Fatalf("skRm = %s, want %s", got, v.SkRm)
	}
	if got := hex.EncodeToString(skR.PublicKey().Bytes()); got != v.PkRm {
		t.Fatalf("pkRm = %s, want %s", got, v.PkRm)
	}
	skE, err := suite.KEM.DeriveKeyPair(mustHex(t, v.IkmE))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(skE.Bytes()); got != v.SkEm {
		t.Fatalf("skEm = %s, want %s", got, v.SkEm)
	}

	parsedSkR, err := suite.KEM.ParsePrivateKey(mustHex(t, v.SkRm))
	if err != nil {
		t.Fatal(err)
	}
	pkR, err := suite.KEM.ParsePublicKey(mustHex(t, v.PkRm))
	if err != nil {
		t.Fatal(err)
	}

	info := mustHex(t, v.Info)
	enc, sender, err := suite.SetupBaseSWithEphemeral(skE, pkR, info)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(enc); got != v.Enc {
		t.Fatalf("enc = %s, want %s", got, v.Enc)
	}
	if got := hex.EncodeToString(sender.baseNonce); got != v.BaseNonce {
		t.Fatalf("base_nonce = %s, want %s", got, v.BaseNonce)
	}
	if got := hex.EncodeToString(sender.exporterSecret); got != v.ExporterSecret {
		t.Fatalf("exporter_secret = %s, want %s", got, v.ExporterSecret)
	}

	receiver, err := suite.SetupBaseR(parsedSkR, enc, info)
	if err != nil {
		t.Fatal(err)
	}

	for i, e := range v.Encryptions {
		ct, err := sender.Seal(mustHex(t, e.AAD), mustHex(t, e.PT))
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(ct); got != e.CT {
			t.Fatalf("encryption %d: ct = %s, want %s", i, got, e.CT)
		}
		pt, err := receiver.Open(mustHex(t, e.AAD), ct)
		if err != nil {
			t.Fatalf("encryption %d: open: %v", i, err)
		}
		if got := hex.EncodeToString(pt); got != e.PT {
			t.Fatalf("encryption %d: pt = %s, want %s", i, got, e.PT)
		}
	}

	for i, e := range v.Exports {
		for _, ctx := range []*Context{&sender.Context, &receiver.Context} {
			out, err := ctx.Export(mustHex(t, e.ExporterContext), e.L)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(out); got != e.ExportedValue {
				t.Fatalf("export %d = %s, want %s", i, got, e.ExportedValue)
			}
		}
	}
}

func TestRoundTripAllSuites(t *testing.T) {
	kems := []KEM{KEMX25519HKDFSHA256, KEMP256HKDFSHA256, KEMP384HKDFSHA384, KEMP521HKDFSHA512}
	kdfs := []KDF{KDFHKDFSHA256, KDFHKDFSHA384, KDFHKDFSHA512}
	aeads := []AEAD{AEADAES128GCM, AEADAES256GCM}
	for _, kem := range kems {
		for _, kdf := range kdfs {
			for _, aead := range aeads {
				suite := Suite{KEM: kem, KDF: kdf, AEAD: aead}
				t.Run(fmt.Sprintf("%s/%s/%s", kem, kdf, aead), func(t *testing.T) {
					skR, err := kem.GenerateKeyPair(rand.Reader)
					if err != nil {
						t.Fatal(err)
					}
					enc, sender, err := suite.SetupBaseS(rand.Reader, skR.PublicKey(), []byte("info"))
					if err != nil {
						t.Fatal(err)
					}
					receiver, err := suite.SetupBaseR(skR, enc, []byte("info"))
					if err != nil {
						t.Fatal(err)
					}
					for i := 0; i < 3; i++ {
						msg := []byte(fmt.Sprintf("message %d", i))
						ct, err := sender.Seal([]byte("aad"), msg)
						if err != nil {
							t.Fatal(err)
						}
						pt, err := receiver.Open([]byte("aad"), ct)
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(pt, msg) {
							t.Fatalf("got %q, want %q", pt, msg)
						}
					}
				})
			}
		}
	}
}

func TestOpenFailures(t *testing.T) {
	suite := Suite{KEM: KEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADAES128GCM}
	skR, err := suite.KEM.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc, sender, err := suite.SetupBaseS(rand.Reader, skR.PublicKey(), []byte("info"))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := sender.Seal(nil, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	// Wrong info: the derived keys differ.
	receiver, err := suite.SetupBaseR(skR, enc, []byte("other"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Open(nil, ct); err == nil {
		t.Fatal("expected open with wrong info to fail")
	}

	// Tampered ciphertext.
	receiver, err = suite.SetupBaseR(skR, enc, []byte("info"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte{}, ct...)
	tampered[0] ^= 0x01
	if _, err := receiver.Open(nil, tampered); err == nil {
		t.Fatal("expected open of tampered ciphertext to fail")
	}
	// A failed open must not advance the sequence number.
	if _, err := receiver.Open(nil, ct); err != nil {
		t.Fatalf("open after failure: %v", err)
	}

	// Low order point (all zeros) must be rejected for X25519.
	if _, err := suite.SetupBaseR(skR, make([]byte, 32), []byte("info")); err == nil {
		t.Fatal("expected low-order public key to be rejected")
	}
	// Invalid encapsulated key length.
	if _, err := suite.SetupBaseR(skR, enc[:31], []byte("info")); err == nil {
		t.Fatal("expected short enc to be rejected")
	}
}

func TestUnsupportedAlgorithms(t *testing.T) {
	cases := []Suite{
		{KEM: 0x0021, KDF: KDFHKDFSHA256, AEAD: AEADAES128GCM},
		{KEM: KEMX25519HKDFSHA256, KDF: 0x0042, AEAD: AEADAES128GCM},
		{KEM: KEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADChaCha20Poly1305},
		{KEM: KEMX25519HKDFSHA256, KDF: KDFHKDFSHA256, AEAD: AEADExportOnly},
	}
	for _, s := range cases {
		if err := s.Validate(); err == nil {
			t.Errorf("expected %v to be rejected", s)
		}
	}
	if _, err := KEM(0x0021).GenerateKeyPair(rand.Reader); err == nil {
		t.Error("expected X448 key generation to fail")
	}
}

func TestExpandLimits(t *testing.T) {
	if _, err := KDFHKDFSHA256.Expand(make([]byte, 32), nil, 255*32+1); err == nil {
		t.Fatal("expected expand of more than 255*Nh bytes to fail")
	}
	out, err := KDFHKDFSHA256.Expand(make([]byte, 32), nil, 255*32)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 255*32 {
		t.Fatalf("got %d bytes", len(out))
	}
}

// TestHKDFRFC5869 checks HKDF-SHA256 against RFC 5869 test case 1.
func TestHKDFRFC5869(t *testing.T) {
	ikm := mustHex(t, "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")
	prk := KDFHKDFSHA256.Extract(salt, ikm)
	if got := hex.EncodeToString(prk); got != "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5" {
		t.Fatalf("prk = %s", got)
	}
	okm, err := KDFHKDFSHA256.Expand(prk, info, 42)
	if err != nil {
		t.Fatal(err)
	}
	want := "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
	if got := hex.EncodeToString(okm); got != want {
		t.Fatalf("okm = %s", got)
	}
}
