// Command ohttp-keygen generates a key pair for the OHTTP gateway plugin and
// prints the matching Traefik configuration and public key configuration.
//
//	go run github.com/mathieuHa/ohttp-gateway-traefik-plugin/cmd/ohttp-keygen@latest -key-id 1
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/ohttp"
)

func main() {
	keyID := flag.Uint("key-id", 1, "key identifier (0-255)")
	kemName := flag.String("kem", "X25519", "KEM: X25519, P-256, P-384 or P-521")
	suitesFlag := flag.String("suites", "HKDF-SHA256/AES-128-GCM,HKDF-SHA256/AES-256-GCM", "comma-separated KDF/AEAD pairs")
	keyFile := flag.String("out", "", "write the hex private key to this file instead of printing it")
	flag.Parse()

	if err := run(*keyID, *kemName, *suitesFlag, *keyFile); err != nil {
		fmt.Fprintln(os.Stderr, "ohttp-keygen:", err)
		os.Exit(1)
	}
}

func run(keyID uint, kemName, suitesFlag, keyFile string) error {
	if keyID > 255 {
		return fmt.Errorf("key-id must be between 0 and 255, got %d", keyID)
	}
	kem, err := ohttp.ParseKEM(kemName)
	if err != nil {
		return err
	}
	names := strings.Split(suitesFlag, ",")
	suites := make([]ohttp.SymmetricSuite, 0, len(names))
	for _, name := range names {
		suite, err := ohttp.ParseSymmetricSuite(name)
		if err != nil {
			return err
		}
		suites = append(suites, suite)
	}

	sk, err := kem.GenerateKeyPair(rand.Reader)
	if err != nil {
		return err
	}
	key, err := ohttp.NewPrivateKeyConfig(uint8(keyID), kem, sk, suites)
	if err != nil {
		return err
	}
	keys, err := ohttp.MarshalKeyConfigs([]ohttp.KeyConfig{key.Config})
	if err != nil {
		return err
	}
	privateKey := hex.EncodeToString(sk.Bytes())

	keyLine := "privateKey: " + privateKey
	if keyFile != "" {
		if err := os.WriteFile(keyFile, []byte(privateKey+"\n"), 0o600); err != nil {
			return err
		}
		keyLine = "privateKeyFile: " + keyFile
	}

	fmt.Printf(`# Traefik dynamic configuration (keep the private key secret).
keys:
  - keyId: %d
    kem: %s
    %s
    suites:
`, keyID, strings.TrimSpace(strings.ToUpper(kemName)), keyLine)
	for _, suite := range suites {
		fmt.Printf("      - %s\n", suite)
	}
	fmt.Printf(`
# Public key configuration (application/ohttp-keys) served by the gateway.
# hex:    %s
# base64: %s
`, hex.EncodeToString(keys), base64.StdEncoding.EncodeToString(keys))
	return nil
}
