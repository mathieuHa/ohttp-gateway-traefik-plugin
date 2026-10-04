// Package ohttp_gateway_traefik_plugin implements a Traefik middleware acting as
// an Oblivious HTTP Gateway Resource (RFC 9458).
//
// The package name is imposed by Traefik's plugin loader, which derives it
// from the module path.
package ohttp_gateway_traefik_plugin

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/ohttp"
)

// Default configuration values.
const (
	DefaultGatewayPath     = "/.well-known/ohttp-gateway"
	DefaultMaxRequestSize  = 1 << 20
	DefaultMaxResponseSize = 10 << 20
	DefaultForwardTimeout  = "30s"
	DefaultKeysCacheMaxAge = 3600
)

// KeyConfig configures one gateway key pair.
//
// Exactly one of PrivateKey, PrivateKeyFile or Seed must be set.
type KeyConfig struct {
	// KeyID is the 8-bit key identifier (0-255) advertised to clients.
	KeyID int `json:"keyId,omitempty"`
	// KEM is the HPKE KEM: X25519 (default), P-256, P-384 or P-521.
	KEM string `json:"kem,omitempty"`
	// PrivateKey is the serialized private key, hex or base64 encoded.
	PrivateKey string `json:"privateKey,omitempty"`
	// PrivateKeyFile is a file containing the hex or base64 encoded private key.
	PrivateKeyFile string `json:"privateKeyFile,omitempty"`
	// Seed is hex or base64 encoded input keying material from which the key
	// pair is derived (RFC 9180 DeriveKeyPair). It must be at least as long as
	// a private key.
	Seed string `json:"seed,omitempty"`
	// Suites lists the accepted "KDF/AEAD" pairs, e.g. "HKDF-SHA256/AES-128-GCM".
	// Defaults to HKDF-SHA256 with AES-128-GCM and AES-256-GCM.
	Suites []string `json:"suites,omitempty"`
	// Retired keys still decrypt requests but are no longer advertised, which
	// lets clients holding an old key configuration finish a rotation.
	Retired bool `json:"retired,omitempty"`
}

// Config is the plugin configuration.
type Config struct {
	// GatewayPath is the path of the Oblivious Gateway Resource. POST requests
	// carrying "message/ohttp-req" are decapsulated, GET requests return the
	// key configurations ("application/ohttp-keys").
	GatewayPath string `json:"gatewayPath,omitempty"`
	// KeysPath is an optional additional path serving the key configurations.
	KeysPath string `json:"keysPath,omitempty"`
	// KeysCacheMaxAge is the max-age, in seconds, sent with key configurations.
	KeysCacheMaxAge int `json:"keysCacheMaxAge,omitempty"`
	// Keys are the gateway key pairs.
	Keys []KeyConfig `json:"keys,omitempty"`
	// AllowedTargets restricts the authorities (host or host:port, optionally
	// with a leading "*." wildcard) that encapsulated requests may target.
	// Empty means any authority.
	AllowedTargets []string `json:"allowedTargets,omitempty"`
	// ForwardURL, when set, sends decapsulated requests over HTTP to this base
	// URL (e.g. Traefik's own entry point) instead of the next handler of the
	// middleware chain. The target authority is kept in the Host header.
	ForwardURL string `json:"forwardUrl,omitempty"`
	// ForwardTimeout bounds requests sent to ForwardURL (Go duration).
	ForwardTimeout string `json:"forwardTimeout,omitempty"`
	// MaxRequestSize is the maximum size in bytes of an encapsulated request.
	MaxRequestSize int64 `json:"maxRequestSize,omitempty"`
	// MaxResponseSize is the maximum size in bytes of a target response body.
	MaxResponseSize int64 `json:"maxResponseSize,omitempty"`
	// PaddingBlockSize pads binary responses to a multiple of this many bytes
	// to reduce what response sizes reveal. 0 disables padding.
	PaddingBlockSize int `json:"paddingBlockSize,omitempty"`
	// LogLevel is one of DEBUG, INFO (default), WARN or ERROR.
	LogLevel string `json:"logLevel,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		GatewayPath:     DefaultGatewayPath,
		KeysCacheMaxAge: DefaultKeysCacheMaxAge,
		ForwardTimeout:  DefaultForwardTimeout,
		MaxRequestSize:  DefaultMaxRequestSize,
		MaxResponseSize: DefaultMaxResponseSize,
		LogLevel:        "INFO",
	}
}

func validateConfig(config *Config) error {
	if !strings.HasPrefix(config.GatewayPath, "/") {
		return fmt.Errorf("gatewayPath must start with '/': %q", config.GatewayPath)
	}
	if config.KeysPath != "" && !strings.HasPrefix(config.KeysPath, "/") {
		return fmt.Errorf("keysPath must start with '/': %q", config.KeysPath)
	}
	if config.KeysPath == config.GatewayPath {
		return errors.New("keysPath must differ from gatewayPath")
	}
	if config.MaxRequestSize <= 0 {
		return errors.New("maxRequestSize must be positive")
	}
	if config.MaxResponseSize <= 0 {
		return errors.New("maxResponseSize must be positive")
	}
	if config.PaddingBlockSize < 0 {
		return errors.New("paddingBlockSize must not be negative")
	}
	if config.KeysCacheMaxAge < 0 {
		return errors.New("keysCacheMaxAge must not be negative")
	}
	if len(config.Keys) == 0 {
		return errors.New("at least one key must be configured")
	}
	for _, target := range config.AllowedTargets {
		if strings.TrimPrefix(target, "*.") == "" || strings.ContainsAny(target, "/ ") {
			return fmt.Errorf("invalid allowedTargets entry %q", target)
		}
	}
	return nil
}

func parseForwardTimeout(value string) (time.Duration, error) {
	if value == "" {
		value = DefaultForwardTimeout
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid forwardTimeout: %w", err)
	}
	if d <= 0 {
		return 0, errors.New("forwardTimeout must be positive")
	}
	return d, nil
}

// loadKeys builds the gateway keys and the advertised key configurations.
func loadKeys(configs []KeyConfig) (keys []*ohttp.PrivateKeyConfig, advertised []ohttp.KeyConfig, err error) {
	for i, kc := range configs {
		key, err := loadKey(kc)
		if err != nil {
			return nil, nil, fmt.Errorf("keys[%d]: %w", i, err)
		}
		keys = append(keys, key)
		if !kc.Retired {
			advertised = append(advertised, key.Config)
		}
	}
	if len(advertised) == 0 {
		return nil, nil, errors.New("at least one key must not be retired")
	}
	return keys, advertised, nil
}

func loadKey(kc KeyConfig) (*ohttp.PrivateKeyConfig, error) {
	if kc.KeyID < 0 || kc.KeyID > 255 {
		return nil, fmt.Errorf("keyId must be between 0 and 255, got %d", kc.KeyID)
	}
	kem, err := ohttp.ParseKEM(kc.KEM)
	if err != nil {
		return nil, err
	}
	suites, err := parseSuites(kc.Suites)
	if err != nil {
		return nil, err
	}

	sources := 0
	for _, s := range []string{kc.PrivateKey, kc.PrivateKeyFile, kc.Seed} {
		if s != "" {
			sources++
		}
	}
	if sources != 1 {
		return nil, errors.New("exactly one of privateKey, privateKeyFile or seed must be set")
	}

	var sk *ecdh.PrivateKey
	switch {
	case kc.Seed != "":
		ikm, err := decodeKeyMaterial(kc.Seed)
		if err != nil {
			return nil, fmt.Errorf("seed: %w", err)
		}
		if len(ikm) < kem.Nsk() {
			return nil, fmt.Errorf("seed must be at least %d bytes", kem.Nsk())
		}
		if sk, err = kem.DeriveKeyPair(ikm); err != nil {
			return nil, err
		}
	case kc.PrivateKeyFile != "":
		content, err := os.ReadFile(kc.PrivateKeyFile)
		if err != nil {
			return nil, fmt.Errorf("privateKeyFile: %w", err)
		}
		raw, err := decodeKeyMaterial(string(content))
		if err != nil {
			return nil, fmt.Errorf("privateKeyFile: %w", err)
		}
		if sk, err = kem.ParsePrivateKey(raw); err != nil {
			return nil, fmt.Errorf("privateKeyFile: %w", err)
		}
	default:
		raw, err := decodeKeyMaterial(kc.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("privateKey: %w", err)
		}
		if sk, err = kem.ParsePrivateKey(raw); err != nil {
			return nil, fmt.Errorf("privateKey: %w", err)
		}
	}
	return ohttp.NewPrivateKeyConfig(uint8(kc.KeyID), kem, sk, suites)
}

// decodeKeyMaterial accepts hex or (standard or URL-safe) base64 input.
func decodeKeyMaterial(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty value")
	}
	if b, err := hex.DecodeString(value); err == nil {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(value); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("value is neither hex nor base64")
}

func parseSuites(names []string) ([]ohttp.SymmetricSuite, error) {
	if len(names) == 0 {
		return ohttp.DefaultSuites(), nil
	}
	suites := make([]ohttp.SymmetricSuite, 0, len(names))
	for _, name := range names {
		suite, err := ohttp.ParseSymmetricSuite(name)
		if err != nil {
			return nil, err
		}
		suites = append(suites, suite)
	}
	return suites, nil
}
