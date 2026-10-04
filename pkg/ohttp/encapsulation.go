package ohttp

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/hpke"
)

const (
	requestLabel  = "message/bhttp request"
	responseLabel = "message/bhttp response"
	headerLen     = 7
)

// Errors returned by Gateway.DecapsulateRequest. ErrUnknownKey and
// ErrUnsupportedSuite indicate that the client used an outdated or incorrect
// key configuration.
var (
	ErrMalformedRequest  = errors.New("ohttp: malformed encapsulated request")
	ErrUnknownKey        = errors.New("ohttp: unknown key identifier")
	ErrUnsupportedSuite  = errors.New("ohttp: unsupported HPKE suite")
	ErrDecryptionFailed  = errors.New("ohttp: request decryption failed")
	ErrMalformedResponse = errors.New("ohttp: malformed encapsulated response")
)

// header is the Encapsulated Request header (RFC 9458, Section 4.1).
type header struct {
	keyID uint8
	suite hpke.Suite
}

func (h header) marshal() []byte {
	b := make([]byte, 0, headerLen)
	b = append(b, h.keyID)
	b = binary.BigEndian.AppendUint16(b, uint16(h.suite.KEM))
	b = binary.BigEndian.AppendUint16(b, uint16(h.suite.KDF))
	return binary.BigEndian.AppendUint16(b, uint16(h.suite.AEAD))
}

func (h header) info() []byte {
	info := make([]byte, 0, len(requestLabel)+1+headerLen)
	info = append(info, requestLabel...)
	info = append(info, 0)
	return append(info, h.marshal()...)
}

func parseHeader(b []byte) header {
	return header{
		keyID: b[0],
		suite: hpke.Suite{
			KEM:  hpke.KEM(binary.BigEndian.Uint16(b[1:3])),
			KDF:  hpke.KDF(binary.BigEndian.Uint16(b[3:5])),
			AEAD: hpke.AEAD(binary.BigEndian.Uint16(b[5:7])),
		},
	}
}

// Gateway decapsulates requests for a set of private keys.
type Gateway struct {
	keys map[uint8]*PrivateKeyConfig
}

// NewGateway returns a gateway serving the given keys. Key identifiers must be
// unique.
func NewGateway(keys []*PrivateKeyConfig) (*Gateway, error) {
	if len(keys) == 0 {
		return nil, errors.New("ohttp: at least one key is required")
	}
	g := &Gateway{keys: make(map[uint8]*PrivateKeyConfig, len(keys))}
	for _, k := range keys {
		if _, ok := g.keys[k.Config.KeyID]; ok {
			return nil, fmt.Errorf("ohttp: duplicate key identifier %d", k.Config.KeyID)
		}
		g.keys[k.Config.KeyID] = k
	}
	return g, nil
}

// ResponseContext holds the state needed to encapsulate the response to a
// decapsulated request.
type ResponseContext struct {
	ctx *hpke.Context
	enc []byte
}

// DecapsulateRequest decrypts an Encapsulated Request (RFC 9458, Section 4.3)
// and returns the binary HTTP request with the context used to encapsulate the
// response.
func (g *Gateway) DecapsulateRequest(encRequest []byte) ([]byte, *ResponseContext, error) {
	if len(encRequest) < headerLen {
		return nil, nil, ErrMalformedRequest
	}
	hdr := parseHeader(encRequest)
	key, ok := g.keys[hdr.keyID]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %d", ErrUnknownKey, hdr.keyID)
	}
	if hdr.suite.KEM != key.Config.KEM {
		return nil, nil, fmt.Errorf("%w: KEM %s does not match key %d", ErrUnsupportedSuite, hdr.suite.KEM, hdr.keyID)
	}
	if !key.supports(hdr.suite.KDF, hdr.suite.AEAD) {
		return nil, nil, fmt.Errorf("%w: %s/%s", ErrUnsupportedSuite, hdr.suite.KDF, hdr.suite.AEAD)
	}

	nenc := hdr.suite.KEM.Nenc()
	rest := encRequest[headerLen:]
	if len(rest) < nenc {
		return nil, nil, ErrMalformedRequest
	}
	enc, ct := rest[:nenc], rest[nenc:]

	receiver, err := hdr.suite.SetupBaseR(key.PrivateKey, enc, hdr.info())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}
	request, err := receiver.Open(nil, ct)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, err)
	}
	return request, &ResponseContext{ctx: &receiver.Context, enc: append([]byte{}, enc...)}, nil
}

func (k *PrivateKeyConfig) supports(kdf hpke.KDF, aead hpke.AEAD) bool {
	for _, s := range k.Config.Suites {
		if s.KDF == kdf && s.AEAD == aead {
			return true
		}
	}
	return false
}

// EncapsulateResponse encrypts a binary HTTP response (RFC 9458, Section 4.4)
// using a fresh random nonce read from rand.
func (c *ResponseContext) EncapsulateResponse(rand io.Reader, response []byte) ([]byte, error) {
	nonce := make([]byte, responseNonceLen(c.ctx.Suite()))
	if _, err := io.ReadFull(rand, nonce); err != nil {
		return nil, err
	}
	return c.encapsulateResponseWithNonce(nonce, response)
}

func (c *ResponseContext) encapsulateResponseWithNonce(nonce, response []byte) ([]byte, error) {
	aead, aeadNonce, err := responseAEAD(c.ctx, c.enc, nonce)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(nonce)+len(response)+aead.Overhead())
	out = append(out, nonce...)
	return aead.Seal(out, aeadNonce, response, nil), nil
}

func responseNonceLen(s hpke.Suite) int {
	if s.AEAD.Nk() > s.AEAD.Nn() {
		return s.AEAD.Nk()
	}
	return s.AEAD.Nn()
}

// responseAEAD derives the AEAD and nonce protecting the response.
func responseAEAD(ctx *hpke.Context, enc, responseNonce []byte) (cipher.AEAD, []byte, error) {
	suite := ctx.Suite()
	secret, err := ctx.Export([]byte(responseLabel), responseNonceLen(suite))
	if err != nil {
		return nil, nil, err
	}
	salt := make([]byte, 0, len(enc)+len(responseNonce))
	salt = append(salt, enc...)
	salt = append(salt, responseNonce...)
	prk := suite.KDF.Extract(salt, secret)
	key, err := suite.KDF.Expand(prk, []byte("key"), suite.AEAD.Nk())
	if err != nil {
		return nil, nil, err
	}
	nonce, err := suite.KDF.Expand(prk, []byte("nonce"), suite.AEAD.Nn())
	if err != nil {
		return nil, nil, err
	}
	aead, err := suite.AEAD.New(key)
	if err != nil {
		return nil, nil, err
	}
	return aead, nonce, nil
}
