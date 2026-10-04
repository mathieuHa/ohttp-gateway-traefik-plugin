package ohttp

import (
	"crypto/ecdh"
	"fmt"
	"io"

	"github.com/mathieuHa/ohttp-gateway-traefik-plugin/pkg/hpke"
)

// Client encapsulates requests for a gateway key configuration.
type Client struct {
	header header
	config KeyConfig
}

// NewClient returns a client using the first symmetric suite of config that is
// supported by this implementation.
func NewClient(config KeyConfig) (*Client, error) {
	for _, s := range config.Suites {
		if s.KDF.IsSupported() && s.AEAD.IsSupported() {
			return NewClientWithSuite(config, s)
		}
	}
	return nil, fmt.Errorf("%w: no supported symmetric suite in key %d", ErrUnsupportedSuite, config.KeyID)
}

// NewClientWithSuite returns a client using an explicit symmetric suite, which
// does not need to be advertised by the key configuration (useful to test the
// gateway's behavior).
func NewClientWithSuite(config KeyConfig, suite SymmetricSuite) (*Client, error) {
	s := hpke.Suite{KEM: config.KEM, KDF: suite.KDF, AEAD: suite.AEAD}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &Client{header: header{keyID: config.KeyID, suite: s}, config: config}, nil
}

// ClientContext holds the state needed to decapsulate the response to an
// encapsulated request.
type ClientContext struct {
	ctx *hpke.Context
	enc []byte
}

// EncapsulateRequest encrypts a binary HTTP request (RFC 9458, Section 4.3).
func (c *Client) EncapsulateRequest(rand io.Reader, request []byte) ([]byte, *ClientContext, error) {
	skE, err := c.header.suite.KEM.GenerateKeyPair(rand)
	if err != nil {
		return nil, nil, err
	}
	return c.encapsulateRequestWithEphemeral(skE, request)
}

func (c *Client) encapsulateRequestWithEphemeral(skE *ecdh.PrivateKey, request []byte) ([]byte, *ClientContext, error) {
	enc, sender, err := c.header.suite.SetupBaseSWithEphemeral(skE, c.config.PublicKey, c.header.info())
	if err != nil {
		return nil, nil, err
	}
	ct, err := sender.Seal(nil, request)
	if err != nil {
		return nil, nil, err
	}
	hdr := c.header.marshal()
	out := make([]byte, 0, len(hdr)+len(enc)+len(ct))
	out = append(out, hdr...)
	out = append(out, enc...)
	out = append(out, ct...)
	return out, &ClientContext{ctx: &sender.Context, enc: enc}, nil
}

// DecapsulateResponse decrypts an Encapsulated Response (RFC 9458, Section 4.4).
func (c *ClientContext) DecapsulateResponse(encResponse []byte) ([]byte, error) {
	n := responseNonceLen(c.ctx.Suite())
	if len(encResponse) < n {
		return nil, ErrMalformedResponse
	}
	aead, nonce, err := responseAEAD(c.ctx, c.enc, encResponse[:n])
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, encResponse[n:], nil)
}
