// Package hpke implements the subset of Hybrid Public Key Encryption (RFC 9180)
// needed by Oblivious HTTP: the base mode, DHKEM over X25519 and the NIST
// curves, HKDF-SHA2 and AES-GCM.
//
// It depends on the Go standard library only, so that it can be interpreted by
// Yaegi when loaded as a Traefik plugin.
package hpke

import (
	"crypto/cipher"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const modeBase = 0x00

var errSequenceOverflow = errors.New("hpke: message limit reached")

// Suite is an HPKE cipher suite.
type Suite struct {
	KEM  KEM
	KDF  KDF
	AEAD AEAD
}

// Validate returns an error if one of the suite algorithms is not supported.
func (s Suite) Validate() error {
	switch {
	case !s.KEM.IsSupported():
		return fmt.Errorf("hpke: unsupported KEM %s", s.KEM)
	case !s.KDF.IsSupported():
		return fmt.Errorf("hpke: unsupported KDF %s", s.KDF)
	case !s.AEAD.IsSupported():
		return fmt.Errorf("hpke: unsupported AEAD %s", s.AEAD)
	default:
		return nil
	}
}

func (s Suite) id() []byte {
	id := []byte("HPKE\x00\x00\x00\x00\x00\x00")
	binary.BigEndian.PutUint16(id[4:], uint16(s.KEM))
	binary.BigEndian.PutUint16(id[6:], uint16(s.KDF))
	binary.BigEndian.PutUint16(id[8:], uint16(s.AEAD))
	return id
}

// Context holds the state shared by HPKE senders and receivers.
type Context struct {
	suite          Suite
	aead           cipher.AEAD
	baseNonce      []byte
	exporterSecret []byte
	seq            uint64
}

// Sender is an HPKE sending context.
type Sender struct {
	Context
}

// Receiver is an HPKE receiving context.
type Receiver struct {
	Context
}

// SetupBaseS creates a sending context for pkR (RFC 9180, Section 5.1.1).
func (s Suite) SetupBaseS(rand io.Reader, pkR *ecdh.PublicKey, info []byte) (enc []byte, sender *Sender, err error) {
	if err = s.Validate(); err != nil {
		return nil, nil, err
	}
	sharedSecret, enc, err := s.KEM.Encap(rand, pkR)
	if err != nil {
		return nil, nil, err
	}
	ctx, err := s.keySchedule(sharedSecret, info)
	if err != nil {
		return nil, nil, err
	}
	return enc, &Sender{Context: *ctx}, nil
}

// SetupBaseSWithEphemeral is SetupBaseS with a caller-provided ephemeral key.
// It exists for deterministic tests (e.g. reproducing published test vectors)
// and must not be used otherwise: reusing an ephemeral key breaks HPKE.
func (s Suite) SetupBaseSWithEphemeral(skE *ecdh.PrivateKey, pkR *ecdh.PublicKey, info []byte) ([]byte, *Sender, error) {
	if err := s.Validate(); err != nil {
		return nil, nil, err
	}
	sharedSecret, enc, err := s.KEM.encapWithEphemeral(skE, pkR)
	if err != nil {
		return nil, nil, err
	}
	ctx, err := s.keySchedule(sharedSecret, info)
	if err != nil {
		return nil, nil, err
	}
	return enc, &Sender{Context: *ctx}, nil
}

// SetupBaseR creates a receiving context from an encapsulated key
// (RFC 9180, Section 5.1.1).
func (s Suite) SetupBaseR(skR *ecdh.PrivateKey, enc, info []byte) (*Receiver, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	sharedSecret, err := s.KEM.Decap(enc, skR)
	if err != nil {
		return nil, err
	}
	ctx, err := s.keySchedule(sharedSecret, info)
	if err != nil {
		return nil, err
	}
	return &Receiver{Context: *ctx}, nil
}

func (s Suite) keySchedule(sharedSecret, info []byte) (*Context, error) {
	sid := s.id()
	kdf := s.KDF

	pskIDHash := kdf.labeledExtract(sid, nil, "psk_id_hash", nil)
	infoHash := kdf.labeledExtract(sid, nil, "info_hash", info)
	keyScheduleContext := make([]byte, 0, 1+len(pskIDHash)+len(infoHash))
	keyScheduleContext = append(keyScheduleContext, modeBase)
	keyScheduleContext = append(keyScheduleContext, pskIDHash...)
	keyScheduleContext = append(keyScheduleContext, infoHash...)

	secret := kdf.labeledExtract(sid, sharedSecret, "secret", nil)

	key, err := kdf.labeledExpand(sid, secret, "key", keyScheduleContext, s.AEAD.Nk())
	if err != nil {
		return nil, err
	}
	baseNonce, err := kdf.labeledExpand(sid, secret, "base_nonce", keyScheduleContext, s.AEAD.Nn())
	if err != nil {
		return nil, err
	}
	exporterSecret, err := kdf.labeledExpand(sid, secret, "exp", keyScheduleContext, kdf.Nh())
	if err != nil {
		return nil, err
	}
	aead, err := s.AEAD.New(key)
	if err != nil {
		return nil, err
	}
	return &Context{
		suite:          s,
		aead:           aead,
		baseNonce:      baseNonce,
		exporterSecret: exporterSecret,
	}, nil
}

// Suite returns the cipher suite of the context.
func (c *Context) Suite() Suite {
	return c.suite
}

// Export derives a secret of the given length from the context
// (RFC 9180, Section 5.3).
func (c *Context) Export(exporterContext []byte, length int) ([]byte, error) {
	return c.suite.KDF.labeledExpand(c.suite.id(), c.exporterSecret, "sec", exporterContext, length)
}

// computeNonce XORs the sequence number into the base nonce. The sequence
// number is only incremented by callers once the AEAD operation succeeded
// (RFC 9180, Section 5.2).
func (c *Context) computeNonce() ([]byte, error) {
	if c.seq == ^uint64(0) {
		return nil, errSequenceOverflow
	}
	nonce := append([]byte{}, c.baseNonce...)
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], c.seq)
	offset := len(nonce) - len(seq)
	for i, b := range seq {
		nonce[offset+i] ^= b
	}
	return nonce, nil
}

// Seal encrypts and authenticates plaintext.
func (s *Sender) Seal(aad, plaintext []byte) ([]byte, error) {
	nonce, err := s.computeNonce()
	if err != nil {
		return nil, err
	}
	s.seq++
	return s.aead.Seal(nil, nonce, plaintext, aad), nil
}

// Open authenticates and decrypts ciphertext.
func (r *Receiver) Open(aad, ciphertext []byte) ([]byte, error) {
	nonce, err := r.computeNonce()
	if err != nil {
		return nil, err
	}
	plaintext, err := r.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	r.seq++
	return plaintext, nil
}
