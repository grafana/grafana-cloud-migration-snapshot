package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"fmt"
	"io"

	"github.com/grafana/grafana-cloud-migration-snapshot/src/contracts"
)

type Hpke struct{}

var _ contracts.Crypto = (*Hpke)(nil)

func NewHpke() Hpke {
	return Hpke{}
}

func (Hpke) Algo() string {
	return "hpke-p521-shake256-aes256gcm"
}

func (h Hpke) Encrypt(keys contracts.AssymetricKeys, reader io.Reader) (io.Reader, error) {
	msg, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading payload from reader: %w", err)
	}

	pk, err := h.kem().NewPublicKey(keys.Public)
	if err != nil {
		return nil, fmt.Errorf("creating ecdh public key: %w", err)
	}

	encrypted, err := hpke.Seal(pk, h.kdf(), h.aead(), []byte(h.Algo()), msg)
	if err != nil {
		return nil, fmt.Errorf("encrypting payload failed: %w", err)
	}

	return bytes.NewReader(encrypted), nil
}

func (h Hpke) Decrypt(keys contracts.AssymetricKeys, reader io.Reader) (io.Reader, error) {
	encryptedPayload, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading from reader: %w", err)
	}

	sk, err := h.kem().NewPrivateKey(keys.Private)
	if err != nil {
		return nil, fmt.Errorf("creating ecdh private key: %w", err)
	}

	decrypted, err := hpke.Open(sk, h.kdf(), h.aead(), []byte(h.Algo()), encryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("decrypting payload failed: %w", err)
	}

	return bytes.NewReader(decrypted), nil
}

func (h Hpke) GenerateKeys() (contracts.AssymetricKeys, error) {
	privateKey, err := h.kem().GenerateKey()
	if err != nil {
		return contracts.AssymetricKeys{}, fmt.Errorf("generating private key: %w", err)
	}

	privateKeyBytes, err := privateKey.Bytes()
	if err != nil {
		return contracts.AssymetricKeys{}, fmt.Errorf("getting private key bytes: %w", err)
	}

	publicKey := privateKey.PublicKey()

	return contracts.AssymetricKeys{
		Public:  publicKey.Bytes(),
		Private: privateKeyBytes,
	}, nil
}

func (h Hpke) kem() hpke.KEM { return hpke.DHKEM(ecdh.P521()) }

func (h Hpke) kdf() hpke.KDF { return hpke.SHAKE256() }

func (h Hpke) aead() hpke.AEAD { return hpke.AES256GCM() }
