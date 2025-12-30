package crypto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	cryptoRand "crypto/rand"
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
	return "hpke-p521-hkdfsha512-aes256gcm"
}

func (h Hpke) Encrypt(keys contracts.AssymetricKeys, reader io.Reader) (io.Reader, error) {
	msg, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading payload from reader: %w", err)
	}

	encrypted, err := hpke.Seal(keys.Public, hpke.HKDFSHA512(), hpke.AES256GCM(), h.Algo(), msg)
	if err != nil {
		return nil, nil
	}

	return bytes.NewReader(encrypted), nil
}

func (h Hpke) Decrypt(keys contracts.AssymetricKeys, reader io.Reader) (io.Reader, error) {
	encryptedPayload, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading from reader: %w", err)
	}

	decrypted, err := hpke.Open(keys.Private, hpke.HKDFSHA512(), hpke.AES256GCM(), h.Algo(), encryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("decrypting payload failed: %w", err)
	}

	return bytes.NewReader(decrypted), nil
}

func (Hpke) GenerateKeys() (contracts.AssymetricKeys, error) {
	curve := ecdh.P521()

	privateKey, err := curve.GenerateKey(cryptoRand.Reader)
	if err != nil {
		return contracts.AssymetricKeys{}, fmt.Errorf("generating private key: %w", err)
	}

	publicKey := privateKey.PublicKey()

	return contracts.AssymetricKeys{
		Public:  publicKey.Bytes(),
		Private: privateKey.Bytes(),
	}, nil
}
