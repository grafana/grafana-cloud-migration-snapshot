package crypto

import (
	cryptoRand "crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/grafana/grafana-cloud-migration-snapshot/src/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNacl(t *testing.T) {
	t.Parallel()

	t.Run("basic", func(t *testing.T) {
		nacl := NewNacl()

		sender, err := nacl.GenerateKeys()
		require.NoError(t, err)

		recipient, err := nacl.GenerateKeys()
		require.NoError(t, err)

		msg := "hello world"

		var nonce [24]byte
		_, err = io.ReadFull(cryptoRand.Reader, nonce[:])
		require.NoError(t, err)

		reader, err := nacl.Encrypt(contracts.AssymetricKeys{
			Public:  recipient.Public,
			Private: sender.Private,
		},
			strings.NewReader(msg),
		)
		require.NoError(t, err)

		reader, err = nacl.Decrypt(contracts.AssymetricKeys{
			Public:  sender.Public,
			Private: recipient.Private,
		},
			reader,
		)
		require.NoError(t, err)

		buffer, err := io.ReadAll(reader)
		require.NoError(t, err)

		assert.Equal(t, msg, string(buffer))
	})

	t.Run("decrypt returns error when encrypted payload is too small", func(t *testing.T) {
		nacl := NewNacl()

		_, err := nacl.Decrypt(contracts.AssymetricKeys{}, strings.NewReader("too small"))
		require.ErrorIs(t, err, ErrEncryptedPayloadLengthTooSmall)
	})
}
