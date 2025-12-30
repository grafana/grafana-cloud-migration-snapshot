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

func TestHpke(t *testing.T) {
	t.Parallel()

	hpke := NewHpke()

	sender, err := hpke.GenerateKeys()
	require.NoError(t, err)

	recipient, err := hpke.GenerateKeys()
	require.NoError(t, err)

	msg := "hello world"

	var nonce [24]byte
	_, err = io.ReadFull(cryptoRand.Reader, nonce[:])
	require.NoError(t, err)

	reader, err := hpke.Encrypt(contracts.AssymetricKeys{
		Public:  recipient.Public,
		Private: sender.Private,
	},
		strings.NewReader(msg),
	)
	require.NoError(t, err)

	reader, err = hpke.Decrypt(contracts.AssymetricKeys{
		Public:  sender.Public,
		Private: recipient.Private,
	},
		reader,
	)
	require.NoError(t, err)

	buffer, err := io.ReadAll(reader)
	require.NoError(t, err)

	assert.Equal(t, msg, string(buffer))
}
