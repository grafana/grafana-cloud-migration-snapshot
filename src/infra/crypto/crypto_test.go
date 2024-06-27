package crypto

import (
	cryptoRand "crypto/rand"
	"io"
	"strings"
	"testing"

	"github.com/grafana/grafana-cloud-migration-snapshot/src/contracts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
)

func TestNacl(t *testing.T) {
	t.Parallel()

	senderPublicKey, senderPrivateKey, err := box.GenerateKey(cryptoRand.Reader)
	require.NoError(t, err)

	recipientPublicKey, recipientPrivateKey, err := box.GenerateKey(cryptoRand.Reader)
	require.NoError(t, err)

	msg := "hello world"

	nacl := NewNacl()

	var nonce [24]byte
	_, err = io.ReadFull(cryptoRand.Reader, nonce[:])
	require.NoError(t, err)

	reader, err := nacl.Encrypt(contracts.AssymetricKeys{
		Public:  recipientPublicKey[:],
		Private: senderPrivateKey[:],
	},
		strings.NewReader(msg),
	)
	require.NoError(t, err)

	reader, err = nacl.Decrypt(contracts.AssymetricKeys{
		Public:  senderPublicKey[:],
		Private: recipientPrivateKey[:],
	},
		reader,
	)
	require.NoError(t, err)

	buffer, err := io.ReadAll(reader)
	require.NoError(t, err)

	assert.Equal(t, msg, string(buffer))
}
