package snapshot

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	cryptoRand "crypto/rand"

	"github.com/grafana/grafana-cloud-migration-snapshot/src/contracts"
	"github.com/grafana/grafana-cloud-migration-snapshot/src/infra/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"
)

func TestCreateSnapshot(t *testing.T) {
	t.Parallel()

	senderPublicKey, senderPrivateKey, err := box.GenerateKey(cryptoRand.Reader)
	require.NoError(t, err)

	recipientPublicKey, recipientPrivateKey, err := box.GenerateKey(cryptoRand.Reader)
	require.NoError(t, err)

	nacl := crypto.NewNacl()

	writer, err := NewSnapshotWriter(contracts.AssymetricKeys{
		Public:  recipientPublicKey[:],
		Private: senderPrivateKey[:],
	},
		nacl,
		"./tmp",
	)
	require.NoError(t, err)

	// Generate random resources.
	datasources := generateItems(string(DatasourceDataType), 10_000)

	folders := generateItems(string(FolderDataType), 10_000)

	dashboards := generateItems(string(DashboardDataType), 10_000)

	// Write the resources to the snapshot.
	require.NoError(t, writer.Write(string(DatasourceDataType), datasources))
	require.NoError(t, writer.Write(string(FolderDataType), folders))
	require.NoError(t, writer.Write(string(DashboardDataType), dashboards))

	// Write the index file.
	indexFilePath, err := writer.Finish(senderPublicKey[:])
	require.NoError(t, err)

	file, err := os.Open(indexFilePath)
	require.NoError(t, err)

	index, err := ReadIndex(file)
	require.NoError(t, err)

	resources := make(map[string][]MigrateDataRequestItemDTO)

	// Using the index, read each data file and group the contents by resource type (e.g. dashboards).
	for resourceType, fileNames := range index.Items {
		for _, fileName := range fileNames {
			file, err := os.Open(filepath.Join(writer.folder, fileName))
			require.NoError(t, err)

			snapshotReader := NewSnapshotReader(contracts.AssymetricKeys{
				Public:  senderPublicKey[:],
				Private: recipientPrivateKey[:],
			}, nacl,
			)
			require.NoError(t, err)

			partition, err := snapshotReader.ReadFile(file)
			require.NoError(t, err)

			resources[resourceType] = append(resources[resourceType], partition.Items...)
		}
	}

	// Ensure we got the initial data back.
	assert.Equal(t, datasources, resources[string(DatasourceDataType)])
	assert.Equal(t, folders, resources[string(FolderDataType)])
	assert.Equal(t, dashboards, resources[string(DashboardDataType)])
}

func generateItems(resourceType string, numItems int) []MigrateDataRequestItemDTO {
	items := make([]MigrateDataRequestItemDTO, 0, numItems)

	for i := 0; i < numItems; i++ {
		items = append(items, MigrateDataRequestItemDTO{
			Type:  MigrateDataType(resourceType),
			RefID: fmt.Sprintf("%s_%d_ref_id", resourceType, i),
			Name:  fmt.Sprintf("%s_%d_name", resourceType, i),
			Data:  fmt.Sprintf("%s_%d_data", resourceType, i),
		})
	}

	return items
}
