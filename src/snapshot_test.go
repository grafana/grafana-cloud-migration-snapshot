package snapshot

import (
	"encoding/json"
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

func tempDir(t *testing.T) string {
	t.Helper()

	return filepath.Join(t.TempDir(), "grafana-cloud-migration-snapshot")
}

type input struct {
	resourceType MigrateDataType
	items        []MigrateDataRequestItemDTO
}

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
		tempDir(t),
	)
	require.NoError(t, err)

	// Generate random resources.
	resources := make([]input, 0)
	for _, resourceType := range []MigrateDataType{
		DatasourceDataType,
		FolderDataType,
		DashboardDataType,
		LibraryElementDataType,
		AlertRuleType,
		AlertRuleGroupType,
		ContactPointType,
		NotificationPolicyType,
		NotificationTemplateType,
		MuteTimingType,
		PluginDataType,
		AnnotationDataType,
		ReportDataType,
	} {
		resources = append(resources, input{
			resourceType: resourceType,
			items:        generateItems(string(resourceType), 10_000),
		},
		)
	}

	// Write the resources to the snapshot.
	for _, input := range resources {
		require.NoError(t, writer.Write(string(input.resourceType), input.items))
	}

	indexFilePath, err := writer.Finish(FinishInput{SenderPublicKey: senderPublicKey[:], Metadata: []byte("metadata")})
	require.NoError(t, err)

	file, err := os.Open(indexFilePath)
	require.NoError(t, err)

	index, err := ReadIndex(file)
	require.NoError(t, err)

	resourcesFromSnapshot := make(map[string][]MigrateDataRequestItemDTO)

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

			resourcesFromSnapshot[resourceType] = append(resourcesFromSnapshot[resourceType], partition.Items...)
		}
	}

	// Ensure we got the initial data back.
	for _, input := range resources {
		assert.Equal(t, input.items, resourcesFromSnapshot[string(input.resourceType)])
	}
}

func TestChecksumIsValidated(t *testing.T) {
	t.Parallel()

	senderPublicKey, senderPrivateKey, err := box.GenerateKey(cryptoRand.Reader)
	require.NoError(t, err)

	recipientPublicKey, recipientPrivateKey, err := box.GenerateKey(cryptoRand.Reader)
	require.NoError(t, err)

	nacl := crypto.NewNacl()

	t.Run("data file checksum is validated", func(t *testing.T) {
		t.Parallel()

		dir := tempDir(t)

		writer, err := NewSnapshotWriter(contracts.AssymetricKeys{
			Public:  recipientPublicKey[:],
			Private: senderPrivateKey[:],
		},
			nacl,
			dir,
		)
		require.NoError(t, err)

		// Generate random resources.
		datasources := generateItems(string(DatasourceDataType), 10_000)

		// Write the resources to the snapshot.
		require.NoError(t, writer.Write(string(DatasourceDataType), datasources))

		indexFilePath, err := writer.Finish(FinishInput{SenderPublicKey: senderPublicKey[:], Metadata: []byte("metadata")})
		require.NoError(t, err)

		file, err := os.Open(indexFilePath)
		require.NoError(t, err)

		index, err := ReadIndex(file)
		require.NoError(t, err)

		snapshotReader := NewSnapshotReader(contracts.AssymetricKeys{
			Public:  senderPublicKey[:],
			Private: recipientPrivateKey[:],
		}, nacl,
		)
		require.NoError(t, err)

		// Open the data file
		filePath := filepath.Join(dir, index.Items[string(DatasourceDataType)][0])
		file, err = os.OpenFile(filePath, os.O_RDWR, 0644)
		require.NoError(t, err)

		// Read the data file
		partition, err := snapshotReader.ReadFile(file)
		require.NoError(t, err)

		// Modify the data
		partition.Items = append(partition.Items, MigrateDataRequestItemDTO{RefID: "some_ref_id"})

		// Write the modified data to the file
		buffer, err := json.Marshal(partition)
		require.NoError(t, err)
		_, err = file.Seek(0, 0)
		require.NoError(t, err)
		require.NoError(t, file.Truncate(0))
		_, err = file.Write(buffer)
		require.NoError(t, err)

		// Try to read the index after modifying the file.
		_, err = file.Seek(0, 0)
		require.NoError(t, err)
		_, err = snapshotReader.ReadFile(file)
		assert.ErrorContains(t, err, "partition checksum mismatch")
	})

	t.Run("index file checksum is validated", func(t *testing.T) {
		t.Parallel()

		writer, err := NewSnapshotWriter(contracts.AssymetricKeys{
			Public:  recipientPublicKey[:],
			Private: senderPrivateKey[:],
		},
			nacl,
			tempDir(t),
		)
		require.NoError(t, err)

		// Write the index file.
		indexFilePath, err := writer.Finish(FinishInput{SenderPublicKey: senderPublicKey[:], Metadata: []byte("metadata")})
		require.NoError(t, err)

		file, err := os.OpenFile(indexFilePath, os.O_RDWR, 0644)
		require.NoError(t, err)

		// Modify the index file.
		var index Index
		require.NoError(t, json.NewDecoder(file).Decode(&index))
		index.Items["foo"] = []string{"bar"}

		buffer, err := json.Marshal(index)
		require.NoError(t, err)

		_, err = file.Seek(0, 0)
		require.NoError(t, err)
		require.NoError(t, file.Truncate(0))
		_, err = file.Write(buffer)
		require.NoError(t, err)

		// Try to read the index after modifying the file.
		_, err = file.Seek(0, 0)
		require.NoError(t, err)
		index, err = ReadIndex(file)
		assert.ErrorContains(t, err, "index checksum mismatch")
	})
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
