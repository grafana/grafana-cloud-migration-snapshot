package snapshot

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/grafana/grafana-cloud-migration-snapshot/src/contracts"
)

type MigrateDataType string

const (
	DashboardDataType        MigrateDataType = "DASHBOARD"
	DatasourceDataType       MigrateDataType = "DATASOURCE"
	FolderDataType           MigrateDataType = "FOLDER"
	LibraryElementDataType   MigrateDataType = "LIBRARY_ELEMENT"
	AlertRuleType            MigrateDataType = "ALERT_RULE"
	AlertRuleGroupType       MigrateDataType = "ALERT_RULE_GROUP"
	ContactPointType         MigrateDataType = "CONTACT_POINT"
	NotificationPolicyType   MigrateDataType = "NOTIFICATION_POLICY"
	NotificationTemplateType MigrateDataType = "NOTIFICATION_TEMPLATE"
	MuteTimingType           MigrateDataType = "MUTE_TIMING"
	PluginDataType           MigrateDataType = "PLUGIN"
	AnnotationDataType       MigrateDataType = "ANNOTATION"
	ReportDataType           MigrateDataType = "REPORT"
)

type MigrateDataRequestItemDTO struct {
	Type  MigrateDataType `json:"type"`
	RefID string          `json:"refId"`
	Name  string          `json:"name"`
	Data  interface{}     `json:"data"`
}

type FinishInput struct {
	// The public key generated by the client.
	SenderPublicKey []byte
	// Metadata returned by CMS when a snapshot is started.
	// The client must include it when building the index.
	Metadata []byte
}

type SnapshotWriter struct {
	// Folder where files will be written to.
	folder string
	// The public and private keys used to encrypt data files.
	keys contracts.AssymetricKeys
	// A map from resource type (e.g. dashboard, datasource) to a list of file paths that contain resources of the type.
	index  map[string]*resourceIndex
	crypto contracts.Crypto
}

type resourceIndex struct {
	// Number used to name partition files. Starts at 0. Monotonically increasing.
	partitionNumber uint32
	// List of file names that contain resources of a specific type (e.g. dashboard, datasource).
	fileNames []string
}

func NewSnapshotWriter(keys contracts.AssymetricKeys, crypto contracts.Crypto, folder string) (writer *SnapshotWriter, err error) {
	if folder != "" {
		if _, err := os.Stat(folder); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("getting folder info: %w", err)
			}

			if err := os.MkdirAll(folder, 0750); err != nil {
				return nil, fmt.Errorf("creating directory to store snapshot files: %w", err)
			}
		}
	}

	return &SnapshotWriter{
		folder: folder,
		keys:   keys,
		index:  make(map[string]*resourceIndex, 0),
		crypto: crypto,
	}, nil
}

func (writer *SnapshotWriter) Write(resourceType string, items []MigrateDataRequestItemDTO) (err error) {
	if _, ok := writer.index[resourceType]; !ok {
		writer.index[resourceType] = &resourceIndex{partitionNumber: 0, fileNames: make([]string, 0)}
	}
	resourceIndex := writer.index[resourceType]

	fileName := fmt.Sprintf("%s_partition_%d.json", strings.ToLower(resourceType), resourceIndex.partitionNumber)
	filepath := filepath.Join(writer.folder, fileName)
	file, err := os.OpenFile(filepath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating/opening partition file: filepath=%s %w", filepath, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("closing file: %w", closeErr))
		}
	}()

	partitionJsonBytes, err := writer.EncodePartition(items)
	if err != nil {
		return fmt.Errorf("encoding partition: %w", err)
	}

	if _, err := file.Write(partitionJsonBytes); err != nil {
		return fmt.Errorf("writing partition bytes to file: %w", err)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("syncing file: %w", err)
	}

	resourceIndex.partitionNumber++
	resourceIndex.fileNames = append(resourceIndex.fileNames, fileName)

	return nil
}

func (writer *SnapshotWriter) EncodePartition(items []MigrateDataRequestItemDTO) (out []byte, err error) {
	buffer := bytes.NewBuffer(make([]byte, 0))

	gzipWriter := gzip.NewWriter(buffer)
	defer func() {
		if closeErr := gzipWriter.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("closing gzip writer: %w", closeErr))
		}
	}()

	itemsJsonBytes, err := json.Marshal(&items)
	if err != nil {
		return out, fmt.Errorf("marshalling migration items: %w", err)
	}

	bytesWritten, err := gzipWriter.Write(itemsJsonBytes)
	if err != nil {
		return out, fmt.Errorf("writing buffer to gzip writer: bytesWritten=%d %w", bytesWritten, err)
	}
	if bytesWritten != len(itemsJsonBytes) {
		return out, fmt.Errorf("writing buffer to gzip writer failed, unable to write every byte: bytesWritten=%d expectedBytesWritten=%d", bytesWritten, len(itemsJsonBytes))
	}

	if err := gzipWriter.Flush(); err != nil {
		return out, fmt.Errorf("flushing gzip writer: %w", err)
	}

	reader, err := writer.crypto.Encrypt(writer.keys, buffer)
	if err != nil {
		return out, fmt.Errorf("creating reader to encrypt buffer: %w", err)
	}
	encryptedBytes, err := io.ReadAll(reader)
	if err != nil {
		return out, fmt.Errorf("reading encrypted bytes: %w", err)
	}
	checksum, err := computeBufferChecksum(encryptedBytes)
	if err != nil {
		return out, fmt.Errorf("computing checksum: %w", err)
	}

	out, err = json.Marshal(compressedPartition{
		Checksum: checksum,
		Data:     encryptedBytes,
	})
	if err != nil {
		return out, fmt.Errorf("marshalling data with checksum: %w", err)
	}

	return out, err
}

func EncodeIndex(index Index) ([]byte, error) {
	checksum, err := computeIndexChecksum(&index)
	if err != nil {
		return nil, fmt.Errorf("computing index checksum: %w", err)
	}
	index.Checksum = checksum

	bytes, err := json.Marshal(index)
	if err != nil {
		return nil, fmt.Errorf("json marshalling index: %w", err)
	}

	return bytes, nil
}

// Index is an in memory index mapping resource types to file paths where the file contains a list of resources.
type Index struct {
	// Checksum is a checksum computed using the fields in this struct.
	Checksum string `json:"checksum"`
	// The index version. Current only version 1 exists.
	Version uint16 `json:"version"`
	// The algorithm used to encrypt data files.
	EncryptionAlgo string `json:"encryptionAlgo"`
	// The public key used to encrypt data files.
	PublicKey []byte `json:"publicKey"`
	// Metadata returned by CMS when a snapshot is started.
	Metadata []byte `json:"metadata"`
	// Items looks like this:
	// {
	//   "DATASOURCE": ["tmp/datasource_partition_0.json"]
	//   "DASHBOARD": ["tmp/dashboard_partition_0.json"]
	//   ..
	// }
	Items map[string][]string `json:"items"`
}

// compressedPartition represents a file that contains resources of a specific type (e.g. dashboards).
type compressedPartition struct {
	// Checksum is a checksum computed using `Data`.
	Checksum string `json:"checksum"`
	Data     []byte `json:"data"`
}

// partition is the same as compressedPartition except that `Data` has been uncompressed and renamed to `Items`.
type partition struct {
	Checksum string
	Items    []MigrateDataRequestItemDTO
}

func computeBufferChecksum(buffer []byte) (string, error) {
	hash := sha256.New()
	bytesWritten, err := hash.Write(buffer)
	if err != nil {
		return "", fmt.Errorf("writing buffer to hash :%w", err)
	}
	if bytesWritten != len(buffer) {
		return "", fmt.Errorf("writing buffer to hash, expected to write %d bytes but wrote %d", len(buffer), bytesWritten)
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func computeIndexChecksum(index *Index) (string, error) {
	hash := sha256.New()
	if err := binary.Write(hash, binary.LittleEndian, index.Version); err != nil {
		return "", fmt.Errorf("writing index version to hash: %w", err)
	}

	// Write never returns error in this case.
	_, _ = hash.Write([]byte(index.EncryptionAlgo))
	_, _ = hash.Write([]byte(index.PublicKey))
	_, _ = hash.Write([]byte(index.Metadata))

	keys := make([]string, 0, len(index.Items))
	for key := range index.Items {
		keys = append(keys, key)
	}
	// Sort map keys to ensure the same hash is computed every time.
	slices.Sort(keys)

	for _, key := range keys {
		_, _ = hash.Write([]byte(key))

		for _, value := range index.Items[key] {
			_, _ = hash.Write([]byte(value))
		}
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// Writes the in memory index to disk.
func (writer *SnapshotWriter) Finish(input FinishInput) (indexFilePath string, err error) {
	if len(input.SenderPublicKey) == 0 {
		return indexFilePath, fmt.Errorf("public key is required")
	}
	if input.Metadata == nil {
		return indexFilePath, fmt.Errorf("metadata is required")
	}
	items := make(map[string][]string)
	for resourceType, resourceIndex := range writer.index {
		items[resourceType] = resourceIndex.fileNames
	}

	index := Index{
		Version:        1,
		EncryptionAlgo: writer.crypto.Algo(),
		PublicKey:      input.SenderPublicKey,
		Metadata:       input.Metadata,
		Items:          items,
	}
	bytes, err := EncodeIndex(index)
	if err != nil {
		return indexFilePath, fmt.Errorf("encoding index: %w", err)
	}

	indexFilePath = filepath.Join(writer.folder, "index.json")
	file, err := os.OpenFile(indexFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("closing index file: %w", closeErr))
		}
	}()
	if err != nil {
		return indexFilePath, fmt.Errorf("creating/opening index file: filepath=%s %w", indexFilePath, err)
	}
	if _, err := file.Write(bytes); err != nil {
		return indexFilePath, fmt.Errorf("writing index contents to file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return indexFilePath, fmt.Errorf("syncing index file contents: %w", err)
	}

	return indexFilePath, nil
}

// ReadIndex reads the index containing the path to the data files.
func ReadIndex(reader io.Reader) (Index, error) {
	var data Index
	if err := json.NewDecoder(reader).Decode(&data); err != nil {
		return data, fmt.Errorf("reading and decoding snapshot data: %w", err)
	}

	checksum, err := computeIndexChecksum(&data)
	if err != nil {
		return data, fmt.Errorf("computing index checksum: %w", err)
	}
	if data.Checksum != checksum {
		return data, fmt.Errorf("index checksum mismatch: expected=%s got=%s", data.Checksum, checksum)
	}

	return data, nil
}

type SnapshotReader struct {
	keys   contracts.AssymetricKeys
	crypto contracts.Crypto
}

func NewSnapshotReader(keys contracts.AssymetricKeys, crypto contracts.Crypto) *SnapshotReader {
	return &SnapshotReader{keys: keys, crypto: crypto}
}

// ReadFile reads a file containing a list of resources.
func (snapshot *SnapshotReader) ReadFile(reader io.Reader) (partition partition, err error) {
	var data compressedPartition
	if err := json.NewDecoder(reader).Decode(&data); err != nil {
		return partition, fmt.Errorf("reading and decoding snapshot partition: %w", err)
	}

	checksum, err := computeBufferChecksum(data.Data)
	if err != nil {
		return partition, fmt.Errorf("computing partition checksum: %w", err)
	}
	if data.Checksum != checksum {
		return partition, fmt.Errorf("partition checksum mismatch: expected=%s got=%s", data.Checksum, checksum)
	}

	decriptionReader, err := snapshot.crypto.Decrypt(snapshot.keys, bytes.NewReader(data.Data))
	if err != nil {
		return partition, fmt.Errorf("creating decryption reader: %w", err)
	}
	gzipReader, err := gzip.NewReader(decriptionReader)
	if err != nil {
		return partition, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer func() {
		if closeErr := gzipReader.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("closing gzip reader: %w", closeErr))
		}
	}()

	items := make([]MigrateDataRequestItemDTO, 0)
	if err := json.NewDecoder(gzipReader).Decode(&items); err != nil {
		return partition, fmt.Errorf("unmarshalling []MigrateDataRequestItemDTO: %w", err)
	}

	partition.Checksum = data.Checksum
	partition.Items = items

	return partition, nil
}
