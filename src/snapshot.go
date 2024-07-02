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
	DashboardDataType  MigrateDataType = "DASHBOARD"
	DatasourceDataType MigrateDataType = "DATASOURCE"
	FolderDataType     MigrateDataType = "FOLDER"
)

type MigrateDataRequestItemDTO struct {
	Type  MigrateDataType `json:"type"`
	RefID string          `json:"refId"`
	Name  string          `json:"name"`
	Data  interface{}     `json:"data"`
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
	// List of file paths that contain resources of a specific type (e.g. dashboard, datasource).
	filePaths []string
}

func NewSnapshotWriter(keys contracts.AssymetricKeys, crypto contracts.Crypto, folder string) (writer *SnapshotWriter, err error) {
	if _, err := os.Stat(folder); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("getting folder info: %w", err)
		}

		if err := os.MkdirAll(folder, 0750); err != nil {
			return nil, fmt.Errorf("creating directory to store snapshot files: %w", err)
		}
		folderFile, err := os.Open(folder)
		if err != nil {
			return nil, fmt.Errorf("opening directory: path=%s %w", folder, err)
		}
		defer func() {
			if closeErr := folderFile.Close(); closeErr != nil {
				err = errors.Join(err, fmt.Errorf("closing folder file: path=%s %w", folder, closeErr))
			}
		}()
		if err := folderFile.Sync(); err != nil {
			return nil, fmt.Errorf("syncinf folder: path=%s %w", folder, err)
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
		writer.index[resourceType] = &resourceIndex{partitionNumber: 0, filePaths: make([]string, 0)}
	}
	resourceIndex := writer.index[resourceType]

	filepath := filepath.Join(writer.folder, fmt.Sprintf("%s_partition_%d.json", strings.ToLower(resourceType), resourceIndex.partitionNumber))
	file, err := os.OpenFile(filepath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating/opening partition file: filepath=%s %w", filepath, err)
	}
	defer func() {
		if closeErr := file.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("closing file: %w", closeErr))
		}
	}()

	buffer := bytes.NewBuffer(make([]byte, 0))

	gzipWriter := gzip.NewWriter(buffer)
	defer func() {
		if closeErr := gzipWriter.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("closing gzip writer: %w", closeErr))
		}
	}()

	itemsJsonBytes, err := json.Marshal(&items)
	if err != nil {
		return fmt.Errorf("marshalling migration items: %w", err)
	}

	bytesWritten, err := gzipWriter.Write(itemsJsonBytes)
	if err != nil {
		return fmt.Errorf("writing buffer to gzip writer: bytesWritten=%d %w", bytesWritten, err)
	}
	if bytesWritten != len(itemsJsonBytes) {
		return fmt.Errorf("writing buffer to gzip writer failed, unable to write every byte: bytesWritten=%d expectedBytesWritten=%d", bytesWritten, len(itemsJsonBytes))
	}

	if err := gzipWriter.Flush(); err != nil {
		return fmt.Errorf("flushwing gzip writer: %w", err)
	}

	reader, err := writer.crypto.Encrypt(writer.keys, buffer)
	if err != nil {
		return fmt.Errorf("creating reader to encrypt buffer: %w", err)
	}
	encryptedBytes, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("reading encrypted bytes: %w", err)
	}
	checksum, err := computeBufferChecksum(encryptedBytes)
	if err != nil {
		return fmt.Errorf("computing checksum: %w", err)
	}

	partitionJsonBytes, err := json.Marshal(compressedPartition{
		Checksum: checksum,
		Data:     encryptedBytes,
	})
	if err != nil {
		return fmt.Errorf("marshalling data with checksum: %w", err)
	}

	if _, err := file.Write(partitionJsonBytes); err != nil {
		return fmt.Errorf("writing partition bytes to file: %w", err)
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("syncing file: %w", err)
	}

	resourceIndex.partitionNumber++
	resourceIndex.filePaths = append(resourceIndex.filePaths, filepath)

	return nil
}

// Index is an in memory index mapping resource types to file paths where the file contains a list of resources.
type Index struct {
	Version uint16 `json:"version"`
	// Checksum is a checksum computed using `Items`.
	Checksum string `json:"checksum"`
	// The algorithm used to encrypt data files.
	EncryptionAlgo string `json:"encryptionAlgo"`
	// The public key used to encrypt data files.
	PublicKey []byte `json:"publicKey"`
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
	if _, err := hash.Write([]byte(index.EncryptionAlgo)); err != nil {
		return "", fmt.Errorf("writing encryption algo to hash: %w", err)
	}
	if _, err := hash.Write([]byte(index.PublicKey)); err != nil {
		return "", fmt.Errorf("writing public key to hash: %w", err)
	}

	keys := make([]string, 0, len(index.Items))
	for key := range index.Items {
		keys = append(keys, key)
	}
	// Sort map keys to ensure the same hash is computed every time.
	slices.Sort(keys)

	for _, key := range keys {
		bytesWritten, err := hash.Write([]byte(key))
		if err != nil {
			return "", fmt.Errorf("writing key to hash :%w", err)
		}
		if bytesWritten != len(key) {
			return "", fmt.Errorf("writing key to hash, expected to write %d bytes but wrote %d", len(key), bytesWritten)
		}

		for _, value := range index.Items[key] {
			bytesWritten, err = hash.Write([]byte(value))
			if err != nil {
				return "", fmt.Errorf("writing value to hash :%w", err)
			}
			if bytesWritten != len(value) {
				return "", fmt.Errorf("writing value to hash, expected to write %d bytes but wrote %d", len(key), bytesWritten)
			}
		}
	}

	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

// Writes the in memory index to disk.
func (writer *SnapshotWriter) Finish(senderPublicKey []byte) (indexFilePath string, err error) {
	items := make(map[string][]string)
	for resourceType, resourceIndex := range writer.index {
		items[resourceType] = resourceIndex.filePaths
	}

	index := Index{
		Version:        1,
		EncryptionAlgo: writer.crypto.Algo(),
		PublicKey:      senderPublicKey,
		Items:          items,
	}
	checksum, err := computeIndexChecksum(&index)
	if err != nil {
		return "", fmt.Errorf("computing index checksum: %w", err)
	}
	index.Checksum = checksum

	bytes, err := json.Marshal(index)
	if err != nil {
		return "", fmt.Errorf("json marshalling index: %w", err)
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
