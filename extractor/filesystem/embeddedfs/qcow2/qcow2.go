// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package qcow2 provides an extractor for extracting software inventories from QEMU's QCOW2 disk images.
package qcow2

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/aead/serpent"
	"github.com/emmansun/gmsm/sm4"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/xts"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/embeddedfs/common"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// cipherMode, ivGen, and hashAlgorithm types for cipher mode parsing
type cipherMode string
type ivGen string
type hashAlgorithm string

const (
	// Name is the unique identifier for the qcow2 extractor.
	Name = "embeddedfs/qcow2"
	// qcow2Magic represent magic bytes for .qcow2 files
	// For more information visit the link below:
	// https://www.qemu.org/docs/master/interop/qcow2.html
	qcow2Magic                       = 0x514649fb // 'QFI\xfb'
	clusterSizeDefault               = 65536      // 64KiB
	sectorSize                       = 512
	luksMagic                        = "LUKS\xba\xbe"
	cryptoHeaderType                 = 0x0537be77
	luksDigestSize                   = 20
	luksKeyEnabled                   = 0x00AC71F3
	luksKeyDisabled                  = 0x0000DEAD
	cipherModeXTS      cipherMode    = "xts"
	cipherModeCBC      cipherMode    = "cbc"
	ivGenPlain         ivGen         = "plain"
	ivGenPlain64       ivGen         = "plain64"
	ivGenESSIV         ivGen         = "essiv"
	hashSHA1           hashAlgorithm = "sha1"
	hashSHA256         hashAlgorithm = "sha256"
)

// header matches qcow2.h's QcowHeader
// https://github.com/qemu/qemu/blob/master/block/qcow2.h#L154
// https://www.qemu.org/docs/master/interop/qcow2.html
type header struct {
	Magic                 uint32   // 0-3
	Version               uint32   // 4-7
	BackingFileOffset     uint64   // 8-15
	BackingFileSize       uint32   // 16-19
	ClusterBits           uint32   // 20-23
	Size                  uint64   // 24-31
	CryptMethod           uint32   // 32-35
	L1Size                uint32   // 36-39
	L1TableOffset         uint64   // 40-47
	RefcountTableOffset   uint64   // 48-55
	RefcountTableClusters uint32   // 56-59
	NbSnapshots           uint32   // 60-63
	SnapshotsOffset       uint64   // 64-71
	IncompatibleFeatures  uint64   // 72-79
	CompatibleFeatures    uint64   // 80-87
	AutoclearFeatures     uint64   // 88-95
	RefcountOrder         uint32   // 96-99
	HeaderLength          uint32   // 100-103
	CompressionType       uint8    // 104
	Padding               [7]uint8 // 105-111
}

// headerExtension represents a QCOW2 header extension
type headerExtension struct {
	Type   uint32
	Length uint32
	Data   []byte
}

// snapshot represents a QCOW2 snapshot
type snapshot struct {
	ID            uint64
	Name          string
	L1TableOffset uint64
	L1Size        uint32
}

// luksHeader represents the LUKS1 header (592 bytes)
type luksHeader struct {
	Magic              [6]byte
	Version            uint16
	CipherName         [32]byte // also called cipher_algo in block-luks.c
	CipherMode         [32]byte
	HashSpec           [32]byte // also called hash_algo in block-luks.c, used in pbkdf2
	PayloadOffset      uint32
	KeyBytes           uint32 // also called master_key_len in block-luks.c
	MKDigest           [20]byte
	MKDigestSalt       [32]byte
	MKDigestIterations uint32
	UUID               [40]byte
	KeySlots           [8]luksKeySlot
}

// luksKeySlot represents a LUKS key slot
type luksKeySlot struct {
	Active             uint32
	PasswordIterations uint32
	PasswordSalt       [32]byte
	KeyMaterialOffset  uint32
	Stripes            uint32
}

// cryptoConfig interface for encryption
type cryptoConfig interface {
	Decrypt(data []byte, guestOffset uint64) ([]byte, error)
	IsEncryptedOffset(offset uint64) bool
}

// legacyAESConfig for legacy AES encryption
type legacyAESConfig struct {
	cipher cipher.Block
}

// luksConfig for LUKS encryption
type luksConfig struct {
	masterKey      []byte
	cipherName     string
	cipherMode     cipherMode
	ivGen          ivGen
	ivHash         hashAlgorithm
	hashSpec       hashAlgorithm
	keyBytes       uint32
	sectorSize     uint64
	encryptedStart uint64
	dataCipher     *xts.Cipher  // Used for XTS mode
	essivCipher    cipher.Block // Used for ESSIV in CBC mode
}

// Extractor implements the filesystem.Extractor interface for qcow2.
type Extractor struct {
	// maxFileSizeBytes is the maximum size of an .qcow2 file that can be traversed.
	// If this limit is greater than zero and a file is encountered that is larger
	// than this limit, the file is ignored.
	maxFileSizeBytes int64
	// password is the password of an encrypted .qcow2 file
	password string
}

// New returns a new QCOW2 extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	maxSize := cfg.MaxFileSizeBytes
	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.QCOW2Config { return c.GetQcow2() })
	if specific.GetMaxFileSizeBytes() > 0 {
		maxSize = specific.GetMaxFileSizeBytes()
	}
	var password string
	if specific.GetPassword() != "" {
		password = specific.GetPassword()
	}
	return &Extractor{maxFileSizeBytes: maxSize, password: password}, nil
}

// Name returns the name of the extractor.
func (e *Extractor) Name() string {
	return Name
}

// Version returns the version of the extractor.
func (e *Extractor) Version() int {
	return 0
}

// Requirements returns the requirements for the extractor.
func (e *Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired checks if the file is a .qcow2 file based on its extension.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	if !strings.HasSuffix(strings.ToLower(path), ".qcow2") {
		return false
	}

	fileinfo, err := api.Stat()
	if err != nil {
		return false
	}

	if e.maxFileSizeBytes > 0 && fileinfo.Size() > e.maxFileSizeBytes {
		return false
	}

	return true
}

// Extract returns an Inventory with embedded filesystems which contains mount functions for each filesystem in the .qcow2 file.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	qcow2Path, err := input.GetRealPath()
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to get real path for %s: %w", input.Path, err)
	}

	// If called on a virtual FS, clean up the temporary directory
	if input.Root == "" {
		defer func() {
			dir := filepath.Dir(qcow2Path)
			if err := os.RemoveAll(dir); err != nil {
				fmt.Printf("os.RemoveAll(%q): %v\n", dir, err)
			}
		}()
	}

	// Create a temporary file for the raw disk image
	tmpRaw, err := os.CreateTemp("", "scalibr-qcow2-raw-*.raw")
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create temporary raw file: %w", err)
	}
	tmpRawPath := tmpRaw.Name()

	// Convert QCOW2 to raw
	// Snapshot feature is disabled for now due to complications but code still requires it
	// so we pass empty string.
	if err := convertQCOW2ToRaw(qcow2Path, tmpRawPath, e.password, ""); err != nil {
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, fmt.Errorf("failed to convert %s to raw image: %w", input.Path, err)
	}

	// Retrieve all partitions and the associated disk handle from the raw disk image.
	partitionList, disk, err := common.GetDiskPartitions(tmpRawPath)
	if err != nil {
		disk.Close()
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, err
	}

	// Create a reference counter for the temporary file
	var refCount int32
	var refMu sync.Mutex

	// Create an Embedded filesystem for each valid partition
	var embeddedFSs []*inventory.EmbeddedFS
	for i, p := range partitionList {
		partitionIndex := i + 1 // go-diskfs uses 1-based indexing
		getEmbeddedFS := common.NewPartitionEmbeddedFSGetter("qcow2", partitionIndex, p, disk, tmpRawPath, &refMu, &refCount)
		embeddedFSs = append(embeddedFSs, &inventory.EmbeddedFS{
			Path:          fmt.Sprintf("%s:%d", input.Path, partitionIndex),
			GetEmbeddedFS: getEmbeddedFS,
		})
	}
	return inventory.Inventory{EmbeddedFSs: embeddedFSs}, nil
}

// QCOW2 conversion functions

// convertQCOW2ToRaw converts a QCOW2 file to a raw disk image.
func convertQCOW2ToRaw(inputPath string, outputPath string, password string, snapshotStr string) error {
	if inputPath == "" {
		return errors.New("convertVMDKToRaw(): must supply an input file")
	}

	if outputPath == "" {
		return errors.New("convertVMDKToRaw(): must supply an output file")
	}

	inputFile, err := os.Open(inputPath)
	if err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	}
	defer inputFile.Close()

	fileInfo, err := inputFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}
	fileSize := uint64(fileInfo.Size())

	header, extensions, err := parseHeader(inputFile)
	if err != nil {
		return fmt.Errorf("failed to parse QCOW2 header: %w", err)
	}

	var crypto cryptoConfig
	if header.CryptMethod != 0 {
		if password == "" {
			return errors.New("password required for encrypted QCOW2 image")
		}
		crypto, err = setupEncryption(header, extensions, password, inputFile)
		if err != nil {
			return fmt.Errorf("failed to setup encryption: %w", err)
		}
	}

	if err := checkImageIntegrity(header, inputFile); err != nil {
		return fmt.Errorf("image validation failed: %w", err)
	}

	var l1Table []uint64
	if snapshotStr != "" {
		snapshots, err := listSnapshots(header, inputFile)
		if err != nil {
			return fmt.Errorf("failed to list snapshots: %w", err)
		}
		var selected *snapshot
		for _, snap := range snapshots {
			if snap.Name == snapshotStr {
				selected = &snap
				break
			}
		}
		if selected == nil {
			return fmt.Errorf("snapshot %q not found", snapshotStr)
		}
		l1Table, err = readSnapshotL1Table(selected, inputFile)
		if err != nil {
			return fmt.Errorf("failed to read snapshot L1 table: %w", err)
		}
	} else {
		l1Table, err = readL1Table(header, inputFile)
		if err != nil {
			return fmt.Errorf("failed to read L1 table: %w", err)
		}
	}

	outputFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	if err := writeRawImage(header, l1Table, inputFile, outputFile, crypto, fileSize); err != nil {
		return fmt.Errorf("conversion failed: %w", err)
	}

	if err := outputFile.Truncate(int64(header.Size)); err != nil {
		return fmt.Errorf("failed to truncate output file: %w", err)
	}

	return nil
}

// parseCipherMode parses <cipher-mode>-<iv-generator>[:<iv-hash>] format
func parseCipherMode(cMode string) (cipherMode, ivGen, hashAlgorithm, error) {
	parts := strings.Split(strings.ToLower(cMode), "-")
	if len(parts) < 2 {
		return "", "", "", fmt.Errorf("invalid cipher mode format: %s", cMode)
	}
	var mode cipherMode
	switch parts[0] {
	case "xts":
		mode = cipherModeXTS
	case "cbc":
		mode = cipherModeCBC
	default:
		return "", "", "", fmt.Errorf("unsupported cipher mode: %s", parts[0])
	}
	var ivgen ivGen
	var ivhash hashAlgorithm
	if strings.Contains(parts[1], ":") {
		// Handle <iv-generator>:<iv-hash>
		subparts := strings.Split(parts[1], ":")
		if len(subparts) != 2 {
			return "", "", "", fmt.Errorf("invalid iv-generator format: %s", parts[1])
		}
		ivgen = ivGen(subparts[0])
		ivhash = hashAlgorithm(subparts[1])
	} else {
		ivgen = ivGen(parts[1])
	}
	switch ivgen {
	case ivGenPlain, ivGenPlain64, ivGenESSIV:
		// Valid IV generators
	default:
		return "", "", "", fmt.Errorf("unsupported IV generator: %s", ivgen)
	}
	if ivgen == ivGenESSIV {
		if ivhash == "" {
			return "", "", "", errors.New("missing iv-hash for essiv mode")
		}
		if ivhash != hashSHA1 && ivhash != hashSHA256 {
			return "", "", "", fmt.Errorf("unsupported iv-hash: %s", ivhash)
		}
	} else {
		ivhash = "" // Ignore iv-hash for non-essiv, per dm-crypt compatibility
	}
	return mode, ivgen, ivhash, nil
}

// luksCipherNameLookup validates cipher name
func luksCipherNameLookup(cipherName string) (string, error) {
	if strings.HasPrefix(strings.ToLower(cipherName), "aes") {
		return "aes", nil
	}
	if strings.HasPrefix(strings.ToLower(cipherName), "serpent") {
		return "serpent", nil
	}
	if strings.HasPrefix(strings.ToLower(cipherName), "sm4") {
		return "sm4", nil
	}
	return "", fmt.Errorf("unsupported cipher algorithm: %s", cipherName)
}

// luksHashNameLookup maps LUKS hash names to Go hash functions
func luksHashNameLookup(hashName hashAlgorithm) (func() hash.Hash, int, error) {
	switch hashName {
	case hashSHA1:
		return sha1.New, sha1.Size, nil
	case hashSHA256:
		return sha256.New, sha256.Size, nil
	default:
		return nil, 0, fmt.Errorf("unsupported hash algorithm: %s", hashName)
	}
}

// IVGenAlgorithm defines the interface for IV generation
type IVGenAlgorithm interface {
	Calculate(sector uint64, niv int) ([]byte, error)
}

// PlainIVGen implements plain IV generation (32-bit LE sector)
type PlainIVGen struct{}

// Calculate generates plain IV
func (p *PlainIVGen) Calculate(sector uint64, niv int) ([]byte, error) {
	iv := make([]byte, niv)
	ivprefix := min(4, niv)
	shortsector := uint32(sector & 0xffffffff)
	var sectorBytes [4]byte
	binary.LittleEndian.PutUint32(sectorBytes[:], shortsector)
	copy(iv, sectorBytes[:ivprefix])
	if ivprefix < niv {
		for i := ivprefix; i < niv; i++ {
			iv[i] = 0
		}
	}
	return iv, nil
}

// Plain64IVGen implements plain64 IV generation (64-bit LE sector)
type Plain64IVGen struct{}

// Calculate generates plain64 IV
func (p *Plain64IVGen) Calculate(sector uint64, niv int) ([]byte, error) {
	iv := make([]byte, niv)
	ivprefix := min(8, niv)
	var sectorBytes [8]byte
	binary.LittleEndian.PutUint64(sectorBytes[:], sector)
	copy(iv, sectorBytes[:ivprefix])
	if ivprefix < niv {
		for i := ivprefix; i < niv; i++ {
			iv[i] = 0
		}
	}
	return iv, nil
}

// ESSIVGen implements ESSIV IV generation
type ESSIVGen struct {
	cipher cipher.Block // AES-ECB cipher for ESSIV
}

// Calculate generates ESSIV IV
func (e *ESSIVGen) Calculate(sector uint64, niv int) ([]byte, error) {
	ndata := e.cipher.BlockSize()
	data := make([]byte, ndata)
	ivprefix := min(ndata, niv)
	var sectorBytes [8]byte
	binary.LittleEndian.PutUint64(sectorBytes[:], sector)
	copy(data, sectorBytes[:min(8, ndata)])
	if 8 < ndata {
		for i := 8; i < ndata; i++ {
			data[i] = 0
		}
	}
	dst := make([]byte, ndata)
	e.cipher.Encrypt(dst, data)
	iv := make([]byte, niv)
	copy(iv, dst[:ivprefix])
	if ivprefix < niv {
		for i := ivprefix; i < niv; i++ {
			iv[i] = 0
		}
	}
	return iv, nil
}

// initESSIV initializes ESSIV cipher with a salt derived from the key
func initESSIV(key []byte, ivHash hashAlgorithm, normalizedCipher string) (cipher.Block, error) {
	hashFunc, digestSize, err := luksHashNameLookup(ivHash)
	if err != nil {
		return nil, err
	}
	// dm-crypt quirk: ESSIV cipher key length matches hash digest length
	keyLen := digestSize
	salt := make([]byte, keyLen)
	h := hashFunc()
	h.Write(key)
	copy(salt, h.Sum(nil)[:min(digestSize, keyLen)])
	switch normalizedCipher {
	case "aes":
		essivCipher, err := aes.NewCipher(salt)
		if err != nil {
			return nil, fmt.Errorf("failed to create ESSIV cipher: %w", err)
		}
		return essivCipher, nil
	case "serpent":
		essivCipher, err := serpent.NewCipher(salt)
		if err != nil {
			return nil, fmt.Errorf("failed to create ESSIV cipher: %w", err)
		}
		return essivCipher, nil
	case "sm4":
		essivCipher, err := sm4.NewCipher(salt)
		if err != nil {
			return nil, fmt.Errorf("failed to create ESSIV cipher: %w", err)
		}
		return essivCipher, nil
	}
	return nil, fmt.Errorf("unknown ESSIV cipher: %s", normalizedCipher)
}

// initXTS initializes XTS cipher with a key
func initXTS(key []byte, normalizedCipher string) (*xts.Cipher, error) {
	var cipherFunc func([]byte) (cipher.Block, error)
	switch normalizedCipher {
	case "aes":
		cipherFunc = aes.NewCipher
	case "serpent":
		cipherFunc = serpent.NewCipher
	case "sm4":
		cipherFunc = sm4.NewCipher
	default:
		return nil, fmt.Errorf("unknown XTS cipher: %s", normalizedCipher)
	}
	tmpCipher, err := xts.NewCipher(cipherFunc, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XTS cipher: %w", err)
	}
	return tmpCipher, nil
}

// BitRangeMask creates a mask for extracting bits from start to end (inclusive)
func BitRangeMask(start, end uint64) uint64 {
	if start > 63 || end > 63 || start > end {
		panic("invalid bit range, must satisfy 0 <= start <= end <= 63")
	}
	width := end - start + 1
	return ((uint64(1) << width) - 1) << start
}

// decompressRawDeflate decompresses raw deflate data to the specified size
func decompressRawDeflate(compressed []byte, decompressedSize uint64) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(compressed))
	defer r.Close()
	decompressed := make([]byte, decompressedSize)
	if _, err := io.ReadFull(r, decompressed); err != nil {
		return nil, fmt.Errorf("failed to decompress raw deflate: %w", err)
	}
	return decompressed, nil
}

// diffuse implements cryptsetup’s diffuse() from af.c
func diffuse(src []byte, dst []byte, hashName hashAlgorithm) error {
	if len(src) != len(dst) {
		return errors.New("diffuse: src and dst length mismatch")
	}
	hashCtor, digestSize, err := luksHashNameLookup(hashName)
	if err != nil {
		return err
	}
	size := len(src)
	blocks := size / digestSize
	rem := size % digestSize

	for i := range blocks {
		h := hashCtor()
		var ivBytes [4]byte
		binary.BigEndian.PutUint32(ivBytes[:], uint32(i))
		h.Write(ivBytes[:])
		h.Write(src[i*digestSize : (i+1)*digestSize])
		sum := h.Sum(nil)
		copy(dst[i*digestSize:(i+1)*digestSize], sum[:digestSize])
	}
	if rem > 0 {
		i := blocks
		h := hashCtor()
		var ivBytes [4]byte
		binary.BigEndian.PutUint32(ivBytes[:], uint32(i))
		h.Write(ivBytes[:])
		h.Write(src[i*digestSize : i*digestSize+rem])
		sum := h.Sum(nil)
		copy(dst[i*digestSize:], sum[:rem])
	}
	return nil
}

// afMerge implements cryptsetup’s AF_merge
func afMerge(split []byte, masterKeyLen int, stripes int, hashName hashAlgorithm) ([]byte, error) {
	if masterKeyLen <= 0 || stripes <= 0 {
		return nil, errors.New("invalid masterKeyLen or stripes")
	}
	if len(split) != masterKeyLen*stripes {
		return nil, fmt.Errorf("AFmerge failed: split length %d does not match masterKeyLen %d * stripes %d", len(split), masterKeyLen, stripes)
	}
	if stripes == 1 {
		out := make([]byte, masterKeyLen)
		copy(out, split[:masterKeyLen])
		return out, nil
	}

	bufblock := make([]byte, masterKeyLen)
	tmp := make([]byte, masterKeyLen)

	for s := range stripes - 1 {
		stripe := split[s*masterKeyLen : (s+1)*masterKeyLen]
		for i := range masterKeyLen {
			bufblock[i] ^= stripe[i]
		}
		if err := diffuse(bufblock, tmp, hashName); err != nil {
			return nil, fmt.Errorf("AFmerge failed: diffuse error: %w", err)
		}
		copy(bufblock, tmp)
	}

	last := split[(stripes-1)*masterKeyLen : stripes*masterKeyLen]
	out := make([]byte, masterKeyLen)
	for i := range masterKeyLen {
		out[i] = last[i] ^ bufblock[i]
	}
	return out, nil
}

// getIVGen returns the appropriate IV generator based on luksConfig
func (c *luksConfig) getIVGen() (IVGenAlgorithm, error) {
	switch c.ivGen {
	case ivGenPlain:
		return &PlainIVGen{}, nil
	case ivGenPlain64:
		return &Plain64IVGen{}, nil
	case ivGenESSIV:
		if c.essivCipher == nil {
			return nil, errors.New("ESSIV cipher not initialized")
		}
		return &ESSIVGen{cipher: c.essivCipher}, nil
	default:
		return nil, fmt.Errorf("unsupported IV generator: %s", c.ivGen)
	}
}

// decryptData decrypts data using the configured cipher and IV generator
func (c *luksConfig) decryptData(data []byte, guestOffset uint64) ([]byte, error) {
	if len(data)%int(c.sectorSize) != 0 {
		return nil, fmt.Errorf("data size %d not sector-aligned", len(data))
	}
	result := make([]byte, len(data))
	ivgen, err := c.getIVGen()
	if err != nil {
		return nil, err
	}
	var blockCipher cipher.Block
	if c.cipherMode != cipherModeXTS {
		switch c.cipherName {
		case "aes":
			blockCipher, err = aes.NewCipher(c.masterKey)
		case "serpent":
			blockCipher, err = serpent.NewCipher(c.masterKey)
		case "sm4":
			blockCipher, err = sm4.NewCipher(c.masterKey)
		default:
			return nil, fmt.Errorf("unsupported cipher: %s", c.cipherName)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create cipher: %w", err)
		}
	}
	for i := 0; i < len(data); i += int(c.sectorSize) {
		sectorNum := guestOffset/c.sectorSize + uint64(i/int(c.sectorSize))
		if c.cipherMode == cipherModeXTS {
			if c.dataCipher == nil {
				return nil, errors.New("XTS cipher not initialized")
			}
			iv, err := ivgen.Calculate(sectorNum, 16)
			if err != nil {
				return nil, fmt.Errorf("failed to generate XTS tweak: %w", err)
			}
			// XTS uses the IV as a tweak, applied per sector
			c.dataCipher.Decrypt(result[i:i+int(c.sectorSize)], data[i:i+int(c.sectorSize)], binary.LittleEndian.Uint64(iv[:8]))
		} else if c.cipherMode == cipherModeCBC {
			iv, err := ivgen.Calculate(sectorNum, blockCipher.BlockSize())
			if err != nil {
				return nil, fmt.Errorf("failed to generate CBC IV: %w", err)
			}
			decrypter := cipher.NewCBCDecrypter(blockCipher, iv)
			decrypter.CryptBlocks(result[i:i+int(c.sectorSize)], data[i:i+int(c.sectorSize)])
		} else {
			return nil, fmt.Errorf("unsupported cipher mode: %s", c.cipherMode)
		}
	}
	return result, nil
}

func (c *luksConfig) Decrypt(data []byte, guestOffset uint64) ([]byte, error) {
	return c.decryptData(data, guestOffset)
}

func (c *luksConfig) IsEncryptedOffset(offset uint64) bool {
	return offset >= c.encryptedStart
}

func (c *legacyAESConfig) Decrypt(data []byte, guestOffset uint64) ([]byte, error) {
	if len(data)%sectorSize != 0 {
		return nil, fmt.Errorf("data size %d not sector-aligned", len(data))
	}
	result := make([]byte, len(data))
	for i := 0; i < len(data); i += sectorSize {
		sectorNum := guestOffset/sectorSize + uint64(i/sectorSize)
		iv := make([]byte, c.cipher.BlockSize())
		binary.LittleEndian.PutUint64(iv, sectorNum)
		decrypter := cipher.NewCBCDecrypter(c.cipher, iv)
		decrypter.CryptBlocks(result[i:i+sectorSize], data[i:i+sectorSize])
	}
	return result, nil
}

func (c *legacyAESConfig) IsEncryptedOffset(offset uint64) bool {
	return true
}

func parseHeader(reader io.Reader) (*header, []headerExtension, error) {
	var h header
	if err := binary.Read(reader, binary.BigEndian, &h); err != nil {
		return nil, nil, fmt.Errorf("failed to read header: %w", err)
	}
	if h.Magic != qcow2Magic {
		return nil, nil, fmt.Errorf("invalid QCOW2 magic: 0x%x", h.Magic)
	}
	if h.Version < 2 || h.Version > 3 {
		return nil, nil, fmt.Errorf("unsupported QCOW2 version: %d", h.Version)
	}
	if h.CryptMethod > 2 {
		return nil, nil, fmt.Errorf("unsupported crypt method: %d", h.CryptMethod)
	}
	if h.IncompatibleFeatures&0x1 != 0 {
		return nil, nil, errors.New("unsupported: external data file")
	}
	if h.CompressionType != 0 {
		return nil, nil, fmt.Errorf("unsupported compression type: %d (only zlib supported)", h.CompressionType)
	}

	if h.Version >= 3 && h.HeaderLength > 112 {
		if _, err := reader.(io.Seeker).Seek(int64(h.HeaderLength), io.SeekStart); err != nil {
			return nil, nil, fmt.Errorf("failed to seek to extensions: %w", err)
		}
	}

	var extensions []headerExtension
	for {
		var ext headerExtension
		if err := binary.Read(reader, binary.BigEndian, &ext.Type); err != nil {
			return nil, nil, fmt.Errorf("failed to read extension type: %w", err)
		}
		if ext.Type == 0 {
			break
		}
		if err := binary.Read(reader, binary.BigEndian, &ext.Length); err != nil {
			return nil, nil, fmt.Errorf("failed to read extension length: %w", err)
		}
		ext.Data = make([]byte, ext.Length)
		if _, err := io.ReadFull(reader, ext.Data); err != nil {
			return nil, nil, fmt.Errorf("failed to read extension data: %w", err)
		}
		if pad := (8 - (ext.Length % 8)) % 8; pad > 0 {
			_, err := io.ReadFull(reader, make([]byte, pad))
			if err != nil {
				return nil, nil, fmt.Errorf("failed to read extension padding: %w", err)
			}
		}
		extensions = append(extensions, ext)
	}

	return &h, extensions, nil
}

// setupEncryption configures LUKS encryption
func setupEncryption(header *header, extensions []headerExtension, password string, reader io.Reader) (cryptoConfig, error) {
	if header.CryptMethod == 0 {
		return nil, nil
	}
	if password == "" {
		return nil, errors.New("password required for encrypted image")
	}

	if header.CryptMethod == 1 {
		key := make([]byte, 16)
		copy(key, []byte(password))
		blockCipher, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}
		return &legacyAESConfig{cipher: blockCipher}, nil
	}

	var cryptoExt *headerExtension
	for _, ext := range extensions {
		if ext.Type == cryptoHeaderType {
			cryptoExt = &ext
			break
		}
	}
	if cryptoExt == nil {
		return nil, errors.New("LUKS crypto header extension missing")
	}

	var extData struct {
		Offset uint64
		Length uint64
	}
	if err := binary.Read(bytes.NewReader(cryptoExt.Data), binary.BigEndian, &extData); err != nil {
		return nil, fmt.Errorf("failed to parse crypto extension: %w", err)
	}
	if _, err := reader.(*os.File).Seek(int64(extData.Offset), io.SeekStart); err != nil {
		return nil, fmt.Errorf("failed to seek to LUKS header at 0x%x: %w", extData.Offset, err)
	}

	var luks luksHeader
	if err := binary.Read(reader, binary.BigEndian, &luks); err != nil {
		return nil, fmt.Errorf("failed to read LUKS header: %w", err)
	}
	if string(luks.Magic[:]) != luksMagic {
		return nil, fmt.Errorf("invalid LUKS magic: %x", luks.Magic)
	}
	if luks.Version != 1 {
		return nil, fmt.Errorf("unsupported LUKS version: %d", luks.Version)
	}

	cipherName := string(bytes.Trim(luks.CipherName[:], "\x00"))
	cipherMode := string(bytes.Trim(luks.CipherMode[:], "\x00"))
	hashSpec := string(bytes.Trim(luks.HashSpec[:], "\x00"))

	// Validate cipher name
	normalizedCipher, err := luksCipherNameLookup(cipherName)
	if err != nil {
		return nil, fmt.Errorf("cipher name validation failed: %w", err)
	}

	// Parse cipher mode
	mode, ivgen, ivhash, err := parseCipherMode(cipherMode)
	if err != nil {
		return nil, fmt.Errorf("cipher mode parsing failed: %w", err)
	}

	// Validate hash spec
	hashFunc, _, err := luksHashNameLookup(hashAlgorithm(hashSpec))
	if err != nil {
		return nil, fmt.Errorf("hash spec validation failed: %w", err)
	}

	var masterKey []byte
	var essivCipher cipher.Block
	for _, slot := range luks.KeySlots {
		if slot.Active != luksKeyEnabled {
			continue
		}

		keyMaterialSize := int(luks.KeyBytes) * int(slot.Stripes)
		if keyMaterialSize%16 != 0 {
			continue
		}
		keyMaterialOffset := int64(extData.Offset) + int64(slot.KeyMaterialOffset)*sectorSize
		if _, err := reader.(*os.File).Seek(keyMaterialOffset, io.SeekStart); err != nil {
			continue
		}
		keyMaterial := make([]byte, keyMaterialSize)
		if _, err := io.ReadFull(reader, keyMaterial); err != nil {
			continue
		}

		derivedKey := pbkdf2.Key([]byte(password), slot.PasswordSalt[:], int(slot.PasswordIterations), int(luks.KeyBytes), hashFunc)

		if ivgen == ivGenESSIV {
			var err error
			essivCipher, err = initESSIV(derivedKey, ivhash, normalizedCipher)
			if err != nil {
				continue
			}
		}

		// Initialize data cipher for XTS if needed
		var dataCipher *xts.Cipher
		if mode == cipherModeXTS {
			var err error
			dataCipher, err = initXTS(derivedKey, normalizedCipher)
			if err != nil {
				continue
			}
		}

		// Decrypt key material using the same cipher mode and IV generator as payload
		config := &luksConfig{
			masterKey:   derivedKey,
			cipherName:  cipherName,
			cipherMode:  mode,
			ivGen:       ivgen,
			ivHash:      ivhash,
			hashSpec:    hashAlgorithm(hashSpec),
			keyBytes:    luks.KeyBytes,
			sectorSize:  sectorSize,
			dataCipher:  dataCipher,
			essivCipher: essivCipher,
		}
		splitKey, err := config.decryptData(keyMaterial, uint64(slot.KeyMaterialOffset))
		if err != nil {
			continue
		}

		// Reconstruct master key
		masterKeyCandidate, err := afMerge(splitKey, int(luks.KeyBytes), int(slot.Stripes), hashAlgorithm(hashSpec))
		if err != nil {
			continue
		}

		// Verify master key
		mkDigestCandidate := pbkdf2.Key(masterKeyCandidate, luks.MKDigestSalt[:], int(luks.MKDigestIterations), luksDigestSize, hashFunc)
		if bytes.Equal(mkDigestCandidate, luks.MKDigest[:]) {
			masterKey = masterKeyCandidate
			break
		}
	}
	if masterKey == nil {
		return nil, errors.New("no valid key slot found")
	}

	// Verify master key length
	masterKeyLen := int(luks.KeyBytes)
	if len(masterKey) != masterKeyLen {
		return nil, fmt.Errorf("invalid master key length %d for %s/%s (expected %d)", len(masterKey), cipherName, mode, masterKeyLen)
	}

	// Initialize data cipher
	var dataCipher *xts.Cipher
	if mode == cipherModeXTS {
		var err error
		dataCipher, err = initXTS(masterKey, normalizedCipher)
		if err != nil {
			return nil, fmt.Errorf("failed to create XTS cipher: %w", err)
		}
	}

	// Initialize ESSIV cipher for payload decryption
	if ivgen == ivGenESSIV {
		var err error
		essivCipher, err = initESSIV(masterKey, ivhash, normalizedCipher)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize ESSIV cipher for payload: %w", err)
		}
	}

	return &luksConfig{
		masterKey:      masterKey,
		cipherName:     cipherName,
		cipherMode:     mode,
		ivGen:          ivgen,
		ivHash:         ivhash,
		hashSpec:       hashAlgorithm(hashSpec),
		keyBytes:       luks.KeyBytes,
		sectorSize:     sectorSize,
		encryptedStart: alignUp(extData.Offset+extData.Length, 1<<header.ClusterBits),
		dataCipher:     dataCipher,
		essivCipher:    essivCipher,
	}, nil
}

func readL1Table(header *header, reader io.ReaderAt) ([]uint64, error) {
	l1Table := make([]uint64, header.L1Size)
	buf := make([]byte, header.L1Size*8)
	if _, err := reader.ReadAt(buf, int64(header.L1TableOffset)); err != nil {
		return nil, fmt.Errorf("failed to read L1 table: %w", err)
	}
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, l1Table); err != nil {
		return nil, fmt.Errorf("failed to parse L1 table: %w", err)
	}
	return l1Table, nil
}

func readL2Table(l1Entry uint64, header *header, reader io.ReaderAt) ([]uint64, error) {
	if l1Entry == 0 {
		return nil, nil
	}
	clusterSize := uint64(1) << header.ClusterBits
	isCompressed := (l1Entry & (1 << 62)) != 0
	var offset uint64
	if isCompressed {
		x := 62 - (header.ClusterBits - 8)
		offset = l1Entry & BitRangeMask(0, uint64(x-1))
	} else {
		offset = l1Entry & BitRangeMask(9, 55)
	}
	buf := make([]byte, clusterSize)
	if _, err := reader.ReadAt(buf, int64(offset)); err != nil {
		return nil, fmt.Errorf("failed to read L2 table at offset 0x%x: %w", offset, err)
	}
	l2Table := make([]uint64, clusterSize/8)
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, l2Table); err != nil {
		return nil, fmt.Errorf("failed to parse L2 table: %w", err)
	}
	return l2Table, nil
}

func readCluster(l2Entry uint64, header *header, reader io.ReaderAt, crypto cryptoConfig, fileSize uint64, guestOffset uint64) ([]byte, error) {
	clusterSize := uint64(1) << header.ClusterBits
	if l2Entry == 0 {
		return bytes.Repeat([]byte{0}, int(clusterSize)), nil
	}
	isCompressed := (l2Entry & (1 << 62)) != 0
	var offset uint64
	if isCompressed {
		x := 62 - (header.ClusterBits - 8)
		offset = l2Entry & BitRangeMask(0, uint64(x-1))
		nbSectors := ((l2Entry >> x) & 0xff) + 1
		compressedSize := nbSectors * sectorSize
		if offset+compressedSize > fileSize {
			difference := offset + compressedSize - fileSize
			compressedSize -= difference
		}
		data := make([]byte, compressedSize)
		if _, err := reader.ReadAt(data, int64(offset)); err != nil {
			return nil, fmt.Errorf("failed to read compressed cluster at offset 0x%x: %w", offset, err)
		}
		decompressed, err := decompressRawDeflate(data, clusterSize)
		if err != nil {
			return nil, fmt.Errorf("failed to decompress cluster: %w", err)
		}
		return decompressed, nil
	}
	offset = l2Entry & BitRangeMask(9, 55)
	if offset+clusterSize > fileSize {
		return nil, fmt.Errorf("cluster offset 0x%x + size %d exceeds file size %d", offset, clusterSize, fileSize)
	}
	data := make([]byte, clusterSize)
	if _, err := reader.ReadAt(data, int64(offset)); err != nil {
		return nil, fmt.Errorf("failed to read cluster at offset 0x%x: %w", offset, err)
	}
	if crypto != nil {
		var err error
		if header.CryptMethod == 1 {
			data, err = crypto.Decrypt(data, guestOffset) // legacy AES
		} else {
			data, err = crypto.Decrypt(data, offset) // LUKS
		}
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt cluster at guest offset 0x%x: %w", guestOffset, err)
		}
	}
	return data, nil
}

func checkImageIntegrity(header *header, reader io.ReaderAt) error {
	clusterSize := uint64(1) << header.ClusterBits
	if header.L1TableOffset%clusterSize != 0 {
		return errors.New("L1 table offset not cluster-aligned")
	}
	if header.RefcountTableOffset%clusterSize != 0 {
		return errors.New("refcount table offset not cluster-aligned")
	}
	refcountTable, err := readRefcountTable(header, reader)
	if err != nil {
		return fmt.Errorf("failed to read refcount table: %w", err)
	}
	for _, rtEntry := range refcountTable {
		if rtEntry == 0 {
			continue
		}
		_, err := readRefcountBlock(rtEntry, header, reader)
		if err != nil {
			continue
		}
	}
	return nil
}

func readRefcountTable(header *header, reader io.ReaderAt) ([]uint64, error) {
	clusterSize := uint64(1) << header.ClusterBits
	buf := make([]byte, header.RefcountTableClusters*uint32(clusterSize))
	if _, err := reader.ReadAt(buf, int64(header.RefcountTableOffset)); err != nil {
		return nil, fmt.Errorf("failed to read refcount table: %w", err)
	}
	refcountTable := make([]uint64, header.RefcountTableClusters*uint32(clusterSize/8))
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, refcountTable); err != nil {
		return nil, fmt.Errorf("failed to parse refcount table: %w", err)
	}
	return refcountTable, nil
}

func readRefcountBlock(rtEntry uint64, header *header, reader io.ReaderAt) ([]uint16, error) {
	clusterSize := uint64(1) << header.ClusterBits
	buf := make([]byte, clusterSize)
	if _, err := reader.ReadAt(buf, int64(rtEntry)); err != nil {
		return nil, fmt.Errorf("failed to read refcount block: %w", err)
	}
	refcountBlock := make([]uint16, clusterSize/2)
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, refcountBlock); err != nil {
		return nil, fmt.Errorf("failed to parse refcount block: %w", err)
	}
	return refcountBlock, nil
}

func listSnapshots(header *header, reader io.ReaderAt) ([]snapshot, error) {
	if header.NbSnapshots == 0 {
		return nil, nil
	}
	buf := make([]byte, header.NbSnapshots*72)
	if _, err := reader.ReadAt(buf, int64(header.SnapshotsOffset)); err != nil {
		return nil, fmt.Errorf("failed to read snapshot table: %w", err)
	}
	var snapshots []snapshot
	readerBuf := bytes.NewReader(buf)
	for i := range header.NbSnapshots {
		var snap struct {
			L1TableOffset uint64
			L1Size        uint32
			ID            uint16
			NameLength    uint16
		}
		if err := binary.Read(readerBuf, binary.BigEndian, &snap); err != nil {
			return nil, fmt.Errorf("failed to parse snapshot %d: %w", i, err)
		}
		name := make([]byte, snap.NameLength)
		if _, err := io.ReadFull(readerBuf, name); err != nil {
			return nil, fmt.Errorf("failed to read snapshot name: %w", err)
		}
		if _, err := readerBuf.Seek(int64(72-snap.NameLength-32), io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("failed to skip snapshot padding: %w", err)
		}
		snapshots = append(snapshots, snapshot{
			ID:            uint64(snap.ID),
			Name:          string(name),
			L1TableOffset: snap.L1TableOffset,
			L1Size:        snap.L1Size,
		})
	}
	return snapshots, nil
}

func readSnapshotL1Table(snap *snapshot, reader io.ReaderAt) ([]uint64, error) {
	l1Table := make([]uint64, snap.L1Size)
	buf := make([]byte, snap.L1Size*8)
	if _, err := reader.ReadAt(buf, int64(snap.L1TableOffset)); err != nil {
		return nil, fmt.Errorf("failed to read snapshot L1 table: %w", err)
	}
	if err := binary.Read(bytes.NewReader(buf), binary.BigEndian, l1Table); err != nil {
		return nil, fmt.Errorf("failed to parse snapshot L1 table: %w", err)
	}
	return l1Table, nil
}

func writeRawImage(header *header, l1Table []uint64, reader io.ReaderAt, writer io.Writer, crypto cryptoConfig, fileSize uint64) error {
	clusterSize := uint64(1) << header.ClusterBits
	entriesPerL2 := clusterSize / 8
	for guestOffset := uint64(0); guestOffset < header.Size; guestOffset += clusterSize {
		l1Index := guestOffset / (clusterSize * entriesPerL2)
		if l1Index >= uint64(len(l1Table)) {
			return fmt.Errorf("L1 index %d out of bounds", l1Index)
		}
		l2Table, err := readL2Table(l1Table[l1Index], header, reader)
		if err != nil {
			return fmt.Errorf("failed to read L2 table at guest offset 0x%x: %w", guestOffset, err)
		}
		if l2Table == nil {
			if _, err := writer.Write(bytes.Repeat([]byte{0}, int(clusterSize))); err != nil {
				return fmt.Errorf("failed to write zeros at guest offset 0x%x: %w", guestOffset, err)
			}
			continue
		}
		l2Index := (guestOffset / clusterSize) % entriesPerL2
		cluster, err := readCluster(l2Table[l2Index], header, reader, crypto, fileSize, guestOffset)
		if err != nil {
			return fmt.Errorf("failed to read cluster at guest offset 0x%x: %w", guestOffset, err)
		}
		if _, err := writer.Write(cluster); err != nil {
			return fmt.Errorf("failed to write cluster at guest offset 0x%x: %w", guestOffset, err)
		}
	}
	return nil
}

func alignUp(n, align uint64) uint64 {
	return (n + align - 1) & ^(align - 1)
}
