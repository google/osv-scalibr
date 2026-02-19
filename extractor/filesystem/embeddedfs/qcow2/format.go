package qcow2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	// qcow2Magic represent magic bytes for .qcow2 files
	// For more information visit the link below:
	// https://www.qemu.org/docs/master/interop/qcow2.html
	qcow2Magic = 0x514649fb // 'QFI\xfb'
	sectorSize = 512
)

// header matches qcow2.h's QcowHeader layout exactly.
// The struct is read directly from on-disk bytes using binary.Read,
// so field order, sizes, and alignment must not change.
// Unused/reserved fields are kept (as blank identifiers) to preserve
// correct offsets, and fixed-width integer types (uint32/uint64) are
// used to match the QCOW2 specification precisely.
// Reference:
// https://github.com/qemu/qemu/blob/master/block/qcow2.h#L154
// https://www.qemu.org/docs/master/interop/qcow2.html
type header struct {
	Magic                 uint32   // 0-3
	Version               uint32   // 4-7
	_                     uint64   // 8-15
	_                     uint32   // 16-19
	ClusterBits           uint32   // 20-23
	Size                  uint64   // 24-31
	CryptMethod           uint32   // 32-35
	L1Size                uint32   // 36-39
	L1TableOffset         uint64   // 40-47
	RefcountTableOffset   uint64   // 48-55
	RefcountTableClusters uint32   // 56-59
	_                     uint32   // 60-63
	_                     uint64   // 64-71
	IncompatibleFeatures  uint64   // 72-79
	_                     uint64   // 80-87
	_                     uint64   // 88-95
	_                     uint32   // 96-99
	HeaderLength          uint32   // 100-103
	CompressionType       uint8    // 104
	_                     [7]uint8 // 105-111
}

// headerExtension represents a QCOW2 header extension
type headerExtension struct {
	Type   uint32
	Length uint32
	Data   []byte
}

// convertQCOW2ToRaw converts a QCOW2 file to a raw disk image.
func convertQCOW2ToRaw(inputPath string, outputPath string, password string) error {
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
	l1Table, err = readL1Table(header, inputFile)
	if err != nil {
		return fmt.Errorf("failed to read L1 table: %w", err)
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

// BitRangeMask creates a mask for extracting bits from start to end (inclusive)
func BitRangeMask(start, end uint64) uint64 {
	if start > 63 || end > 63 || start > end {
		panic("invalid bit range, must satisfy 0 <= start <= end <= 63")
	}
	width := end - start + 1
	return ((uint64(1) << width) - 1) << start
}

func alignUp(n, align uint64) uint64 {
	return (n + align - 1) & ^(align - 1)
}
