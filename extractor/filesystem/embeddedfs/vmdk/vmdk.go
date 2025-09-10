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

// Package vmdk provides an extractor for extracting software inventories from VMDK disk images
package vmdk

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/diskfs/go-diskfs"
	diskfsfilesystem "github.com/diskfs/go-diskfs/filesystem"
	"github.com/diskfs/go-diskfs/filesystem/fat32"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/masahiro331/go-ext4-filesystem/ext4"
)

const (
	// Name is the unique identifier for the vmdk extractor.
	Name = "embeddedfs/vmdk"
	// SectorSize is the default sector size (512 bytes).
	SectorSize = 512
	// SparseMagic is always 'KDMV'.
	SparseMagic = 0x564d444b
	// GDAtEnd indicates that the Grain Directory is stored in the footer at the end of the VMDK file.
	GDAtEnd = 0xFFFFFFFFFFFFFFFF
	// DefaultGrainSec is default sectors if header invalid (64KiB).
	DefaultGrainSec  = 128
	defaultPageSize  = 1024 * 1024
	defaultCacheSize = 100 * 1024 * 1024
)

// sparseExtentHeader defines the VMDK sparse extent header structure.
type sparseExtentHeader struct {
	MagicNumber        uint32
	Version            uint32
	Flags              uint32
	Capacity           uint64
	GrainSize          uint64
	DescriptorOffset   uint64
	DescriptorSize     uint64
	NumGTEsPerGT       uint32
	RGDOffset          uint64
	GDOffset           uint64
	OverHead           uint64
	UncleanShutdown    byte
	SingleEndLineChar  byte
	NonEndLineChar     byte
	DoubleEndLineChar1 byte
	DoubleEndLineChar2 byte
	CompressAlgorithm  uint16
	Pad                [433]byte
}

// gdgtInfo holds GD/GT allocation information.
type gdgtInfo struct {
	GTEs      uint64
	GTs       uint32
	GDsectors uint32
	GTsectors uint32
	gd        []uint32
}

// Extractor implements the filesystem.Extractor interface for vmdk.
type Extractor struct{}

// New returns a new VMDK extractor.
func New() filesystem.Extractor {
	return &Extractor{}
}

// NewDefault returns a New()
func NewDefault() filesystem.Extractor {
	return New()
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

// FileRequired checks if the file is a .vmdk file based on its extension.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	return strings.HasSuffix(strings.ToLower(path), ".vmdk")
}

// Extract returns an Inventory with embedded filesystems which contains mount functions for each filesystem in the .vmdk file.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	vmdkPath, err := input.GetRealPath()
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to get real path for %s: %w", input.Path, err)
	}
	// If called on a virtual FS, clean up the temporary directory
	if input.Root == "" {
		defer func() {
			dir := filepath.Dir(vmdkPath)
			if err := os.RemoveAll(dir); err != nil {
				fmt.Printf("os.RemoveAll(%q): %v\n", dir, err)
			}
		}()
	}

	// Create a temporary file for the raw disk image
	tmpRaw, err := os.CreateTemp("", "scalibr-vmdk-raw-*.raw")
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create temporary raw file: %w", err)
	}
	tmpRawPath := tmpRaw.Name()

	// Convert VMDK to raw
	if err := convertVMDKToRaw(vmdkPath, tmpRawPath); err != nil {
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, fmt.Errorf("failed to convert %s to raw image: %w", vmdkPath, err)
	}

	// Open the raw disk image with go-diskfs
	disk, err := diskfs.Open(tmpRawPath, diskfs.WithOpenMode(diskfs.ReadOnly))
	if err != nil {
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, fmt.Errorf("failed to open raw disk image %s: %w", tmpRawPath, err)
	}

	// Get the partition table
	partitions, err := disk.GetPartitionTable()
	if err != nil {
		disk.Close()
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, fmt.Errorf("failed to get partition table: %w", err)
	}
	partitionList := partitions.GetPartitions()
	if len(partitionList) == 0 {
		disk.Close()
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, errors.New("no partitions found in raw disk image")
	}

	// Create a reference counter for the temporary file
	var refCount int32
	var refMu sync.Mutex

	// Create an Embedded filesystem for each valid partition
	var embeddedFSs []*inventory.EmbeddedFS
	for i, p := range partitionList {
		partitionIndex := i + 1 // go-diskfs uses 1-based indexing
		getEmbeddedFS := func(ctx context.Context) (scalibrfs.FS, error) {
			// Open raw image for ext4 parser
			f, err := os.Open(tmpRawPath)
			if err != nil {
				return nil, fmt.Errorf("failed to open raw image %s: %w", tmpRawPath, err)
			}

			// Get partition offset and size (They are already multiplied by sector size)
			offset := p.GetStart()
			size := p.GetSize()
			section := io.NewSectionReader(f, offset, size)
			fsType := detectFilesystem(section, 0)

			switch fsType {
			case "ext4":
				fs, err := ext4.NewFS(*section, nil)
				if err != nil {
					f.Close()
					return nil, fmt.Errorf("failed to create ext4 filesystem for partition %d: %w", partitionIndex, err)
				}
				refMu.Lock()
				refCount++
				refMu.Unlock()
				ext4fs := &ext4FS{
					fs:         fs,
					file:       f,
					tmpRawPath: tmpRawPath,
					refCount:   &refCount,
					refMu:      &refMu,
				}
				return ext4fs, nil
			case "FAT32":
				f.Close() // Close the file as GetFilesystem reopens it
				fs, err := disk.GetFilesystem(partitionIndex)
				if err != nil {
					return nil, fmt.Errorf("failed to get filesystem for partition %d: %w", partitionIndex, err)
				}
				fat32fs, ok := fs.(*fat32.FileSystem)
				if !ok {
					return nil, fmt.Errorf("partition %d is not a FAT32 filesystem", partitionIndex)
				}
				f, err = os.Open(tmpRawPath)
				if err != nil {
					return nil, fmt.Errorf("failed to reopen raw image %s: %w", tmpRawPath, err)
				}
				refMu.Lock()
				refCount++
				refMu.Unlock()
				return &fat32FS{
					fs:         fat32fs,
					file:       f,
					tmpRawPath: tmpRawPath,
					refCount:   &refCount,
					refMu:      &refMu,
				}, nil
			default:
				f.Close()
				return nil, fmt.Errorf("unsupported filesystem type %s for partition %d", fsType, partitionIndex)
			}
		}

		embeddedFSs = append(embeddedFSs, &inventory.EmbeddedFS{
			Path:          fmt.Sprintf("%s:%d", vmdkPath, partitionIndex),
			GetEmbeddedFS: getEmbeddedFS,
		})
	}
	return inventory.Inventory{EmbeddedFSs: embeddedFSs}, nil
}

// detectFilesystem identifies the filesystem type by magic bytes
func detectFilesystem(r io.ReaderAt, offset int64) string {
	buf := make([]byte, 4096)
	_, err := r.ReadAt(buf, offset)
	if err != nil {
		return fmt.Sprintf("read error: %v", err)
	}
	// https://www.kernel.org/doc/html/latest/filesystems/ext4/globals.html
	// EXT4 magic at offset 0x438
	if len(buf) > 0x438+2 {
		if binary.LittleEndian.Uint16(buf[0x438:0x43A]) == 0xEF53 {
			return "ext4"
		}
	}
	// https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system
	// FAT32: "FAT32   " at offset 0x52
	if len(buf) > 0x52+8 {
		if string(buf[0x52:0x52+8]) == "FAT32   " {
			return "FAT32"
		}
	}
	return "unknown"
}

// ext4FS wraps go-ext4-filesystem to implement scalibrfs.FS
type ext4FS struct {
	fs         *ext4.FileSystem
	file       *os.File
	tmpRawPath string
	// refCount is used to close the underlying file once all readers have closed it
	refCount *int32
	refMu    *sync.Mutex
}

func (e *ext4FS) Open(name string) (fs.File, error) {
	file, err := e.fs.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", name, err)
	}
	ext4File, ok := file.(*ext4.File)
	if !ok {
		return nil, fmt.Errorf("opened file %s is not an ext4.File", name)
	}
	return &ext4FileWrapper{file: ext4File, name: name}, nil
}

func (e *ext4FS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := e.fs.ReadDir(name)
	if err != nil {
		fmt.Printf("ext4.ReadDir(%q) failed: %v\n", name, err)
		return nil, fmt.Errorf("failed to read directory %s: %w", name, err)
	}
	return entries, nil
}

func (e *ext4FS) Stat(name string) (fs.FileInfo, error) {
	if name == "." || name == "" || name == "/" {
		// Return synthetic FileInfo for root directory
		return &fileInfo{
			name:    name,
			isDir:   true,
			modTime: time.Now(),
		}, nil
	}
	info, err := e.fs.Stat(name)
	if err != nil {
		fmt.Printf("ext4FS.Stat(%q) failed: %v\n", name, err)
		return nil, fmt.Errorf("failed to stat %s: %w", name, err)
	}
	return info, nil
}

func (e *ext4FS) Close() error {
	e.refMu.Lock()
	defer e.refMu.Unlock()
	if e.file == nil {
		return nil // Already closed
	}
	*e.refCount--
	if *e.refCount == 0 {
		err := e.file.Close()
		e.file = nil // Prevent double close
		if err != nil {
			return fmt.Errorf("failed to close raw file %s: %w", e.tmpRawPath, err)
		}
		if err := os.Remove(e.tmpRawPath); err != nil {
			return fmt.Errorf("failed to remove temporary raw file %s: %w", e.tmpRawPath, err)
		}
	}
	return nil
}

// ext4FileWrapper wraps ext4.File to implement fs.File
type ext4FileWrapper struct {
	file *ext4.File
	name string
}

func (e *ext4FileWrapper) Read(p []byte) (int, error) {
	return e.file.Read(p)
}

func (e *ext4FileWrapper) Close() error {
	return e.file.Close()
}

func (e *ext4FileWrapper) Stat() (fs.FileInfo, error) {
	return e.file.Stat()
}

// fat32FS wraps go-diskfs fat32.FileSystem to implement scalibrfs.FS
type fat32FS struct {
	fs         *fat32.FileSystem
	file       *os.File
	tmpRawPath string
	// refCount is used to close the underlying file once all readers have closed it
	refCount *int32
	refMu    *sync.Mutex
}

func (f *fat32FS) Open(name string) (fs.File, error) {
	file, err := f.fs.OpenFile(name, os.O_RDONLY)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", name, err)
	}
	return &fat32FileWrapper{file: file, name: name, fs: f.fs}, nil
}

func (f *fat32FS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "." || name == "" {
		name = "/"
	}
	fis, err := f.fs.ReadDir(name)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", name, err)
	}
	entries := make([]fs.DirEntry, 0, len(fis))
	for _, fi := range fis {
		entries = append(entries, fs.FileInfoToDirEntry(fi))
	}
	return entries, nil
}

func (f *fat32FS) Stat(name string) (fs.FileInfo, error) {
	if name == "/" || name == "" || name == "." {
		// Return synthetic FileInfo for root directory
		return &fileInfo{
			name:    name,
			isDir:   true,
			modTime: time.Now(),
		}, nil
	}
	fis, err := f.fs.ReadDir(path.Dir(name))
	if err != nil {
		return nil, fmt.Errorf("failed to stat %s: %w", name, err)
	}
	base := path.Base(name)
	for _, fi := range fis {
		if fi.Name() == base {
			return fi, nil
		}
	}
	return nil, fmt.Errorf("file %s not found", name)
}

func (f *fat32FS) Close() error {
	f.refMu.Lock()
	defer f.refMu.Unlock()
	if f.file == nil {
		return nil
	}
	*f.refCount--
	if *f.refCount == 0 {
		err := f.file.Close()
		f.file = nil
		if err != nil {
			return fmt.Errorf("failed to close raw file %s: %w", f.tmpRawPath, err)
		}
		if err := os.Remove(f.tmpRawPath); err != nil {
			return fmt.Errorf("failed to remove temporary raw file %s: %w", f.tmpRawPath, err)
		}
	}
	return nil
}

// fat32FileWrapper wraps diskfsfilesystem.File to implement scalibrfs.FS
type fat32FileWrapper struct {
	file diskfsfilesystem.File
	name string
	fs   *fat32.FileSystem
}

func (f *fat32FileWrapper) Read(p []byte) (int, error) {
	return f.file.Read(p)
}

func (f *fat32FileWrapper) Close() error {
	return f.file.Close()
}

func (f *fat32FileWrapper) Stat() (fs.FileInfo, error) {
	if f.name == "/" || f.name == "" || f.name == "." {
		// Return synthetic FileInfo for root directory
		return &fileInfo{
			name:    f.name,
			isDir:   true,
			modTime: time.Now(),
		}, nil
	}
	fis, err := f.fs.ReadDir(path.Dir(f.name))
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", path.Dir(f.name), err)
	}
	base := path.Base(f.name)
	for _, fi := range fis {
		if fi.Name() == base {
			return fi, nil
		}
	}
	return nil, fmt.Errorf("file %s not found", f.name)
}

// fileInfo is a simple implementation of fs.FileInfo for the root directory
type fileInfo struct {
	name    string
	isDir   bool
	modTime time.Time
}

func (fi *fileInfo) Name() string {
	return fi.name
}

func (fi *fileInfo) Size() int64 {
	return 0
}

func (fi *fileInfo) Mode() fs.FileMode {
	if fi.isDir {
		return fs.ModeDir | 0755
	}
	return 0644
}

func (fi *fileInfo) ModTime() time.Time {
	return fi.modTime
}

func (fi *fileInfo) IsDir() bool {
	return fi.isDir
}

func (fi *fileInfo) Sys() any {
	return nil
}

// VMDK conversion functions

// readHeaderAt reads the 512-byte header at the given offset.
func readHeaderAt(r io.ReaderAt, offset int64) (sparseExtentHeader, error) {
	var hdr sparseExtentHeader
	buf := make([]byte, SectorSize)
	n, err := r.ReadAt(buf, offset)
	if err != nil && !errors.Is(err, io.EOF) {
		return hdr, fmt.Errorf("read header at %d: %w", offset, err)
	}
	if n < SectorSize {
		return hdr, fmt.Errorf("short header read: %d bytes", n)
	}
	br := bytes.NewReader(buf)
	if err := binary.Read(br, binary.LittleEndian, &hdr); err != nil {
		return hdr, fmt.Errorf("parse header: %w", err)
	}
	if hdr.MagicNumber != SparseMagic {
		return hdr, fmt.Errorf("invalid magic: 0x%x", hdr.MagicNumber)
	}
	return hdr, nil
}

// readFooterIfGDAtEnd reads the footer header near EOF if GDOffset is GDAtEnd.
func readFooterIfGDAtEnd(f *os.File, hdr *sparseExtentHeader) error {
	if hdr.GDOffset != GDAtEnd {
		return nil
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() < 1536 {
		return errors.New("file too small to contain footer/EOS")
	}
	base := fi.Size() - 1536
	footerHeaderBlock := make([]byte, 512)
	if _, err := f.ReadAt(footerHeaderBlock, base+512); err != nil {
		return fmt.Errorf("read footer header block: %w", err)
	}
	if binary.LittleEndian.Uint32(footerHeaderBlock[0:4]) != SparseMagic {
		return fmt.Errorf("footer magic mismatch: 0x%x", binary.LittleEndian.Uint32(footerHeaderBlock[0:4]))
	}
	var foot sparseExtentHeader
	r := bytes.NewReader(footerHeaderBlock[4:])
	if err := binary.Read(r, binary.LittleEndian, &foot); err != nil {
		return fmt.Errorf("parse footer header: %w", err)
	}
	*hdr = foot
	return nil
}

// readStreamMarker reads a VMDK stream marker.
func readStreamMarker(f *os.File) (val uint64, size uint32, typ uint32, data []byte, err error) {
	head := make([]byte, 12)
	if _, err = io.ReadFull(f, head); err != nil {
		return 0, 0, 0, nil, err
	}
	val = binary.LittleEndian.Uint64(head[0:8])
	size = binary.LittleEndian.Uint32(head[8:12])
	if size == 0 {
		tb := make([]byte, 4)
		if _, err = io.ReadFull(f, tb); err != nil {
			return val, size, 0, nil, err
		}
		typ = binary.LittleEndian.Uint32(tb)
		consumed := int64(16)
		pad := (SectorSize - (consumed % SectorSize)) % SectorSize
		if pad > 0 {
			if _, err := f.Seek(pad, io.SeekCurrent); err != nil {
				return val, size, typ, nil, err
			}
		}
		return val, size, typ, nil, nil
	}
	if size > 0 {
		data = make([]byte, size)
		if _, err = io.ReadFull(f, data); err != nil {
			return val, size, 0, nil, err
		}
		consumed := int64(12 + size)
		pad := (SectorSize - (consumed % SectorSize)) % SectorSize
		if pad > 0 {
			if _, err := f.Seek(pad, io.SeekCurrent); err != nil {
				return val, size, 0, nil, err
			}
		}
		return val, size, 0, data, nil
	}
	return val, size, 0, nil, nil
}

// convertStreamOptimizedExtent converts a stream-optimized VMDK extent.
func convertStreamOptimizedExtent(f *os.File, out *os.File, hdr sparseExtentHeader) error {
	if hdr.GDOffset == GDAtEnd {
		if err := readFooterIfGDAtEnd(f, &hdr); err != nil {
			return fmt.Errorf("read footer: %w", err)
		}
	}
	grainSec := hdr.GrainSize
	if grainSec == 0 || (grainSec&(grainSec-1)) != 0 {
		grainSec = DefaultGrainSec
	}
	grainBytes := int64(grainSec) * SectorSize
	start := int64(hdr.OverHead) * SectorSize
	if _, err := f.Seek(start, io.SeekStart); err != nil {
		return fmt.Errorf("seek to stream start: %w", err)
	}
	capacityBytes := int64(hdr.Capacity) * SectorSize
	if err := out.Truncate(capacityBytes); err != nil {
		return fmt.Errorf("truncate out: %w", err)
	}

	for {
		val, size, typ, payload, err := readStreamMarker(f)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return fmt.Errorf("read marker: %w", err)
		}
		if size != 0 {
			lba := int64(val)
			woff := lba * SectorSize
			if int64(size) == grainBytes {
				if _, werr := out.WriteAt(payload, woff); werr != nil {
					return fmt.Errorf("write raw grain at lba %d: %w", lba, werr)
				}
			} else if size < uint32(grainBytes) || size > uint32(grainBytes) {
				zr, zerr := zlib.NewReader(bytes.NewReader(payload))
				if zerr != nil {
					return fmt.Errorf("zlib reader at lba %d: %w", lba, zerr)
				}
				dec, derr := io.ReadAll(zr)
				zr.Close()
				if derr != nil && !errors.Is(derr, io.EOF) {
					return fmt.Errorf("zlib read at lba %d: %w", lba, derr)
				}
				if int64(len(dec)) < grainBytes {
					tmp := make([]byte, grainBytes)
					copy(tmp, dec)
					dec = tmp
				} else if int64(len(dec)) > grainBytes {
					tmp := make([]byte, int64(len(dec))+(-int64(len(dec))%grainBytes))
					copy(tmp, dec)
					dec = tmp
				}
				if _, werr := out.WriteAt(dec, woff); werr != nil {
					return fmt.Errorf("write decompressed grain at lba %d: %w", lba, werr)
				}
			} else {
				return fmt.Errorf("invalid grain payload size %d > grainBytes %d", size, grainBytes)
			}
			continue
		}
		switch typ {
		case 0: // EOS
			return nil
		case 1: // GT
			if val > 0 {
				if _, err := f.Seek(int64(val*SectorSize), io.SeekCurrent); err != nil {
					return fmt.Errorf("skip GT metadata: %w", err)
				}
			}
		case 2: // GD
			if val > 0 {
				if _, err := f.Seek(int64(val*SectorSize), io.SeekCurrent); err != nil {
					return fmt.Errorf("skip GD metadata: %w", err)
				}
			}
		case 3: // FOOTER
			if val > 0 {
				meta := make([]byte, int64(val*SectorSize))
				if _, err := io.ReadFull(f, meta); err != nil {
					return fmt.Errorf("read footer meta: %w", err)
				}
				if len(meta) >= 4 && binary.LittleEndian.Uint32(meta[0:4]) == SparseMagic {
					var foot sparseExtentHeader
					br := bytes.NewReader(meta[4:])
					if err := binary.Read(br, binary.LittleEndian, &foot); err == nil {
						hdr = foot
						grainSec = hdr.GrainSize
						if grainSec == 0 || (grainSec&(grainSec-1)) != 0 {
							grainSec = DefaultGrainSec
						}
						grainBytes = int64(grainSec) * SectorSize
						capacityBytes = int64(hdr.Capacity) * SectorSize
						_ = out.Truncate(capacityBytes)
					}
				}
			}
		case 4: // PROGRESS
			if val > 0 {
				if _, err := f.Seek(int64(val*SectorSize), io.SeekCurrent); err != nil {
					return fmt.Errorf("skip progress metadata: %w", err)
				}
			}
		default:
			if val > 0 {
				if _, err := f.Seek(int64(val*SectorSize), io.SeekCurrent); err != nil {
					return fmt.Errorf("skip unknown metadata type %d: %w", typ, err)
				}
			}
		}
	}
	return nil
}

// getGDGT computes GD/GT sizes and allocates structures.
func getGDGT(hdr sparseExtentHeader) (*gdgtInfo, error) {
	if hdr.GrainSize < 1 || hdr.GrainSize > 128 || (hdr.GrainSize&(hdr.GrainSize-1)) != 0 {
		return nil, fmt.Errorf("invalid grainSize %d", hdr.GrainSize)
	}
	if hdr.NumGTEsPerGT < uint32(SectorSize/4) || (hdr.NumGTEsPerGT&(hdr.NumGTEsPerGT-1)) != 0 {
		return nil, fmt.Errorf("invalid numGTEsPerGT %d", hdr.NumGTEsPerGT)
	}
	lastGrainNr := hdr.Capacity / hdr.GrainSize
	var lastGrainSize uint64
	if hdr.Capacity&(hdr.GrainSize-1) != 0 {
		lastGrainSize = (hdr.Capacity & (hdr.GrainSize - 1)) * SectorSize
	} else {
		lastGrainSize = 0
	}
	GTEs := lastGrainNr
	if lastGrainSize != 0 {
		GTEs = lastGrainNr + 1
	}
	GTs := uint32((GTEs + uint64(hdr.NumGTEsPerGT) - 1) / uint64(hdr.NumGTEsPerGT))
	GDsectors := uint32((uint64(GTs)*4 + SectorSize - 1) / SectorSize)
	GTsectors := uint32((uint64(hdr.NumGTEsPerGT)*4 + SectorSize - 1) / SectorSize)
	totalSectors := int64(GDsectors + GTsectors*GTs)
	totalBytes := totalSectors * SectorSize
	if totalBytes > 1<<31 {
		return nil, fmt.Errorf("gd/gt allocation too large: %d bytes", totalBytes)
	}
	gdarr := make([]uint32, (GDsectors*SectorSize)/4+(GTsectors*GTs*SectorSize)/4)
	info := &gdgtInfo{
		GTEs:      GTEs,
		GTs:       GTs,
		GDsectors: GDsectors,
		GTsectors: GTsectors,
		gd:        gdarr,
	}
	return info, nil
}

// readGD reads GD sectors from file.
func readGD(f *os.File, hdr sparseExtentHeader, info *gdgtInfo) error {
	if hdr.GDOffset == 0 {
		return errors.New("no GD offset")
	}
	start := int64(hdr.GDOffset) * SectorSize
	totalBytes := int64(info.GDsectors) * SectorSize
	buf := make([]byte, totalBytes)
	if _, err := f.ReadAt(buf, start); err != nil {
		return fmt.Errorf("read GD at %d: %w", start, err)
	}
	for i := range int(info.GDsectors * SectorSize / 4) {
		info.gd[i] = binary.LittleEndian.Uint32(buf[i*4 : i*4+4])
	}
	return nil
}

// convertMonolithicSparse converts a monolithic sparse VMDK.
func convertMonolithicSparse(f *os.File, out *os.File, hdr sparseExtentHeader) error {
	info, err := getGDGT(hdr)
	if err != nil {
		return err
	}
	GDOffset := hdr.GDOffset
	if hdr.RGDOffset != 0 {
		GDOffset = hdr.RGDOffset
	}
	if GDOffset == 0 || GDOffset == GDAtEnd {
		return errors.New("gd offset missing for monolithicSparse")
	}
	if err := readGD(f, hdr, info); err != nil {
		return fmt.Errorf("readGD: %w", err)
	}
	grainBytes := int64(hdr.GrainSize) * SectorSize
	totalGrains := int64((hdr.Capacity + hdr.GrainSize - 1) / hdr.GrainSize)
	if err := out.Truncate(int64(hdr.Capacity) * SectorSize); err != nil {
		return fmt.Errorf("truncate out: %w", err)
	}
	numGTEsPerGT := int64(hdr.NumGTEsPerGT)
	for g := range totalGrains {
		gdIdx := int(g / numGTEsPerGT)
		gtIdx := int(g % numGTEsPerGT)
		if gdIdx >= len(info.gd) {
			zero := make([]byte, grainBytes)
			if _, err := out.WriteAt(zero, g*grainBytes); err != nil {
				return err
			}
			continue
		}
		gtSector := uint64(info.gd[gdIdx])
		if gtSector == 0 {
			zero := make([]byte, grainBytes)
			if _, err := out.WriteAt(zero, g*grainBytes); err != nil {
				return err
			}
			continue
		}
		gtOffset := int64(gtSector) * SectorSize
		gtSizeBytes := int64(info.GTsectors) * SectorSize
		gtBuf := make([]byte, gtSizeBytes)
		if _, err := f.ReadAt(gtBuf, gtOffset); err != nil {
			return fmt.Errorf("read GT at %d: %w", gtOffset, err)
		}
		if gtIdx*4+4 > len(gtBuf) {
			zero := make([]byte, grainBytes)
			if _, err := out.WriteAt(zero, g*grainBytes); err != nil {
				return err
			}
			continue
		}
		gte := binary.LittleEndian.Uint32(gtBuf[gtIdx*4 : gtIdx*4+4])
		if gte == 0 {
			zero := make([]byte, grainBytes)
			if _, err := out.WriteAt(zero, g*grainBytes); err != nil {
				return err
			}
			continue
		}
		grainSector := int64(gte)
		grainOffset := grainSector * SectorSize
		var toRead = grainBytes
		if g == totalGrains-1 {
			lastSectors := int64(hdr.Capacity % hdr.GrainSize)
			if lastSectors == 0 {
				lastSectors = int64(hdr.GrainSize)
			}
			toRead = lastSectors * SectorSize
		}
		grainData := make([]byte, toRead)
		if _, err := f.ReadAt(grainData, grainOffset); err != nil {
			return fmt.Errorf("read grain at %d: %w", grainOffset, err)
		}
		if _, err := out.WriteAt(grainData, g*grainBytes); err != nil {
			return fmt.Errorf("write grain at %d: %w", g*grainBytes, err)
		}
	}
	return nil
}

// convertVMDKToRaw converts a VMDK file to a raw disk image.
func convertVMDKToRaw(inPath string, outPath string) error {
	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	hdr, err := readHeaderAt(in, 0)
	if err != nil {
		fi, st := in.Stat()
		if st != nil {
			return fmt.Errorf("stat input: %w", st)
		}
		if fi.Size() >= 1024 {
			offset := fi.Size() - 1024
			hdr2, err2 := readHeaderAt(in, offset)
			if err2 == nil {
				hdr = hdr2
			} else {
				return fmt.Errorf("read header failed: %w", err)
			}
		} else {
			return fmt.Errorf("read header failed: %w", err)
		}
	}

	const flagHasCompressed = 1 << 16
	const flagHasMetadata = 1 << 17
	isStream := (hdr.Flags&flagHasCompressed != 0) && (hdr.Flags&flagHasMetadata != 0)
	if hdr.CompressAlgorithm == 1 {
		isStream = true
	}

	if isStream {
		if err := convertStreamOptimizedExtent(in, out, hdr); err != nil {
			return err
		}
	} else {
		if err := convertMonolithicSparse(in, out, hdr); err != nil {
			return err
		}
	}
	return nil
}
