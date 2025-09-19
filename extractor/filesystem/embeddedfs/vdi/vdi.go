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

// Package vdi provides an extractor for extracting software inventories from VirtualBox's VDI disk images
package vdi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
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
	// Name is the unique identifier for the vdi extractor.
	Name = "embeddedfs/vdi"
	// Signature is always 0xBEDA107F.
	Signature = 0xBEDA107F
)

// Header describes the on-disk VDI header structure.
type Header struct {
	Text            [0x40]byte
	Signature       uint32
	Version         uint32
	HeaderSize      uint32
	ImageType       uint32
	ImageFlags      uint32
	Description     [256]byte
	OffsetBmap      uint32
	OffsetData      uint32
	Cylinders       uint32
	Heads           uint32
	Sectors         uint32
	SectorSize      uint32
	Unused1         uint32
	DiskSize        uint64
	BlockSize       uint32
	BlockExtra      uint32
	BlocksInImage   uint32
	BlocksAllocated uint32
	UUIDImage       [16]byte
	UUIDLastSnap    [16]byte
	UUIDLink        [16]byte
	UUIDParent      [16]byte
	Unused2         [7]uint64
}

// Extractor implements the filesystem.Extractor interface for vdi.
type Extractor struct{}

// New returns a new VDI extractor.
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
	return &plugin.Capabilities{
		OS:              plugin.OSAny,
		Network:         plugin.NetworkAny,
		DirectFS:        true, // Requires direct filesystem access for GetRealPath
		RunningSystem:   false,
		ExtractFromDirs: false,
	}
}

// FileRequired checks if the file is a .vdi file based on its extension.
func (e *Extractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	return strings.HasSuffix(strings.ToLower(path), ".vdi")
}

// Extract returns an Inventory with embedded filesystems which contains mount functions for each filesystem in the .vdi file.
func (e *Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	vdiPath, err := input.GetRealPath()
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to get real path for %s: %w", input.Path, err)
	}

	// Create a temporary file for the raw disk image
	tmpRaw, err := os.CreateTemp("", "scalibr-vdi-raw-*.raw")
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("failed to create temporary raw file: %w", err)
	}
	tmpRawPath := tmpRaw.Name()

	// Convert VDI to raw
	if err := convertVDIToRaw(vdiPath, tmpRawPath); err != nil {
		os.Remove(tmpRawPath)
		return inventory.Inventory{}, fmt.Errorf("failed to convert %s to raw image: %w", vdiPath, err)
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

	// Create a Embedded filesystem for each valid partition
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
			Path:          fmt.Sprintf("%s:%d", vdiPath, partitionIndex),
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
	// EXT4 magic at offset 0x438
	if len(buf) > 0x438+2 {
		if binary.LittleEndian.Uint16(buf[0x438:0x43A]) == 0xEF53 {
			return "ext4"
		}
	}
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
	refCount   *int32
	refMu      *sync.Mutex
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

// ext4FileWrapper wraps ext4.File to implement fs.File and io.ReaderAt
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

// Implement io.ReaderAt for scalibrfs.File (assumed to require it)
func (e *ext4FileWrapper) ReadAt(p []byte, off int64) (int, error) {
	// Read the entire file into memory (suitable for small files like private-key.pem)
	data, err := io.ReadAll(e.file)
	if err != nil {
		return 0, fmt.Errorf("failed to read file %s: %w", e.name, err)
	}
	if off >= int64(len(data)) {
		return 0, io.EOF
	}
	n := copy(p, data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// fat32FS wraps go-diskfs fat32.FileSystem to implement scalibrfs.FS
type fat32FS struct {
	fs         *fat32.FileSystem
	file       *os.File
	tmpRawPath string
	refCount   *int32
	refMu      *sync.Mutex
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
		// Return synthetic FileInfo for root directory
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

// fat32FileWrapper wraps diskfsfilesystem.File to implement scalibrfs.FS and io.ReaderAt
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

func (f *fat32FileWrapper) ReadAt(p []byte, off int64) (int, error) {
	// diskfsfilesystem.File implements io.ReadWriteSeeker, so we can use Seek and Read
	_, err := f.file.Seek(off, io.SeekStart)
	if err != nil {
		return 0, fmt.Errorf("failed to seek to offset %d in file %s: %w", off, f.name, err)
	}
	n, err := f.file.Read(p)
	if err != nil {
		return n, fmt.Errorf("failed to read at offset %d in file %s: %w", off, f.name, err)
	}
	return n, nil
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

// VDI conversion functions

func convertVDIToRaw(inPath string, outPath string) error {
	f, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Read header
	var hdr Header
	if err := binary.Read(f, binary.LittleEndian, &hdr); err != nil {
		return err
	}

	// Sanity check: VDI signature should be 0xBEDA107F
	if hdr.Signature != Signature {
		return errors.New("not a valid VDI file (bad signature)")
	}

	// Open output
	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	switch hdr.ImageType {
	case 2: // fixed/static
		if _, err := f.Seek(int64(hdr.OffsetData), io.SeekStart); err != nil {
			return err
		}
		_, err = io.CopyN(out, f, int64(hdr.DiskSize))
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		return nil

	case 1: // dynamic/sparse
		// Read block map
		if _, err := f.Seek(int64(hdr.OffsetBmap), io.SeekStart); err != nil {
			return err
		}
		indices := make([]uint32, hdr.BlocksInImage)
		if err := binary.Read(f, binary.LittleEndian, &indices); err != nil {
			return err
		}

		// Each block stride = BlockSize + BlockExtra
		stride := uint64(hdr.BlockSize) + uint64(hdr.BlockExtra)

		for i := range int(hdr.BlocksInImage) {
			virtOffset := uint64(i) * uint64(hdr.BlockSize)
			writeSize := uint64(hdr.BlockSize)
			if virtOffset+writeSize > hdr.DiskSize {
				writeSize = hdr.DiskSize - virtOffset
			}

			idx := indices[i]
			if idx == 0xFFFFFFFF || idx == 0xFFFFFFFE {
				// unallocated/discarded: write zeros
				if err := writeZeros(out, int64(writeSize)); err != nil {
					return err
				}
				continue
			}

			// Physical location of block
			phys := int64(hdr.OffsetData) + int64(uint64(idx)*stride) + int64(hdr.BlockExtra)
			if _, err := f.Seek(phys, io.SeekStart); err != nil {
				return err
			}
			if _, err := io.CopyN(out, f, int64(writeSize)); err != nil {
				return err
			}
		}
		return nil

	default:
		return fmt.Errorf("unsupported VDI type %d", hdr.ImageType)
	}
}

func writeZeros(w io.Writer, n int64) error {
	buf := make([]byte, 64*1024)
	for n > 0 {
		chunk := int64(len(buf))
		if chunk > n {
			chunk = n
		}
		if _, err := w.Write(buf[:chunk]); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}
