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
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/0xXA/go-exfat"
	"github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/filesystem/fat32"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/masahiro331/go-ext4-filesystem/ext4"
	"www.velocidex.com/golang/go-ntfs/parser"
)

const (
	// Name is the unique identifier for the vdi extractor.
	Name = "embeddedfs/vdi"
	// Signature is always 0xBEDA107F.
	Signature = 0xBEDA107F
	defaultPageSize  = 1024 * 1024
	defaultCacheSize = 100 * 1024 * 1024
)

// header describes the on-disk VDI header structure.
type header struct {
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
	return &plugin.Capabilities{}
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
	// If called on a virtual FS, clean up the temporary directory
	if input.Root == "" {
		defer func() {
			dir := filepath.Dir(vdiPath)
			if err := os.RemoveAll(dir); err != nil {
				fmt.Printf("os.RemoveAll(%q): %v\n", dir, err)
			}
		}()
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

	// Create an Embedded filesystem for each valid partition
	var embeddedFSs []*inventory.EmbeddedFS
	for i, p := range partitionList {
		partitionIndex := i + 1 // go-diskfs uses 1-based indexing
		getEmbeddedFS := func(ctx context.Context) (scalibrfs.FS, error) {
			// Open raw image for filesystem parsers
			f, err := os.Open(tmpRawPath)
			if err != nil {
				return nil, fmt.Errorf("failed to open raw image %s: %w", tmpRawPath, err)
			}

			// Get partition offset and size (already multiplied by sector size)
			offset := p.GetStart()
			size := p.GetSize()
			section := io.NewSectionReader(f, offset, size)
			fsType := detectFilesystem(section, 0)

			// Create a temporary directory for extracted files
			tempDir, err := os.MkdirTemp("", fmt.Sprintf("scalibr-vdi-%s-%d-", fsType, partitionIndex))
			if err != nil {
				f.Close()
				return nil, fmt.Errorf("failed to create temporary directory for %s partition %d: %w", fsType, partitionIndex, err)
			}

			switch fsType {
			case "ext4":
				fs, err := ext4.NewFS(*section, nil)
				if err != nil {
					f.Close()
					os.RemoveAll(tempDir)
					return nil, fmt.Errorf("failed to create ext4 filesystem for partition %d: %w", partitionIndex, err)
				}
				if err := extractAllRecursiveExt(fs, "/", tempDir); err != nil {
					f.Close()
					os.RemoveAll(tempDir)
					return nil, fmt.Errorf("failed to extract ext4 files for partition %d: %w", partitionIndex, err)
				}
				refMu.Lock()
				refCount++
				refMu.Unlock()
				return &ext4DirFS{
					fs:         scalibrfs.DirFS(tempDir),
					file:       f,
					tmpDir:     tempDir,
					tmpRawPath: tmpRawPath,
					refCount:   &refCount,
					refMu:      &refMu,
				}, nil
			case "FAT32":
				f.Close() // Close the file as GetFilesystem reopens it
				fs, err := disk.GetFilesystem(partitionIndex)
				if err != nil {
					os.RemoveAll(tempDir)
					return nil, fmt.Errorf("failed to get filesystem for partition %d: %w", partitionIndex, err)
				}
				fat32fs, ok := fs.(*fat32.FileSystem)
				if !ok {
					os.RemoveAll(tempDir)
					return nil, fmt.Errorf("partition %d is not a FAT32 filesystem", partitionIndex)
				}
				f, err = os.Open(tmpRawPath)
				if err != nil {
					os.RemoveAll(tempDir)
					return nil, fmt.Errorf("failed to reopen raw image %s: %w", tmpRawPath, err)
				}
				if err := extractAllRecursiveFat32(fat32fs, "/", tempDir); err != nil {
					f.Close()
					os.RemoveAll(tempDir)
					return nil, fmt.Errorf("failed to extract FAT32 files for partition %d: %w", partitionIndex, err)
				}
				refMu.Lock()
				refCount++
				refMu.Unlock()
				return &fat32DirFS{
					fs:         scalibrfs.DirFS(tempDir),
					file:       f,
					tmpDir:     tempDir,
					tmpRawPath: tmpRawPath,
					refCount:   &refCount,
					refMu:      &refMu,
				}, nil
			case "exFAT":
				fs, err := exfat.NewExFATFileSystem(section)
				if err != nil {
					f.Close()
					os.RemoveAll(tempDir)
					return nil, fmt.Errorf("failed to create exFAT filesystem for partition %d: %w", partitionIndex, err)
				}
				if err := fs.ExtractAllRecursive("/", tempDir); err != nil {
					f.Close()
					os.RemoveAll(tempDir)
					return nil, fmt.Errorf("failed to extract exFAT files for partition %d: %w", partitionIndex, err)
				}
				refMu.Lock()
				refCount++
				refMu.Unlock()
				return &exfatDirFS{
					fs:         scalibrfs.DirFS(tempDir),
					file:       f,
					tmpDir:     tempDir,
					tmpRawPath: tmpRawPath,
					refCount:   &refCount,
					refMu:      &refMu,
				}, nil
			case "NTFS":
				reader, err := parser.NewPagedReader(section, defaultPageSize, defaultCacheSize)
				if err != nil {
					f.Close()
					os.RemoveAll(tempDir)
					return nil, fmt.Errorf("failed to create paged reader for NTFS partition %d: %w", partitionIndex, err)
				}
				fs, err := parser.GetNTFSContext(reader, 0)
				if err != nil {
					f.Close()
					os.RemoveAll(tempDir)
					return nil, fmt.Errorf("failed to create NTFS filesystem for partition %d: %w", partitionIndex, err)
				}
				if err := extractAllRecursiveNtfs(fs, "/", tempDir); err != nil {
					f.Close()
					os.RemoveAll(tempDir)
					return nil, fmt.Errorf("failed to extract NTFS files for partition %d: %w", partitionIndex, err)
				}
				refMu.Lock()
				refCount++
				refMu.Unlock()
				return &ntfsDirFS{
					fs:         scalibrfs.DirFS(tempDir),
					file:       f,
					tmpDir:     tempDir,
					tmpRawPath: tmpRawPath,
					refCount:   &refCount,
					refMu:      &refMu,
				}, nil
			default:
				f.Close()
				os.RemoveAll(tempDir)
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
	// https://www.kernel.org/doc/html/latest/filesystems/ext4/globals.html
	// EXT4 magic at offset 0x438
	if len(buf) > 0x438+2 {
		if binary.LittleEndian.Uint16(buf[0x438:0x43A]) == 0xEF53 {
			return "ext4"
		}
	}
	// https://en.wikipedia.org/wiki/NTFS
	// NTFS: "NTFS    " at offset 0x03
	if len(buf) > 3+8 {
		if string(buf[3:3+8]) == "NTFS    " {
			return "NTFS"
		}
	}
	// https://en.wikipedia.org/wiki/Design_of_the_FAT_file_system
	// FAT32: "FAT32   " at offset 0x52
	if len(buf) > 0x52+8 {
		if string(buf[0x52:0x52+8]) == "FAT32   " {
			return "FAT32"
		}
	}
	// https://en.wikipedia.org/wiki/ExFAT
	// exFAT: "EXFAT   " at offset 0x03
	if len(buf) > 3+8 {
		if string(buf[3:3+8]) == "EXFAT   " {
			return "exFAT"
		}
	}
	return "unknown"
}

func normalizePath(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return p
}

// removes ".", "..", and "lost+found"
func filterEntriesFat32(entries []os.FileInfo) []os.FileInfo {
	var filtered []os.FileInfo
	for _, e := range entries {
		name := e.Name()
		if name == "." || name == ".." || name == "lost+found" {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

// removes ".", "..", and "lost+found"
func filterEntriesExt(entries []fs.DirEntry) []fs.DirEntry {
	var filtered []fs.DirEntry
	for _, e := range entries {
		name := e.Name()
		if name == "." || name == ".." || name == "lost+found" {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

// extractAllRecursiveExt extracts all files from an ext4 filesystem to a temporary directory.
func extractAllRecursiveExt(fs *ext4.FileSystem, srcPath, destPath string) error {
	srcPath = normalizePath(srcPath)
	entries, err := fs.ReadDir(srcPath)
	if err != nil {
		fmt.Printf("Warning: Failed to list directory %s: %v\n", srcPath, err)
		return nil // Continue processing other entries
	}

	entries = filterEntriesExt(entries)

	if err := os.MkdirAll(destPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", destPath, err)
	}

	for _, entry := range entries {
		srcFullPath := path.Join(srcPath, entry.Name())
		destFullPath := filepath.Join(destPath, entry.Name())

		if entry.IsDir() {
			if err := os.MkdirAll(destFullPath, 0755); err != nil {
				fmt.Printf("Warning: Failed to create directory %s: %v\n", destFullPath, err)
				continue
			}
			if err := extractAllRecursiveExt(fs, srcFullPath, destFullPath); err != nil {
				fmt.Printf("Warning: Failed to extract directory %s: %v\n", srcFullPath, err)
				continue
			}
		} else {
			file, err := fs.Open(srcFullPath)
			if err != nil {
				fmt.Printf("Warning: Failed to open file %s: %v\n", srcFullPath, err)
				continue
			}
			defer file.Close()

			destFile, err := os.Create(destFullPath)
			if err != nil {
				fmt.Printf("Warning: Failed to create file %s: %v\n", destFullPath, err)
				continue
			}
			defer destFile.Close()

			if _, err := io.Copy(destFile, file); err != nil {
				fmt.Printf("Warning: Failed to copy file %s to %s: %v\n", srcFullPath, destFullPath, err)
				continue
			}
		}
	}
	return nil
}

// Add filterEntriesNtfs to remove ".", "..", and "$" entries
func filterEntriesNtfs(entries []*parser.FileInfo) []*parser.FileInfo {
	var filtered []*parser.FileInfo
	for _, e := range entries {
		name := e.Name
		if name == "" || name == "." || name == ".." || strings.HasPrefix(name, "$") {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

// extractAllRecursiveFat32 extracts all files from a FAT32 filesystem to a temporary directory.
func extractAllRecursiveFat32(fs *fat32.FileSystem, srcPath, destPath string) error {
	if srcPath == "" || srcPath == "." {
		srcPath = "/"
	}
	srcPath = normalizePath(srcPath)
	entries, err := fs.ReadDir(srcPath)
	if err != nil {
		fmt.Printf("Warning: Failed to list directory %s: %v\n", srcPath, err)
		return nil // Continue processing other entries
	}

	entries = filterEntriesFat32(entries)

	if err := os.MkdirAll(destPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", destPath, err)
	}

	for _, entry := range entries {
		srcFullPath := path.Join(srcPath, entry.Name())
		destFullPath := filepath.Join(destPath, entry.Name())

		if entry.IsDir() {
			if err := os.MkdirAll(destFullPath, 0755); err != nil {
				fmt.Printf("Warning: Failed to create directory %s: %v\n", destFullPath, err)
				continue
			}
			if err := extractAllRecursiveFat32(fs, srcFullPath, destFullPath); err != nil {
				fmt.Printf("Warning: Failed to extract directory %s: %v\n", srcFullPath, err)
				continue
			}
		} else {
			file, err := fs.OpenFile(srcFullPath, os.O_RDONLY)
			if err != nil {
				fmt.Printf("Warning: Failed to open file %s: %v\n", srcFullPath, err)
				continue
			}
			defer file.Close()

			destFile, err := os.Create(destFullPath)
			if err != nil {
				fmt.Printf("Warning: Failed to create file %s: %v\n", destFullPath, err)
				continue
			}
			defer destFile.Close()

			if _, err := io.Copy(destFile, file); err != nil {
				fmt.Printf("Warning: Failed to copy file %s to %s: %v\n", srcFullPath, destFullPath, err)
				continue
			}
		}
	}
	return nil
}

// extractAllRecursiveNtfs extracts all files from a NTFS filesystem to a temporary directory.
func extractAllRecursiveNtfs(fs *parser.NTFSContext, srcPath, destPath string) error {
	srcPath = normalizePath(srcPath)
	if srcPath == "" || srcPath == "." {
		srcPath = "/"
	}

	dir, err := fs.GetMFT(5) // Root directory MFT entry
	if err != nil {
		fmt.Printf("Warning: Failed to get root MFT for %s: %v\n", srcPath, err)
		return nil // Continue processing other entries
	}
	entry, err := dir.Open(fs, srcPath)
	if err != nil {
		fmt.Printf("Warning: Failed to open directory %s: %v\n", srcPath, err)
		return nil // Continue processing other entries
	}
	entries := parser.ListDir(fs, entry)
	entries = filterEntriesNtfs(entries)

	if err := os.MkdirAll(destPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", destPath, err)
	}

	for _, entryInfo := range entries {
		srcFullPath := path.Join(srcPath, entryInfo.Name)
		destFullPath := filepath.Join(destPath, entryInfo.Name)

		if entryInfo.IsDir {
			if err := os.MkdirAll(destFullPath, 0755); err != nil {
				fmt.Printf("Warning: Failed to create directory %s: %v\n", destFullPath, err)
				continue
			}
			if err := extractAllRecursiveNtfs(fs, srcFullPath, destFullPath); err != nil {
				fmt.Printf("Warning: Failed to extract directory %s: %v\n", srcFullPath, err)
				continue
			}
		} else {
			fileEntry, err := dir.Open(fs, srcFullPath)
			if err != nil {
				fmt.Printf("Warning: Failed to open file %s: %v\n", srcFullPath, err)
				continue
			}
			// Get the file's data attribute
			attr, err := fileEntry.GetAttribute(fs, 128, -1, "") // Data attribute
			if err != nil {
				fmt.Printf("Warning: Failed to get data attribute for %s: %v\n", srcFullPath, err)
				continue
			}
			fileReaderAt := attr.Data(fs) // io.ReaderAt for file content
			// Convert io.ReaderAt to io.Reader using io.NewSectionReader
			fileReader := io.NewSectionReader(fileReaderAt, 0, entryInfo.Size)

			destFile, err := os.Create(destFullPath)
			if err != nil {
				fmt.Printf("Warning: Failed to create file %s: %v\n", destFullPath, err)
				continue
			}
			defer destFile.Close()

			if _, err := io.Copy(destFile, fileReader); err != nil {
				fmt.Printf("Warning: Failed to copy file %s to %s: %v\n", srcFullPath, destFullPath, err)
				continue
			}
		}
	}
	return nil
}

// ext4DirFS wraps scalibrfs.DirFS to include reference counting and cleanup
type ext4DirFS struct {
	fs         scalibrfs.FS
	file       *os.File
	tmpDir     string
	tmpRawPath string
	refCount   *int32
	refMu      *sync.Mutex
}

func (e *ext4DirFS) Open(name string) (fs.File, error) {
	return e.fs.Open(name)
}

func (e *ext4DirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "/" || name == "" {
		name = "."
	}
	return e.fs.ReadDir(name)
}

func (e *ext4DirFS) Stat(name string) (fs.FileInfo, error) {
	if name == "/" || name == "" || name == "." {
		// Return synthetic FileInfo for root directory
		return &fileInfo{
			name:    name,
			isDir:   true,
			modTime: time.Now(),
		}, nil
	}
	return e.fs.Stat(name)
}

func (e *ext4DirFS) Close() error {
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
	if err := os.RemoveAll(e.tmpDir); err != nil {
		return fmt.Errorf("failed to remove temporary directory %s: %w", e.tmpDir, err)
	}
	return nil
}

// fat32DirFS wraps scalibrfs.DirFS to include reference counting and cleanup
type fat32DirFS struct {
	fs         scalibrfs.FS
	file       *os.File
	tmpDir     string
	tmpRawPath string
	refCount   *int32
	refMu      *sync.Mutex
}

func (f *fat32DirFS) Open(name string) (fs.File, error) {
	return f.fs.Open(name)
}

func (f *fat32DirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "/" || name == "" {
		name = "."
	}
	return f.fs.ReadDir(name)
}

func (f *fat32DirFS) Stat(name string) (fs.FileInfo, error) {
	if name == "/" || name == "" || name == "." {
		// Return synthetic FileInfo for root directory
		return &fileInfo{
			name:    name,
			isDir:   true,
			modTime: time.Now(),
		}, nil
	}
	return f.fs.Stat(name)
}

func (f *fat32DirFS) Close() error {
	f.refMu.Lock()
	defer f.refMu.Unlock()
	if f.file == nil {
		return nil // Already closed
	}
	*f.refCount--
	if *f.refCount == 0 {
		err := f.file.Close()
		f.file = nil // Prevent double close
		if err != nil {
			return fmt.Errorf("failed to close raw file %s: %w", f.tmpRawPath, err)
		}
		if err := os.Remove(f.tmpRawPath); err != nil {
			return fmt.Errorf("failed to remove temporary raw file %s: %w", f.tmpRawPath, err)
		}
	}
	if err := os.RemoveAll(f.tmpDir); err != nil {
		return fmt.Errorf("failed to remove temporary directory %s: %w", f.tmpDir, err)
	}
	return nil
}

// exfatDirFS wraps scalibrfs.DirFS to include reference counting and cleanup
type exfatDirFS struct {
	fs         scalibrfs.FS
	file       *os.File
	tmpDir     string
	tmpRawPath string
	refCount   *int32
	refMu      *sync.Mutex
}

func (e *exfatDirFS) Open(name string) (fs.File, error) {
	return e.fs.Open(name)
}

func (e *exfatDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "/" || name == "" {
		name = "."
	}
	return e.fs.ReadDir(name)
}

func (e *exfatDirFS) Stat(name string) (fs.FileInfo, error) {
	if name == "/" || name == "" || name == "." {
		// Return synthetic FileInfo for root directory
		return &fileInfo{
			name:    name,
			isDir:   true,
			modTime: time.Now(),
		}, nil
	}
	return e.fs.Stat(name)
}

func (e *exfatDirFS) Close() error {
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
	if err := os.RemoveAll(e.tmpDir); err != nil {
		return fmt.Errorf("failed to remove temporary directory %s: %w", e.tmpDir, err)
	}
	return nil
}

// ntfsDirFS wraps scalibrfs.DirFS to include reference counting and cleanup
type ntfsDirFS struct {
	fs         scalibrfs.FS
	file       *os.File
	tmpDir     string
	tmpRawPath string
	refCount   *int32
	refMu      *sync.Mutex
}

func (n *ntfsDirFS) Open(name string) (fs.File, error) {
	return n.fs.Open(name)
}

func (n *ntfsDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "/" || name == "" {
		name = "."
	}
	return n.fs.ReadDir(name)
}

func (n *ntfsDirFS) Stat(name string) (fs.FileInfo, error) {
	if name == "/" || name == "" || name == "." {
		// Return synthetic FileInfo for root directory
		return &fileInfo{
			name:    name,
			isDir:   true,
			modTime: time.Now(),
		}, nil
	}
	return n.fs.Stat(name)
}

func (n *ntfsDirFS) Close() error {
	n.refMu.Lock()
	defer n.refMu.Unlock()
	if n.file == nil {
		return nil // Already closed
	}
	*n.refCount--
	if *n.refCount == 0 {
		err := n.file.Close()
		n.file = nil // Prevent double close
		if err != nil {
			return fmt.Errorf("failed to close raw file %s: %w", n.tmpRawPath, err)
		}
		if err := os.Remove(n.tmpRawPath); err != nil {
			return fmt.Errorf("failed to remove temporary raw file %s: %w", n.tmpRawPath, err)
		}
	}
	if err := os.RemoveAll(n.tmpDir); err != nil {
		return fmt.Errorf("failed to remove temporary directory %s: %w", n.tmpDir, err)
	}
	return nil
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
	var hdr header
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
