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

// Package common provides common utilities for embedded filesystem extractors.
package common

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/diskfs/go-diskfs/disk"
	"github.com/diskfs/go-diskfs/filesystem/fat32"
	"github.com/dsoprea/go-exfat"
	"github.com/masahiro331/go-ext4-filesystem/ext4"
	"www.velocidex.com/golang/go-ntfs/parser"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

const (
	defaultPageSize  = 1024 * 1024
	defaultCacheSize = 100 * 1024 * 1024
)

// DetectFilesystem identifies the filesystem type by magic bytes.
func DetectFilesystem(r io.ReaderAt, offset int64) string {
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

// filterEntriesFat32 removes ".", "..", and "lost+found" from FAT32 entries.
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

// filterEntriesExt removes ".", "..", and "lost+found" from ext4 entries.
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

// filterEntriesNtfs removes ".", "..", and "$"-prefixed entries from NTFS entries.
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

// ExtractAllRecursiveExt extracts all files from an ext4 filesystem to a temporary directory recursively.
func ExtractAllRecursiveExt(fs *ext4.FileSystem, srcPath, destPath string) error {
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
			if err := ExtractAllRecursiveExt(fs, srcFullPath, destFullPath); err != nil {
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

// ExtractAllRecursiveFat32 extracts all files from a FAT32 filesystem to a temporary directory recursively.
func ExtractAllRecursiveFat32(fs *fat32.FileSystem, srcPath, destPath string) error {
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
			if err := ExtractAllRecursiveFat32(fs, srcFullPath, destFullPath); err != nil {
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

// ExtractAllRecursiveNtfs extracts all files from a NTFS filesystem to a temporary directory recursively.
func ExtractAllRecursiveNtfs(fs *parser.NTFSContext, srcPath, destPath string) error {
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
			if err := ExtractAllRecursiveNtfs(fs, srcFullPath, destFullPath); err != nil {
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

// ExtractAllRecursiveExFAT extracts all files from an exFAT filesystem to a temporary directory recursively.
func ExtractAllRecursiveExFAT(section *io.SectionReader, dst string) error {
	er := exfat.NewExfatReader(section)
	if err := er.Parse(); err != nil {
		return fmt.Errorf("failed to parse exfat filesystem: %w", err)
	}

	tree := exfat.NewTree(er)
	if err := tree.Load(); err != nil {
		return fmt.Errorf("failed to load exfat tree: %w", err)
	}

	files, nodes, err := tree.List()
	if err != nil {
		return fmt.Errorf("failed to list exfat entries: %w", err)
	}

	for _, relPath := range files {
		node := nodes[relPath]
		resPath := strings.ReplaceAll(relPath, "\\", string(os.PathSeparator))
		outPath := filepath.Join(dst, resPath)

		sde := node.StreamDirectoryEntry()
		if node.IsDirectory() {
			if err := os.MkdirAll(outPath, 0o755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", outPath, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
			return fmt.Errorf("failed to create parent directories for %s: %w", outPath, err)
		}

		outFile, err := os.Create(outPath)
		if err != nil {
			return fmt.Errorf("failed to create file %s: %w", outPath, err)
		}

		useFat := !sde.GeneralSecondaryFlags.NoFatChain()
		if _, _, err := er.WriteFromClusterChain(sde.FirstCluster, sde.ValidDataLength, useFat, outFile); err != nil {
			// Ignore this error because we're going to manually truncate the file at the end
			if !strings.Contains(err.Error(), "written bytes do not equal data-size") {
				return fmt.Errorf("failed to write cluster chain %s: %w", outPath, err)
			}
		}

		err = outFile.Truncate(int64(sde.ValidDataLength))
		if err != nil {
			continue
		}

		if err := outFile.Close(); err != nil {
			return fmt.Errorf("failed to close file %s: %w", outPath, err)
		}
	}

	return nil
}

// CloserWithTmpPaths is an interface for filesystems that provide temporary paths for cleanup.
type CloserWithTmpPaths interface {
	scalibrfs.FS
	Close() error
	TempPaths() []string
}

// GenerateFSParams holds parameters for generating embedded filesystems.
type GenerateFSParams struct {
	File           *os.File
	Disk           *disk.Disk
	Section        *io.SectionReader
	PartitionIndex int
	TempDir        string
	TmpRawPath     string
	RefMu          *sync.Mutex
	RefCount       *int32
}

// GenerateEXTFS generates an ext4 filesystem and extracts files to a temporary directory.
func GenerateEXTFS(params GenerateFSParams) (*EmbeddedDirFS, error) {
	fs, err := ext4.NewFS(*params.Section, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ext4 filesystem for partition %d: %w", params.PartitionIndex, err)
	}
	if err := ExtractAllRecursiveExt(fs, "/", params.TempDir); err != nil {
		return nil, fmt.Errorf("failed to extract ext4 files for partition %d: %w", params.PartitionIndex, err)
	}
	params.RefMu.Lock()
	*params.RefCount++
	params.RefMu.Unlock()
	return &EmbeddedDirFS{
		FS:       scalibrfs.DirFS(params.TempDir),
		File:     params.File,
		TmpPaths: []string{params.TempDir, params.TmpRawPath},
		RefCount: params.RefCount,
		RefMu:    params.RefMu,
	}, nil
}

// GenerateFAT32FS generates a FAT32 filesystem and extracts files to a temporary directory.
// Note that unlike in the other generator functions, the file is expected to be closed
// as disk.GetFilesystem() will reopen it.
func GenerateFAT32FS(params GenerateFSParams) (*EmbeddedDirFS, error) {
	fs, err := params.Disk.GetFilesystem(params.PartitionIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to get filesystem for partition %d: %w", params.PartitionIndex, err)
	}
	fat32fs, ok := fs.(*fat32.FileSystem)
	if !ok {
		return nil, fmt.Errorf("partition %d is not a FAT32 filesystem", params.PartitionIndex)
	}
	f, err := os.Open(params.TmpRawPath)
	if err != nil {
		return nil, fmt.Errorf("failed to reopen raw image %s: %w", params.TmpRawPath, err)
	}
	if err := ExtractAllRecursiveFat32(fat32fs, "/", params.TempDir); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to extract FAT32 files for partition %d: %w", params.PartitionIndex, err)
	}
	params.RefMu.Lock()
	*params.RefCount++
	params.RefMu.Unlock()
	return &EmbeddedDirFS{
		FS:       scalibrfs.DirFS(params.TempDir),
		File:     f,
		TmpPaths: []string{params.TempDir, params.TmpRawPath},
		RefCount: params.RefCount,
		RefMu:    params.RefMu,
	}, nil
}

// GenerateEXFATFS generates an exFAT filesystem and extracts files to a temporary directory.
func GenerateEXFATFS(params GenerateFSParams) (*EmbeddedDirFS, error) {
	if err := ExtractAllRecursiveExFAT(params.Section, params.TempDir); err != nil {
		return nil, fmt.Errorf("failed to extract exFAT files for partition %d: %w", params.PartitionIndex, err)
	}
	params.RefMu.Lock()
	*params.RefCount++
	params.RefMu.Unlock()
	return &EmbeddedDirFS{
		FS:       scalibrfs.DirFS(params.TempDir),
		File:     params.File,
		TmpPaths: []string{params.TempDir, params.TmpRawPath},
		RefCount: params.RefCount,
		RefMu:    params.RefMu,
	}, nil
}

// GenerateNTFSFS generates an NTFS filesystem and extracts files to a temporary directory.
func GenerateNTFSFS(params GenerateFSParams) (*EmbeddedDirFS, error) {
	reader, err := parser.NewPagedReader(params.Section, defaultPageSize, defaultCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create paged reader for NTFS partition %d: %w", params.PartitionIndex, err)
	}
	fs, err := parser.GetNTFSContext(reader, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create NTFS filesystem for partition %d: %w", params.PartitionIndex, err)
	}
	if err := ExtractAllRecursiveNtfs(fs, "/", params.TempDir); err != nil {
		return nil, fmt.Errorf("failed to extract NTFS files for partition %d: %w", params.PartitionIndex, err)
	}
	params.RefMu.Lock()
	*params.RefCount++
	params.RefMu.Unlock()
	return &EmbeddedDirFS{
		FS:       scalibrfs.DirFS(params.TempDir),
		File:     params.File,
		TmpPaths: []string{params.TempDir, params.TmpRawPath},
		RefCount: params.RefCount,
		RefMu:    params.RefMu,
	}, nil
}

// EmbeddedDirFS wraps scalibrfs.DirFS to include reference counting and cleanup.
type EmbeddedDirFS struct {
	FS       scalibrfs.FS
	File     *os.File
	TmpPaths []string
	RefCount *int32
	RefMu    *sync.Mutex
}

// Open opens the specified file from the embedded filesystem.
func (e *EmbeddedDirFS) Open(name string) (fs.File, error) {
	return e.FS.Open(name)
}

// ReadDir returns a list of directory entries for the specified path.
// If name is empty or "/", it reads from the root directory instead.
func (e *EmbeddedDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "/" || name == "" {
		name = "."
	}
	return e.FS.ReadDir(name)
}

// Stat returns a FileInfo describing the named file or directory.
// If the name refers to the root directory ("/", "", or "."), it
// returns a synthetic FileInfo representing a directory.
func (e *EmbeddedDirFS) Stat(name string) (fs.FileInfo, error) {
	if name == "/" || name == "" || name == "." {
		// Return synthetic FileInfo for root directory
		return &fileInfo{
			name:    name,
			isDir:   true,
			modTime: time.Now(),
		}, nil
	}
	return e.FS.Stat(name)
}

// Close closes the underlying file without removing temporary paths.
func (e *EmbeddedDirFS) Close() error {
	e.RefMu.Lock()
	defer e.RefMu.Unlock()
	if e.File == nil {
		return nil // Already closed
	}
	*e.RefCount--
	if *e.RefCount == 0 {
		err := e.File.Close()
		e.File = nil // Prevent double close
		if err != nil {
			return fmt.Errorf("failed to close raw file: %w", err)
		}
	}
	return nil
}

// TempPaths returns the temporary paths associated with the filesystem for cleanup.
func (e *EmbeddedDirFS) TempPaths() []string {
	return e.TmpPaths
}

// fileInfo is a simple implementation of fs.FileInfo for the root directory.
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
