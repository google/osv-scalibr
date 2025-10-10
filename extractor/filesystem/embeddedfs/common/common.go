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

	"github.com/diskfs/go-diskfs/filesystem/fat32"
	"github.com/dsoprea/go-exfat"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/masahiro331/go-ext4-filesystem/ext4"
	"www.velocidex.com/golang/go-ntfs/parser"
)

// DetectFilesystem identifies the filesystem type by magic bytes
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

// ExtractAllRecursiveExt extracts all files from an ext4 filesystem to a temporary directory.
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

// ExtractAllRecursiveFat32 extracts all files from a FAT32 filesystem to a temporary directory.
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

// ExtractAllRecursiveNtfs extracts all files from a NTFS filesystem to a temporary directory.
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

// ExtractAllRecursiveExFAT extracts all files from an exFAT filesystem to a temporary directorary.
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

		useFat := sde.GeneralSecondaryFlags.NoFatChain() == false
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

// Ext4DirFS wraps scalibrfs.DirFS to include reference counting and cleanup
type Ext4DirFS struct {
	FS         scalibrfs.FS
	File       *os.File
	TmpDir     string
	TmpRawPath string
	RefCount   *int32
	RefMu      *sync.Mutex
}

func (e *Ext4DirFS) Open(name string) (fs.File, error) {
	return e.FS.Open(name)
}

func (e *Ext4DirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "/" || name == "" {
		name = "."
	}
	return e.FS.ReadDir(name)
}

func (e *Ext4DirFS) Stat(name string) (fs.FileInfo, error) {
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

func (e *Ext4DirFS) Close() error {
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
			return fmt.Errorf("failed to close raw file %s: %w", e.TmpRawPath, err)
		}
		if err := os.Remove(e.TmpRawPath); err != nil {
			return fmt.Errorf("failed to remove temporary raw file %s: %w", e.TmpRawPath, err)
		}
	}
	if err := os.RemoveAll(e.TmpDir); err != nil {
		return fmt.Errorf("failed to remove temporary directory %s: %w", e.TmpDir, err)
	}
	return nil
}

// Fat32DirFS wraps scalibrfs.DirFS to include reference counting and cleanup
type Fat32DirFS struct {
	FS         scalibrfs.FS
	File       *os.File
	TmpDir     string
	TmpRawPath string
	RefCount   *int32
	RefMu      *sync.Mutex
}

func (f *Fat32DirFS) Open(name string) (fs.File, error) {
	return f.FS.Open(name)
}

func (f *Fat32DirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "/" || name == "" {
		name = "."
	}
	return f.FS.ReadDir(name)
}

func (f *Fat32DirFS) Stat(name string) (fs.FileInfo, error) {
	if name == "/" || name == "" || name == "." {
		// Return synthetic FileInfo for root directory
		return &fileInfo{
			name:    name,
			isDir:   true,
			modTime: time.Now(),
		}, nil
	}
	return f.FS.Stat(name)
}

func (f *Fat32DirFS) Close() error {
	f.RefMu.Lock()
	defer f.RefMu.Unlock()
	if f.File == nil {
		return nil // Already closed
	}
	*f.RefCount--
	if *f.RefCount == 0 {
		err := f.File.Close()
		f.File = nil // Prevent double close
		if err != nil {
			return fmt.Errorf("failed to close raw file %s: %w", f.TmpRawPath, err)
		}
		if err := os.Remove(f.TmpRawPath); err != nil {
			return fmt.Errorf("failed to remove temporary raw file %s: %w", f.TmpRawPath, err)
		}
	}
	if err := os.RemoveAll(f.TmpDir); err != nil {
		return fmt.Errorf("failed to remove temporary directory %s: %w", f.TmpDir, err)
	}
	return nil
}

// ExfatDirFS wraps scalibrfs.DirFS to include reference counting and cleanup
type ExfatDirFS struct {
	FS         scalibrfs.FS
	File       *os.File
	TmpDir     string
	TmpRawPath string
	RefCount   *int32
	RefMu      *sync.Mutex
}

func (e *ExfatDirFS) Open(name string) (fs.File, error) {
	return e.FS.Open(name)
}

func (e *ExfatDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "/" || name == "" {
		name = "."
	}
	return e.FS.ReadDir(name)
}

func (e *ExfatDirFS) Stat(name string) (fs.FileInfo, error) {
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

func (e *ExfatDirFS) Close() error {
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
			return fmt.Errorf("failed to close raw file %s: %w", e.TmpRawPath, err)
		}
		if err := os.Remove(e.TmpRawPath); err != nil {
			return fmt.Errorf("failed to remove temporary raw file %s: %w", e.TmpRawPath, err)
		}
	}
	if err := os.RemoveAll(e.TmpDir); err != nil {
		return fmt.Errorf("failed to remove temporary directory %s: %w", e.TmpDir, err)
	}
	return nil
}

// NtfsDirFS wraps scalibrfs.DirFS to include reference counting and cleanup
type NtfsDirFS struct {
	FS         scalibrfs.FS
	File       *os.File
	TmpDir     string
	TmpRawPath string
	RefCount   *int32
	RefMu      *sync.Mutex
}

func (n *NtfsDirFS) Open(name string) (fs.File, error) {
	return n.FS.Open(name)
}

func (n *NtfsDirFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "/" || name == "" {
		name = "."
	}
	return n.FS.ReadDir(name)
}

func (n *NtfsDirFS) Stat(name string) (fs.FileInfo, error) {
	if name == "/" || name == "" || name == "." {
		// Return synthetic FileInfo for root directory
		return &fileInfo{
			name:    name,
			isDir:   true,
			modTime: time.Now(),
		}, nil
	}
	return n.FS.Stat(name)
}

func (n *NtfsDirFS) Close() error {
	n.RefMu.Lock()
	defer n.RefMu.Unlock()
	if n.File == nil {
		return nil // Already closed
	}
	*n.RefCount--
	if *n.RefCount == 0 {
		err := n.File.Close()
		n.File = nil // Prevent double close
		if err != nil {
			return fmt.Errorf("failed to close raw file %s: %w", n.TmpRawPath, err)
		}
		if err := os.Remove(n.TmpRawPath); err != nil {
			return fmt.Errorf("failed to remove temporary raw file %s: %w", n.TmpRawPath, err)
		}
	}
	if err := os.RemoveAll(n.TmpDir); err != nil {
		return fmt.Errorf("failed to remove temporary directory %s: %w", n.TmpDir, err)
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
