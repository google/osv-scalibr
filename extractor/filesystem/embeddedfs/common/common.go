// Copyright 2026 Google LLC
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

	"archive/tar"

	"github.com/diskfs/go-diskfs"
	"github.com/diskfs/go-diskfs/disk"
	"github.com/diskfs/go-diskfs/filesystem/fat32"
	"github.com/diskfs/go-diskfs/partition/part"
	"github.com/dsoprea/go-exfat"
	"github.com/google/osv-scalibr/artifact/image/symlink"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/tempdir"
	"github.com/masahiro331/go-ext4-filesystem/ext4"
	"www.velocidex.com/golang/go-ntfs/parser"
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

// filterEntriesFat32 removes ".", "..", "lost+found", and "/"-containing entries from FAT32 entries.
func filterEntriesFat32(entries []os.FileInfo) []os.FileInfo {
	var filtered []os.FileInfo
	for _, e := range entries {
		name := e.Name()
		if name == "." || name == ".." || name == "lost+found" || strings.Contains(name, "/") {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

// filterEntriesExt removes ".", "..", "lost+found", and "/"-containing entries from ext4 entries.
func filterEntriesExt(entries []fs.DirEntry) []fs.DirEntry {
	var filtered []fs.DirEntry
	for _, e := range entries {
		name := e.Name()
		if name == "." || name == ".." || name == "lost+found" || strings.Contains(name, "/") {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

// filterEntriesNtfs removes ".", "..", "$"-prefixed, and "/"-containing entries from NTFS entries.
func filterEntriesNtfs(entries []*parser.FileInfo) []*parser.FileInfo {
	var filtered []*parser.FileInfo
	for _, e := range entries {
		name := e.Name
		if name == "" || name == "." || name == ".." || strings.HasPrefix(name, "$") || strings.Contains(name, "/") {
			continue
		}
		filtered = append(filtered, e)
	}
	return filtered
}

// ExtractAllRecursiveExt extracts all files from an ext4 filesystem to a temporary directory recursively.
func ExtractAllRecursiveExt(fs *ext4.FileSystem, srcPath string, destRoot *os.Root) error {
	srcPath = normalizePath(srcPath)
	entries, err := fs.ReadDir(srcPath)
	if err != nil {
		fmt.Printf("Warning: Failed to list directory %s: %v\n", srcPath, err)
		return nil // Continue processing other entries
	}

	entries = filterEntriesExt(entries)

	for _, entry := range entries {
		srcFullPath := path.Join(srcPath, entry.Name())
		destName := entry.Name()

		if entry.IsDir() {
			subRoot, err := destRoot.OpenRoot(destName)
			if err != nil {
				fmt.Printf("Warning: Failed to create subdir %s: %v\n", destName, err)
				continue
			}
			if err := ExtractAllRecursiveExt(fs, srcFullPath, subRoot); err != nil {
				subRoot.Close()
				fmt.Printf("Warning: Failed to extract directory %s: %v\n", srcFullPath, err)
				continue
			}
			subRoot.Close()
		} else {
			file, err := fs.Open(srcFullPath)
			if err != nil {
				fmt.Printf("Warning: Failed to open file %s: %v\n", srcFullPath, err)
				continue
			}
			defer file.Close()

			destFile, err := destRoot.Create(destName)
			if err != nil {
				fmt.Printf("Warning: Failed to create file %s: %v\n", destName, err)
				continue
			}
			defer destFile.Close()

			if _, err := io.Copy(destFile, file); err != nil {
				fmt.Printf("Warning: Failed to copy file %s: %v\n", srcFullPath, err)
				continue
			}
		}
	}
	return nil
}

// ExtractAllRecursiveFat32 extracts all files from a FAT32 filesystem to a temporary directory recursively.
func ExtractAllRecursiveFat32(fs *fat32.FileSystem, srcPath string, destRoot *os.Root) error {
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

	for _, entry := range entries {
		srcFullPath := path.Join(srcPath, entry.Name())
		destName := entry.Name()

		if entry.IsDir() {
			subRoot, err := destRoot.OpenRoot(destName)
			if err != nil {
				fmt.Printf("Warning: Failed to create subdir %s: %v\n", destName, err)
				continue
			}
			if err := ExtractAllRecursiveFat32(fs, srcFullPath, subRoot); err != nil {
				subRoot.Close()
				fmt.Printf("Warning: Failed to extract directory %s: %v\n", srcFullPath, err)
				continue
			}
			subRoot.Close()
		} else {
			file, err := fs.OpenFile(srcFullPath, os.O_RDONLY)
			if err != nil {
				fmt.Printf("Warning: Failed to open file %s: %v\n", srcFullPath, err)
				continue
			}
			defer file.Close()

			destFile, err := destRoot.Create(destName)
			if err != nil {
				fmt.Printf("Warning: Failed to create file %s: %v\n", destName, err)
				continue
			}
			defer destFile.Close()

			if _, err := io.Copy(destFile, file); err != nil {
				fmt.Printf("Warning: Failed to copy file %s: %v\n", srcFullPath, err)
				continue
			}
		}
	}
	return nil
}

// ExtractAllRecursiveNtfs extracts all files from a NTFS filesystem to a temporary directory recursively.
func ExtractAllRecursiveNtfs(fs *parser.NTFSContext, srcPath string, destRoot *os.Root) error {
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

	for _, entryInfo := range entries {
		srcFullPath := path.Join(srcPath, entryInfo.Name)
		destName := entryInfo.Name

		if entryInfo.IsDir {
			subRoot, err := destRoot.OpenRoot(destName)
			if err != nil {
				fmt.Printf("Warning: Failed to create subdir %s: %v\n", destName, err)
				continue
			}
			if err := ExtractAllRecursiveNtfs(fs, srcFullPath, subRoot); err != nil {
				subRoot.Close()
				fmt.Printf("Warning: Failed to extract directory %s: %v\n", srcFullPath, err)
				continue
			}
			subRoot.Close()
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

			destFile, err := destRoot.Create(destName)
			if err != nil {
				fmt.Printf("Warning: Failed to create file %s: %v\n", destName, err)
				continue
			}
			defer destFile.Close()

			if _, err := io.Copy(destFile, fileReader); err != nil {
				fmt.Printf("Warning: Failed to copy file %s: %v\n", srcFullPath, err)
				continue
			}
		}
	}
	return nil
}

// ExtractAllRecursiveExFAT extracts all files from an exFAT filesystem to a temporary directory recursively.
func ExtractAllRecursiveExFAT(section *io.SectionReader, destRoot *os.Root) error {
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

		sde := node.StreamDirectoryEntry()
		if node.IsDirectory() {
			if err := destRoot.MkdirAll(resPath, 0o755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", resPath, err)
			}
			continue
		}

		if err := destRoot.MkdirAll(filepath.Dir(resPath), 0o755); err != nil {
			return fmt.Errorf("failed to create parent directories for %s: %w", resPath, err)
		}

		outFile, err := destRoot.Create(resPath)
		if err != nil {
			return fmt.Errorf("failed to create file %s: %w", resPath, err)
		}

		useFat := !sde.GeneralSecondaryFlags.NoFatChain()
		if _, _, err := er.WriteFromClusterChain(sde.FirstCluster, sde.ValidDataLength, useFat, outFile); err != nil {
			// Ignore this error because we're going to manually truncate the file at the end
			if !strings.Contains(err.Error(), "written bytes do not equal data-size") {
				outFile.Close()
				return fmt.Errorf("failed to write cluster chain %s: %w", resPath, err)
			}
		}

		err = outFile.Truncate(int64(sde.ValidDataLength))
		if err != nil {
			continue
		}

		if err := outFile.Close(); err != nil {
			return fmt.Errorf("failed to close file %s: %w", resPath, err)
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

// GetDiskPartitions opens a raw disk image and returns its partitions along with the disk handle.
func GetDiskPartitions(rawDiskIMGPath string) ([]part.Partition, *disk.Disk, error) {
	// Open the raw disk image with go-diskfs
	disk, err := diskfs.Open(rawDiskIMGPath, diskfs.WithOpenMode(diskfs.ReadOnly))
	if err != nil {
		disk.Close()
		os.Remove(rawDiskIMGPath)
		return nil, nil, fmt.Errorf("failed to open raw disk image %s: %w", rawDiskIMGPath, err)
	}

	partitions, err := disk.GetPartitionTable()
	if err != nil {
		disk.Close()
		return nil, nil, fmt.Errorf("failed to get partition table: %w", err)
	}
	partitionList := partitions.GetPartitions()
	if len(partitionList) == 0 {
		disk.Close()
		return nil, nil, errors.New("no partitions found in raw disk image")
	}
	return partitionList, disk, nil
}

// NewPartitionEmbeddedFSGetter creates a lazy getter function for an embedded filesystem from a disk partition.
func NewPartitionEmbeddedFSGetter(pluginName string, partitionIndex int, p part.Partition, disk *disk.Disk, pluginDir string, pluginRoot *os.Root, rawDiskIMGPath string, refMu *sync.Mutex, refCount *int32) func(context.Context) (scalibrfs.FS, error) {
	return func(ctx context.Context) (scalibrfs.FS, error) {
		// Get partition offset and size (already multiplied by sector size)
		offset := p.GetStart()
		size := p.GetSize()

		// Open raw image for filesystem parsers
		f, err := os.Open(rawDiskIMGPath)
		if err != nil {
			return nil, fmt.Errorf("failed to open raw image %s: %w", rawDiskIMGPath, err)
		}

		section := io.NewSectionReader(f, offset, size)
		fsType := DetectFilesystem(section, 0)

		// Creates a temporary directory for extracted files
		// Disk layout will be similar to the following in the OS set temporary directory:
		// ├── osv-scalibr-run-953505549
		// │				└── extractor
		// │				    └── vdi
		// |						└── valid.vdi 								<--- File discovered by the extractor (pluginRoot parameter points here)
		// │				        	├── partition-1-ext4					<--- A folder containing partition data
		// │				        	│				└── private-key1.pem
		// │				        	├── partition-2-exfat
		// │				        	│				└── private-key2.pem
		// │				        	├── partition-3-fat32
		// │				        	│				└── private-key3.pem
		// │				        	├── partition-4-ntfs
		// │				        	│				└── private-key4.pem
		// │				        	└── vdi-12345.raw 						<--- Converted disk image
		partitionSubDir := fmt.Sprintf("partition-%d-%s", partitionIndex, strings.ToLower(fsType))
		// Ensure dir exists
		if err := pluginRoot.MkdirAll(partitionSubDir, 0o755); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("failed to create partition directory %s: %w", partitionSubDir, err)
		}
		partitionRoot, err := pluginRoot.OpenRoot(partitionSubDir)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("failed to open partition directory %s: %w", partitionSubDir, err)
		}

		rootPath, err := tempdir.GetRootPath()
		if err != nil {
			return nil, fmt.Errorf("failed to get scalibr per run directory: %w", err)
		}
		params := generateFSParams{
			File:           f,
			Disk:           disk,
			Section:        section,
			PartitionIndex: partitionIndex,
			TempDir:        filepath.Join(rootPath, pluginDir, partitionSubDir),
			PartitionRoot:  partitionRoot,
			RawDiskIMGPath: rawDiskIMGPath,
			RefMu:          refMu,
			RefCount:       refCount,
		}

		var fsys scalibrfs.FS
		switch fsType {
		case "ext4":
			fsys, err = generateEXTFS(params)
		case "FAT32":
			fsys, err = generateFAT32FS(params)
		case "exFAT":
			fsys, err = generateEXFATFS(params)
		case "NTFS":
			fsys, err = generateNTFSFS(params)
		default:
			fsys, err = nil, fmt.Errorf("unsupported filesystem type %s for partition %d", fsType, partitionIndex)
		}
		if err != nil {
			partitionRoot.Close()
			if fsType != "FAT32" {
				f.Close()
			}
			if errRemove := pluginRoot.RemoveAll(partitionSubDir); errRemove != nil {
				return nil, fmt.Errorf("%w; %w", err, errRemove)
			}
			return nil, err
		}
		return fsys, nil
	}
}

// generateFSParams holds parameters for generating embedded filesystems.
type generateFSParams struct {
	File           *os.File
	Disk           *disk.Disk
	Section        *io.SectionReader
	PartitionIndex int
	PartitionRoot  *os.Root
	TempDir        string
	RawDiskIMGPath string
	RefMu          *sync.Mutex
	RefCount       *int32
}

// generateEXTFS generates an ext4 filesystem and extracts files to a temporary directory.
func generateEXTFS(params generateFSParams) (*EmbeddedDirFS, error) {
	fs, err := ext4.NewFS(*params.Section, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create ext4 filesystem for partition %d: %w", params.PartitionIndex, err)
	}
	if err := ExtractAllRecursiveExt(fs, "/", params.PartitionRoot); err != nil {
		return nil, fmt.Errorf("failed to extract ext4 files for partition %d: %w", params.PartitionIndex, err)
	}
	params.RefMu.Lock()
	*params.RefCount++
	params.RefMu.Unlock()
	return &EmbeddedDirFS{
		FS:       &RootFSWrapper{Root: params.PartitionRoot, FS: params.PartitionRoot.FS()},
		Root:     params.PartitionRoot,
		File:     params.File,
		TmpPaths: []string{params.TempDir, params.RawDiskIMGPath},
		RefCount: params.RefCount,
		RefMu:    params.RefMu,
	}, nil
}

// generateFAT32FS generates a FAT32 filesystem and extracts files to a temporary directory.
// Note that unlike in the other generator functions, the file is expected to be closed
// as disk.GetFilesystem() will reopen it.
func generateFAT32FS(params generateFSParams) (*EmbeddedDirFS, error) {
	fs, err := params.Disk.GetFilesystem(params.PartitionIndex)
	if err != nil {
		return nil, fmt.Errorf("failed to get filesystem for partition %d: %w", params.PartitionIndex, err)
	}
	fat32fs, ok := fs.(*fat32.FileSystem)
	if !ok {
		return nil, fmt.Errorf("partition %d is not a FAT32 filesystem", params.PartitionIndex)
	}
	f, err := os.Open(params.RawDiskIMGPath)
	if err != nil {
		return nil, fmt.Errorf("failed to reopen raw image %s: %w", params.RawDiskIMGPath, err)
	}
	if err := ExtractAllRecursiveFat32(fat32fs, "/", params.PartitionRoot); err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to extract FAT32 files for partition %d: %w", params.PartitionIndex, err)
	}
	params.RefMu.Lock()
	*params.RefCount++
	params.RefMu.Unlock()
	return &EmbeddedDirFS{
		FS:       &RootFSWrapper{Root: params.PartitionRoot, FS: params.PartitionRoot.FS()},
		Root:     params.PartitionRoot,
		File:     f,
		TmpPaths: []string{params.TempDir, params.RawDiskIMGPath},
		RefCount: params.RefCount,
		RefMu:    params.RefMu,
	}, nil
}

// generateEXFATFS generates an exFAT filesystem and extracts files to a temporary directory.
func generateEXFATFS(params generateFSParams) (*EmbeddedDirFS, error) {
	if err := ExtractAllRecursiveExFAT(params.Section, params.PartitionRoot); err != nil {
		return nil, fmt.Errorf("failed to extract exFAT files for partition %d: %w", params.PartitionIndex, err)
	}
	params.RefMu.Lock()
	*params.RefCount++
	params.RefMu.Unlock()
	return &EmbeddedDirFS{
		FS:       &RootFSWrapper{Root: params.PartitionRoot, FS: params.PartitionRoot.FS()},
		Root:     params.PartitionRoot,
		File:     params.File,
		TmpPaths: []string{params.TempDir, params.RawDiskIMGPath},
		RefCount: params.RefCount,
		RefMu:    params.RefMu,
	}, nil
}

// generateNTFSFS generates an NTFS filesystem and extracts files to a temporary directory.
func generateNTFSFS(params generateFSParams) (*EmbeddedDirFS, error) {
	reader, err := parser.NewPagedReader(params.Section, defaultPageSize, defaultCacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create paged reader for NTFS partition %d: %w", params.PartitionIndex, err)
	}
	fs, err := parser.GetNTFSContext(reader, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create NTFS filesystem for partition %d: %w", params.PartitionIndex, err)
	}
	if err := ExtractAllRecursiveNtfs(fs, "/", params.PartitionRoot); err != nil {
		return nil, fmt.Errorf("failed to extract NTFS files for partition %d: %w", params.PartitionIndex, err)
	}
	params.RefMu.Lock()
	*params.RefCount++
	params.RefMu.Unlock()
	return &EmbeddedDirFS{
		FS:       &RootFSWrapper{Root: params.PartitionRoot, FS: params.PartitionRoot.FS()},
		Root:     params.PartitionRoot,
		File:     params.File,
		TmpPaths: []string{params.TempDir, params.RawDiskIMGPath},
		RefCount: params.RefCount,
		RefMu:    params.RefMu,
	}, nil
}

// EmbeddedDirFS wraps scalibrfs.DirFS to include reference counting and cleanup.
type EmbeddedDirFS struct {
	FS       scalibrfs.FS
	Root     *os.Root
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

	// Close the partition root if it's not nil
	if e.Root != nil {
		e.Root.Close()
		e.Root = nil
	}

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

// RootFSWrapper wraps os.Root.FS() to satisfy scalibrfs.FS interface.
type RootFSWrapper struct {
	Root *os.Root
	FS   fs.FS
}

// Open opens a file from the underlying filesystem.
func (w *RootFSWrapper) Open(name string) (fs.File, error) {
	return w.FS.Open(name)
}

// ReadDir lists directory entries for the given path.
// It normalizes root paths ("/", "") to "." for compatibility.
func (w *RootFSWrapper) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "/" || name == "" {
		name = "."
	}
	return fs.ReadDir(w.FS, name)
}

// Stat returns file information for the given path.
// For root paths ("/", "", "."), it returns a synthetic directory.
func (w *RootFSWrapper) Stat(name string) (fs.FileInfo, error) {
	if name == "/" || name == "" || name == "." {
		return &fileInfo{name: name, isDir: true, modTime: time.Now()}, nil
	}
	return fs.Stat(w.FS, name)
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

// TARToTempDir extracts a tar file into a temporary directory
// that can be used to traverse its contents recursively.
func TARToTempDir(pluginDir string, pluginRoot *os.Root, reader io.Reader) error {
	// Extract the tar archive
	var extractErr error
	tr := tar.NewReader(reader)
loop:
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			extractErr = fmt.Errorf("failed to read tar header: %w", err)
			break
		}

		if symlink.TargetOutsideRoot("/", hdr.Name) {
			extractErr = errors.New("tar contains invalid entries")
			break
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := pluginRoot.MkdirAll(hdr.Name, 0755); err != nil {
				extractErr = fmt.Errorf("failed to create directory %s: %w", hdr.Name, err)
				break loop
			}
		case tar.TypeReg:
			if err := pluginRoot.MkdirAll(filepath.Dir(hdr.Name), 0755); err != nil {
				extractErr = fmt.Errorf("failed to create directory %s: %w", hdr.Name, err)
				break loop
			}
			outFile, err := pluginRoot.Create(hdr.Name)
			if err != nil {
				extractErr = fmt.Errorf("failed to create file %s: %w", hdr.Name, err)
				break loop
			}
			if _, err := io.Copy(outFile, tr); err != nil {
				outFile.Close()
				extractErr = fmt.Errorf("failed to copy file %s: %w", hdr.Name, err)
				break loop
			}
			outFile.Close()
		default:
			// Skip other types (symlinks, etc.) for now
		}
	}

	if extractErr != nil {
		if err := tempdir.RemoveAll(pluginDir); err != nil {
			return fmt.Errorf("%w; %w", extractErr, err)
		}
		return extractErr
	}

	return nil
}
